//! Single generic OIDC provider: PKCE + nonce login, first-login provision,
//! linking to an existing account, invite gating, and sticky group roles.

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{self, SESSION_USER_ID},
    config::Env,
    db::{self, User},
    error::AppError,
    routes::{invites, roles},
    state::AppState,
};

/// Client shape returned by `CoreClient::from_provider_metadata`:
/// auth URL set, token/userinfo maybe-set (absent endpoints error at call time).
pub type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
pub struct OidcState {
    pub client: DiscoveredClient,
    pub http: reqwest::Client,
}

/// Boot-time discovery; failure disables OIDC with a warning rather than
/// refusing to start (the IdP may be briefly unreachable at boot).
pub async fn build(env: &Env, http: &reqwest::Client) -> Option<OidcState> {
    if !env.oidc_enabled {
        return None;
    }
    let (Some(discovery), Some(id), Some(secret), Some(redirect)) = (
        env.oidc_discovery_url.clone(),
        env.oidc_client_id.clone(),
        env.oidc_client_secret.clone(),
        env.oidc_redirect_url.clone(),
    ) else {
        tracing::error!("OIDC enabled but OIDC_* env incomplete; OIDC disabled");
        return None;
    };
    let issuer = match openidconnect::IssuerUrl::new(discovery.clone()) {
        Ok(url) => url,
        Err(error) => {
            tracing::error!(error = %error, "OIDC discovery URL invalid; OIDC disabled");
            return None;
        }
    };
    let provider = match CoreProviderMetadata::discover_async(issuer, http).await {
        Ok(provider) => provider,
        Err(error) => {
            tracing::error!(error = %error, "OIDC discovery failed; OIDC disabled");
            return None;
        }
    };
    let redirect_url = match openidconnect::RedirectUrl::new(redirect) {
        Ok(url) => url,
        Err(error) => {
            tracing::error!(error = %error, "OIDC redirect URL invalid; OIDC disabled");
            return None;
        }
    };
    let client = CoreClient::from_provider_metadata(
        provider,
        openidconnect::ClientId::new(id),
        Some(openidconnect::ClientSecret::new(secret)),
    )
    .set_redirect_uri(redirect_url);
    tracing::info!(discovery = %discovery, "OIDC provider configured");
    Some(OidcState {
        client,
        http: http.clone(),
    })
}

fn oidc(state: &AppState) -> Result<OidcState, AppError> {
    state.oidc.clone().ok_or(AppError::NotFound)
}

#[derive(Debug, Default, Deserialize)]
pub struct LoginQuery {
    invite: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    session
        .remove::<String>("oidc_link_uid")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    start_login(&state, &session, query.invite).await
}

async fn start_login(
    state: &AppState,
    session: &Session,
    invite: Option<String>,
) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    if !cfg.allow_oidc {
        return Err(AppError::NotFound);
    }
    let oidc = oidc(state)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = oidc
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("groups".into()))
        .set_pkce_challenge(challenge)
        .url();
    session
        .insert("oidc_verifier", verifier.secret().to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    session
        .insert("oidc_nonce", nonce.secret().to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    session
        .insert("oidc_csrf", csrf.secret().to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    match invite.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) {
        Some(invite) => session
            .insert("oidc_invite", invite)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?,
        None => {
            session
                .remove::<String>("oidc_invite")
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
        }
    }
    Ok(Redirect::to(url.as_str()).into_response())
}

/// Dashboard "link OIDC" posts here: remembers the account, then OIDC login.
pub async fn link_start(
    State(state): State<AppState>,
    session: Session,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let Some(user) =
        crate::identity::current_user(&state.pool, &state.env.session_secret, &session, &headers)
            .await
    else {
        return Err(AppError::Unauthorized);
    };
    session
        .insert("oidc_link_uid", user.id.to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    start_login(&state, &session, None).await
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

fn groups_from_id_token(raw: &str) -> Vec<String> {
    let Some(payload) = raw.split('.').nth(1) else {
        return Vec::new();
    };
    let Ok(payload) = URL_SAFE_NO_PAD.decode(payload) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return Vec::new();
    };
    let Some(groups) = value.get("groups").and_then(|groups| groups.as_array()) else {
        return Vec::new();
    };
    groups
        .iter()
        .filter_map(|group| group.as_str().map(str::to_string))
        .collect()
}

async fn apply_group_role(
    state: &AppState,
    user: &User,
    issuer: &str,
    groups: &[String],
) -> Result<(), AppError> {
    if user.role_id.is_some() || groups.is_empty() {
        return Ok(());
    }
    if let Some(role_id) =
        roles::assign_from_oidc_groups(&state.pool, &user.id, issuer, groups).await?
    {
        db::audit(
            &state.pool,
            None,
            "user.role",
            Some("user"),
            Some(&user.id.to_string()),
            Some(json!({"role_id": role_id, "source": "oidc", "issuer": issuer})),
        )
        .await?;
    }
    Ok(())
}

pub async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    if !cfg.allow_oidc {
        return Err(AppError::NotFound);
    }
    let oidc = oidc(&state)?;

    let csrf: Option<String> = session
        .get("oidc_csrf")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let verifier: Option<String> = session
        .get("oidc_verifier")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let nonce: Option<String> = session
        .get("oidc_nonce")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let (Some(csrf), Some(verifier), Some(nonce)) = (csrf, verifier, nonce) else {
        return Err(AppError::bad_request("login session expired; try again"));
    };
    if !auth::tokens_equal(&csrf, &query.state) {
        return Err(AppError::bad_request("state mismatch; try again"));
    }

    let token = oidc
        .client
        .exchange_code(AuthorizationCode::new(query.code))
        .map_err(|error| AppError::internal(format!("provider token endpoint unusable: {error}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&oidc.http)
        .await
        .map_err(|error| AppError::internal(format!("code exchange failed: {error}")))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| AppError::internal("provider returned no id_token"))?;
    let claims = id_token
        .claims(&oidc.client.id_token_verifier(), &Nonce::new(nonce))
        .map_err(|error| AppError::bad_request(format!("id_token invalid: {error}")))?;
    let sub = claims.subject().as_str().to_string();
    // This exact normalized claim string is both stored in oidc_identities and
    // matched against role_oidc_groups.issuer.
    let issuer = claims.issuer().url().as_str().to_string();
    let groups = groups_from_id_token(&id_token.to_string());

    // Link mode is allowed even while registration is closed: it never creates
    // an account. Group assignment only fills a role that is still NULL.
    let link_uid: Option<String> = session
        .get("oidc_link_uid")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(link_uid) = link_uid {
        let uid: Uuid = link_uid
            .parse()
            .map_err(|_| AppError::bad_request("bad link session"))?;
        let user = db::find_user_by_id(&state.pool, &uid)
            .await?
            .ok_or(AppError::NotFound)?;
        db::link_oidc(&state.pool, &issuer, &sub, &user.id).await?;
        apply_group_role(&state, &user, &issuer, &groups).await?;
        session
            .remove::<String>("oidc_link_uid")
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        session
            .insert(SESSION_USER_ID, user.id.to_string())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        session
            .cycle_id()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        tracing::info!(user = %user.username, "OIDC identity linked");
        return Ok(Redirect::to("/account").into_response());
    }

    if let Some(user) = db::find_oidc_user(&state.pool, &issuer, &sub).await? {
        apply_group_role(&state, &user, &issuer, &groups).await?;
        session
            .insert(SESSION_USER_ID, user.id.to_string())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        session
            .cycle_id()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        return Ok(Redirect::to("/account").into_response());
    }

    if cfg.registration_mode == "closed" {
        return Err(AppError::forbidden(
            "registration is closed; ask an admin to link your account",
        ));
    }
    let invite: Option<String> = session
        .get("oidc_invite")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if cfg.registration_mode == "invite" && invite.as_deref().is_none_or(|value| value.is_empty()) {
        return Err(AppError::forbidden(
            "a valid invite code is required to create an account",
        ));
    }

    let preferred = claims
        .preferred_username()
        .map(|value| value.as_str())
        .unwrap_or("user");
    let base = auth::oidc_base_username(preferred);
    let mut username = base.clone();
    for suffix in 1..1000 {
        if !db::username_taken(&state.pool, &username).await? {
            break;
        }
        username = format!("{base}{suffix}");
    }
    let id = auth::new_user_id();
    let is_admin = db::user_count(&state.pool).await? == 0;
    let user = if cfg.registration_mode == "invite" {
        match invites::create_user(
            &state.pool,
            &id,
            &username,
            None,
            None,
            is_admin,
            invite.as_deref().unwrap_or_default(),
        )
        .await
        {
            Ok(user) => user,
            Err(invites::InviteRegistrationError::Invalid) => {
                return Err(AppError::forbidden(
                    "invite code is invalid, expired, or fully used",
                ));
            }
            Err(invites::InviteRegistrationError::Database(error)) => {
                return Err(AppError::from(error));
            }
        }
    } else {
        db::insert_user(&state.pool, &id, &username, None, is_admin).await?
    };
    db::link_oidc(&state.pool, &issuer, &sub, &user.id).await?;
    apply_group_role(&state, &user, &issuer, &groups).await?;
    session
        .remove::<String>("oidc_invite")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    session
        .insert(SESSION_USER_ID, user.id.to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    session
        .cycle_id()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    tracing::info!(username = %username, issuer = %issuer, "OIDC account provisioned");
    Ok(Redirect::to("/account").into_response())
}

