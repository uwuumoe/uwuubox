//! Single generic OIDC provider: PKCE + nonce login, first-login link or
//! provision, and linking to an existing local account from the dashboard.

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{self, SESSION_USER_ID},
    config::Env,
    db,
    error::AppError,
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
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "OIDC discovery URL invalid; OIDC disabled");
            return None;
        }
    };
    let provider = match CoreProviderMetadata::discover_async(issuer, http).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "OIDC discovery failed; OIDC disabled");
            return None;
        }
    };
    let redirect_url = match openidconnect::RedirectUrl::new(redirect) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "OIDC redirect URL invalid; OIDC disabled");
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

pub async fn login(State(state): State<AppState>, session: Session) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    if !cfg.allow_oidc {
        return Err(AppError::NotFound);
    }
    let oidc = oidc(&state)?;
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
        .set_pkce_challenge(challenge)
        .url();
    session
        .insert("oidc_verifier", verifier.secret().to_string())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    session
        .insert("oidc_nonce", nonce.secret().to_string())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    session
        .insert("oidc_csrf", csrf.secret().to_string())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
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
        .map_err(|e| AppError::internal(e.to_string()))?;
    login(State(state), session).await
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    if !cfg.allow_oidc {
        return Err(AppError::NotFound);
    }
    let oidc = oidc(&state)?;

    let csrf: Option<String> = session
        .get("oidc_csrf")
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let verifier: Option<String> = session
        .get("oidc_verifier")
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let nonce_str: Option<String> = session
        .get("oidc_nonce")
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (Some(csrf), Some(verifier), Some(nonce_str)) = (csrf, verifier, nonce_str) else {
        return Err(AppError::bad_request("login session expired; try again"));
    };
    if !auth::tokens_equal(&csrf, &q.state) {
        return Err(AppError::bad_request("state mismatch; try again"));
    }

    let token = oidc
        .client
        .exchange_code(AuthorizationCode::new(q.code))
        .map_err(|e| AppError::internal(format!("provider token endpoint unusable: {e}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&oidc.http)
        .await
        .map_err(|e| AppError::internal(format!("code exchange failed: {e}")))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| AppError::internal("provider returned no id_token"))?;
    let nonce = Nonce::new(nonce_str);
    let claims = id_token
        .claims(&oidc.client.id_token_verifier(), &nonce)
        .map_err(|e| AppError::bad_request(format!("id_token invalid: {e}")))?;
    let sub = claims.subject().as_str().to_string();
    let issuer = claims.issuer().url().as_str().to_string();

    // Link mode: attach (issuer, sub) to the dashboard account that started it.
    let link_uid: Option<String> = session
        .get("oidc_link_uid")
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    if let Some(link_uid) = link_uid {
        let uid: Uuid = link_uid
            .parse()
            .map_err(|_| AppError::bad_request("bad link session"))?;
        let user = db::find_user_by_id(&state.pool, &uid)
            .await?
            .ok_or(AppError::NotFound)?;
        db::link_oidc(&state.pool, &issuer, &sub, &user.id).await?;
        let _ = session.remove::<String>("oidc_link_uid").await;
        session
            .insert(SESSION_USER_ID, user.id.to_string())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        tracing::info!(user = %user.username, "OIDC identity linked");
        return Ok(Redirect::to("/account").into_response());
    }

    if let Some(user) = db::find_oidc_user(&state.pool, &issuer, &sub).await? {
        session
            .insert(SESSION_USER_ID, user.id.to_string())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        session
            .cycle_id()
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        return Ok(Redirect::to("/account").into_response());
    }

    // First login: provision iff registration is open, else 403 page.
    if !cfg.allow_registration {
        return Err(AppError::forbidden(
            "registration is closed; ask an admin to link your account",
        ));
    }
    let preferred = claims
        .preferred_username()
        .map(|s| s.as_str())
        .unwrap_or("user");
    let base = auth::oidc_base_username(preferred);
    let mut username = base.clone();
    for n in 1..1000 {
        if !db::username_taken(&state.pool, &username).await? {
            break;
        }
        username = format!("{base}{n}");
    }
    let id = auth::new_user_id();
    let is_admin = db::user_count(&state.pool).await? == 0;
    let user = db::insert_user(&state.pool, &id, &username, None, is_admin).await?;
    db::link_oidc(&state.pool, &issuer, &sub, &user.id).await?;
    session
        .insert(SESSION_USER_ID, user.id.to_string())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    session
        .cycle_id()
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    tracing::info!(username = %username, issuer = %issuer, "OIDC account provisioned");
    Ok(Redirect::to("/account").into_response())
}
