//! Accounts: local register/login/logout, dashboard, profiles, avatars,
//! API tokens, OIDC link initiation.

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    Form,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use uuid::Uuid;
use validator::ValidateEmail;

use crate::{
    auth::{self, SESSION_USER_ID},
    db::{self, User},
    error::AppError,
    identity::current_user,
    mime,
    routes::{
        common::{avatar_url, wants_html},
        files::{remove_file, set_file_visibility},
        invites::{self, InviteRegistrationError},
        passkeys,
    },
    state::AppState,
    storage::avatar_key,
    views::{self, DashboardPage},
};

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}

fn login_error_page(
    cfg: &crate::config::InstanceConfig,
    mode: &str,
    msg: impl Into<String>,
) -> Result<Response, AppError> {
    use askama::Template;
    let error = Some(msg.into());
    let body = if mode == "register" {
        views::register_page(cfg, error)
            .render()
            .map_err(|e| AppError::internal(e.to_string()))?
    } else {
        views::login_page(cfg, error)
            .render()
            .map_err(|e| AppError::internal(e.to_string()))?
    };
    Ok((StatusCode::BAD_REQUEST, Html(body)).into_response())
}

// ---- local auth ----

pub async fn register_form(State(state): State<AppState>) -> Result<Response, AppError> {
    use askama::Template;
    let cfg = db::instance_config(&state.pool).await?;
    if cfg.registration_mode == "closed" {
        return Err(AppError::forbidden("registration is closed"));
    }
    let mut page = views::register_page(&cfg, None);
    page.oidc_enabled = cfg.allow_oidc && state.oidc.is_some();
    let body = page
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Html(body).into_response())
}

#[derive(Deserialize)]
pub struct RegisterForm {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub invite: Option<String>,
}

pub async fn register_post(
    State(state): State<AppState>,
    session: Session,
    Form(f): Form<RegisterForm>,
) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    if cfg.registration_mode == "closed" {
        return Err(AppError::forbidden("registration is closed"));
    }
    let username = f.username.trim().to_string();
    let email = f
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(str::to_lowercase);
    if email.as_ref().is_some_and(|email| !email.validate_email()) {
        return login_error_page(&cfg, "register", "enter a valid email address");
    }
    if let Err(e) = auth::validate_username(&username) {
        return login_error_page(&cfg, "register", e);
    }
    let hash = match auth::hash_password(&f.password) {
        Ok(h) => h,
        Err(e) => return login_error_page(&cfg, "register", e),
    };
    let id = auth::new_user_id();
    let is_admin = db::user_count(&state.pool).await? == 0;
    let user_result = match cfg.registration_mode.as_str() {
        "open" => sqlx::query_as::<_, User>(
            "INSERT INTO users (id, username, password_hash, email, is_admin)
             VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(id)
        .bind(&username)
        .bind(&hash)
        .bind(email.as_deref())
        .bind(is_admin)
        .fetch_one(&state.pool)
        .await
        .map_err(InviteRegistrationError::Database),
        "invite" => {
            let invite = f.invite.as_deref().map(str::trim).unwrap_or_default();
            if invite.is_empty() {
                return login_error_page(&cfg, "register", "invite code is required");
            }
            invites::create_user(
                &state.pool,
                &id,
                &username,
                Some(&hash),
                email.as_deref(),
                is_admin,
                invite,
            )
            .await
        }
        _ => return Err(AppError::forbidden("registration is closed")),
    };
    match user_result {
        Ok(user) => {
            session
                .insert(SESSION_USER_ID, user.id.to_string())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            session
                .cycle_id()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            tracing::info!(username = %username, admin = is_admin, "user registered");
            Ok(Redirect::to("/account").into_response())
        }
        Err(InviteRegistrationError::Invalid) => login_error_page(
            &cfg,
            "register",
            "invite code is invalid, expired, or fully used",
        ),
        Err(InviteRegistrationError::Database(e)) if is_unique_violation(&e) => {
            login_error_page(&cfg, "register", "username or email is already in use")
        }
        Err(InviteRegistrationError::Database(e)) => Err(AppError::from(e)),
    }
}

pub async fn login_form(State(state): State<AppState>) -> Result<Response, AppError> {
    use askama::Template;
    let cfg = db::instance_config(&state.pool).await?;
    if !cfg.allow_local_login {
        return Err(AppError::forbidden("local login is disabled"));
    }
    let mut page = views::login_page(&cfg, None);
    page.oidc_enabled = cfg.allow_oidc && state.oidc.is_some();
    let body = page
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Html(body).into_response())
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

pub async fn login_post(
    State(state): State<AppState>,
    session: Session,
    Form(f): Form<LoginForm>,
) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    if !cfg.allow_local_login {
        return Err(AppError::forbidden("local login is disabled"));
    }
    let fail = || login_error_page(&cfg, "login", "invalid username or password");
    let Some(user) = db::find_user_by_name(&state.pool, f.username.trim()).await? else {
        return fail();
    };
    let hash = user.password_hash.clone().unwrap_or_default();
    if hash.is_empty() || !auth::verify_password(&hash, &f.password) {
        return fail();
    }
    session
        .insert(SESSION_USER_ID, user.id.to_string())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    session
        .cycle_id()
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Redirect::to("/account").into_response())
}

pub async fn logout(session: Session) -> Result<Response, AppError> {
    session
        .delete()
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Redirect::to("/").into_response())
}

// ---- dashboard ----

async fn dashboard_response(
    state: &AppState,
    user: &User,
    just_created_token: Option<String>,
    profile_error: Option<String>,
) -> Result<Response, AppError> {
    use askama::Template;
    let (files, pastes) = db::own_items(&state.pool, &user.id).await?;
    let tokens = db::list_tokens(&state.pool, &user.id).await?;
    let passkeys = passkeys::list_for_user(&state.pool, &user.id).await?;
    let cfg = db::instance_config(&state.pool).await?;
    let linked = db::oidc_linked(&state.pool, &user.id).await?;
    let storage_used = db::storage_used(&state.pool, &user.id).await?;
    let quota_bytes = db::effective_limits(&state.pool, &cfg, Some(user))
        .await?
        .quota_bytes;
    let storage_used_human = views::human_bytes(storage_used);
    let page = DashboardPage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user: Some(user.clone()),
        files,
        pastes,
        tokens,
        passkeys,
        just_created_token,
        profile_error,
        now: Utc::now(),
        oidc_enabled: cfg.allow_oidc && state.oidc.is_some(),
        oidc_linked: linked,
        webauthn_enabled: state.webauthn.is_some(),
        avatar_url: avatar_url(user.avatar_key.as_deref()),
        base_url: state.env.base_url.clone(),
        storage_used,
        storage_used_human,
        quota_bytes,
    };
    let body = page
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    let status = if page.profile_error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    Ok((status, Html(body)).into_response())
}

pub async fn dashboard(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Ok(Redirect::to("/login").into_response());
    };
    dashboard_response(&state, &user, None, None).await
}

#[derive(Deserialize)]
pub struct ProfileForm {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub email: Option<String>,
}

pub async fn update_profile(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(f): Form<ProfileForm>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let name = f
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let bio = f
        .bio
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let email = f
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(str::to_lowercase);
    if email.as_ref().is_some_and(|email| !email.validate_email()) {
        return dashboard_response(
            &state,
            &user,
            None,
            Some("enter a valid email address".into()),
        )
        .await;
    }
    if name.as_ref().is_some_and(|s| s.len() > 64) {
        return Err(AppError::bad_request("display_name must be <= 64 chars"));
    }
    if bio.as_ref().is_some_and(|s| s.len() > 500) {
        return Err(AppError::bad_request("bio must be <= 500 chars"));
    }
    let updated =
        sqlx::query("UPDATE users SET display_name = $1, bio = $2, email = $3 WHERE id = $4")
            .bind(name.as_deref())
            .bind(bio.as_deref())
            .bind(email.as_deref())
            .bind(user.id)
            .execute(&state.pool)
            .await;
    match updated {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            return dashboard_response(&state, &user, None, Some("email is already in use".into()))
                .await;
        }
        Err(error) => return Err(AppError::from(error)),
    }
    Ok(Redirect::to("/account").into_response())
}

fn avatar_ext(mime: &str) -> Option<&'static str> {
    match mime {
        "image/png" => Some(".png"),
        "image/jpeg" => Some(".jpg"),
        "image/gif" => Some(".gif"),
        "image/webp" => Some(".webp"),
        "image/avif" => Some(".avif"),
        _ => None,
    }
}

pub async fn upload_avatar(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let cfg = db::instance_config(&state.pool).await?;
    let max_avatar_bytes = db::effective_limits(&state.pool, &cfg, Some(&user))
        .await?
        .max_avatar_bytes;
    let mut data: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(format!("malformed multipart: {e}")))?
    {
        if matches!(field.name(), Some("avatar") | Some("file")) {
            data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| AppError::bad_request(format!("unreadable upload: {e}")))?
                    .to_vec(),
            );
        }
    }
    let Some(data) = data else {
        return Err(AppError::bad_request("missing avatar field"));
    };
    if data.len() as i64 > max_avatar_bytes {
        return Err(AppError::TooLarge {
            max_bytes: max_avatar_bytes,
        });
    }
    // Re-validate sniffed bytes; spoofed extensions never reach the store.
    let sniffed = mime::sniff_mime(&data);
    let Some(ext) = avatar_ext(&sniffed) else {
        return Err(AppError::UnsupportedMedia { mime: sniffed });
    };
    let key = avatar_key(&user.id, ext);
    state
        .store
        .put(&key, bytes::Bytes::from(data), &sniffed)
        .await?;
    if let Some(old) = user.avatar_key.as_deref() {
        if old != key {
            if let Err(e) = state.store.delete(old).await {
                tracing::warn!(error = %e, "avatar: old key delete failed");
            }
        }
    }
    db::set_avatar_key(&state.pool, &user.id, Some(&key)).await?;
    Ok(Redirect::to("/account").into_response())
}

pub async fn serve_avatar(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(AppError::NotFound);
    }
    let key = format!("avatars/{name}");
    let bytes = match state.store.get(&key).await {
        Ok(b) => b,
        Err(crate::storage::StorageError::NotFound(_)) => return Err(AppError::NotFound),
        Err(e) => return Err(AppError::from(e)),
    };
    if !mime::is_avatar_mime(&mime::sniff_mime(&bytes)) {
        return Err(AppError::NotFound);
    }
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, mime::sniff_mime(&bytes))
        .header(axum::http::header::CONTENT_LENGTH, bytes.len())
        .header("X-Content-Type-Options", "nosniff")
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=86400")
        .body(axum::body::Body::from(bytes))
        .map_err(|e| AppError::internal(e.to_string()))
}

// ---- dashboard item actions (HTML form posts) ----

pub async fn dashboard_delete_file(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(segment): Path<String>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let core = crate::ids::strip_to_core(&segment).to_string();
    let row = db::find_file(&state.pool, &core)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.owner_id != Some(user.id) {
        return Err(AppError::NotFound);
    }
    remove_file(&state, &row).await?;
    Ok(Redirect::to("/account").into_response())
}

#[derive(Deserialize)]
pub struct DashboardVisibility {
    pub visibility: String,
}

pub async fn dashboard_file_visibility(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(segment): Path<String>,
    Form(f): Form<DashboardVisibility>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let core = crate::ids::strip_to_core(&segment).to_string();
    set_file_visibility(&state, &core, user.id, f.visibility.trim()).await?;
    Ok(Redirect::to("/account").into_response())
}

pub async fn dashboard_delete_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(core): Path<String>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let row = db::find_paste(&state.pool, core.trim())
        .await?
        .ok_or(AppError::NotFound)?;
    if row.owner_id != Some(user.id) {
        return Err(AppError::NotFound);
    }
    sqlx::query("DELETE FROM pastes WHERE id_core = $1")
        .bind(core.trim())
        .execute(&state.pool)
        .await?;
    Ok(Redirect::to("/account").into_response())
}

pub async fn dashboard_paste_visibility(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(core): Path<String>,
    Form(f): Form<DashboardVisibility>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    if !matches!(f.visibility.trim(), "public" | "unlisted") {
        return Err(AppError::bad_request("visibility must be public|unlisted"));
    }
    let row = db::find_paste(&state.pool, core.trim())
        .await?
        .ok_or(AppError::NotFound)?;
    if row.owner_id != Some(user.id) {
        return Err(AppError::NotFound);
    }
    sqlx::query("UPDATE pastes SET visibility = $1 WHERE id_core = $2")
        .bind(f.visibility.trim())
        .bind(core.trim())
        .execute(&state.pool)
        .await?;
    Ok(Redirect::to("/account").into_response())
}

// ---- API tokens ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenForm {
    pub label: Option<String>,
    pub scope_upload: Option<String>,
    pub scope_paste: Option<String>,
    pub scope_delete: Option<String>,
    pub scope_read: Option<String>,
    pub expiry: Option<String>,
}

pub async fn create_token(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let label = f.label.map(|s| s.trim().to_string()).unwrap_or_default();
    if label.len() > 64 {
        return Err(AppError::bad_request("label must be <= 64 chars"));
    }
    let requested: Vec<&str> = [
        f.scope_upload.as_deref(),
        f.scope_paste.as_deref(),
        f.scope_delete.as_deref(),
        f.scope_read.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    if requested
        .iter()
        .any(|scope| !crate::identity::API_SCOPES.contains(scope))
    {
        return Err(AppError::bad_request("invalid token scope"));
    }
    let scopes: Vec<String> = crate::identity::API_SCOPES
        .iter()
        .filter(|scope| requested.contains(scope))
        .map(|scope| (*scope).to_string())
        .collect();
    if scopes.is_empty() {
        return Err(AppError::bad_request("select at least one token scope"));
    }
    let expires_at = match f.expiry.as_deref().unwrap_or("never") {
        "7d" => Some(Utc::now() + Duration::days(7)),
        "30d" => Some(Utc::now() + Duration::days(30)),
        "90d" => Some(Utc::now() + Duration::days(90)),
        "never" => None,
        _ => return Err(AppError::bad_request("invalid token expiry")),
    };
    let raw = auth::new_api_token();
    let hash = auth::api_token_hash(&state.env.session_secret, &raw);
    db::insert_token(
        &state.pool,
        &Uuid::new_v4(),
        &user.id,
        &hash,
        &label,
        &scopes,
        expires_at,
    )
    .await?;
    tracing::info!(user = %user.username, "api token created");
    if !wants_html(&headers) {
        return Ok(Json(json!({
            "token": raw,
            "scopes": scopes,
            "expires_at": expires_at,
            "note": "treat like a password; it is shown once"
        }))
        .into_response());
    }
    dashboard_response(&state, &user, Some(raw), None).await
}

pub async fn revoke_token(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let Some(user) = current_user(&state.pool, &state.env.session_secret, &session, &headers).await
    else {
        return Err(AppError::Unauthorized);
    };
    let id: Uuid = id
        .parse()
        .map_err(|_| AppError::bad_request("bad token id"))?;
    db::revoke_token(&state.pool, &id, &user.id).await?;
    Ok(Redirect::to("/account").into_response())
}

// ---- public profile ----

#[derive(Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
}

pub async fn profile(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(username): Path<String>,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    use askama::Template;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let cfg = db::instance_config(&state.pool).await?;
    let Some(profile) = db::find_user_by_name(&state.pool, username.trim()).await? else {
        return Err(AppError::NotFound);
    };
    let page = q.page.unwrap_or(1).max(1);
    let (mut files, mut pastes) =
        db::public_items(&state.pool, &profile.id, 21, (page - 1) * 20).await?;
    let has_next = files.len() > 20 || pastes.len() > 20;
    files.truncate(20);
    pastes.truncate(20);
    let collections = crate::routes::collections::public_for_owner(&state.pool, profile.id).await?;
    let page_view = crate::views::ProfilePage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user,
        avatar_url: avatar_url(profile.avatar_key.as_deref()),
        files,
        pastes,
        collections,
        page,
        has_next,
        profile,
    };
    let body = page_view
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Html(body).into_response())
}
