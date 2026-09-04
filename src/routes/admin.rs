//! Admin UI: instance config form + user grants. Non-admins get 404
//! (not 403) so admin-route probing reveals nothing.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    config::InstanceConfig,
    db::{self, User},
    error::AppError,
    identity::current_user,
    state::AppState,
    views::AdminPage,
};

async fn require_admin(
    state: &AppState,
    session: &Session,
    headers: &HeaderMap,
) -> Result<User, AppError> {
    let user = current_user(&state.pool, &state.env.session_secret, session, headers).await;
    match user {
        Some(u) if u.is_admin => Ok(u),
        _ => Err(AppError::NotFound),
    }
}

pub async fn admin_page(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use askama::Template;
    let user = require_admin(&state, &session, &headers).await?;
    let cfg = db::instance_config(&state.pool).await?;
    let users = db::list_users(&state.pool).await?;
    let page = AdminPage {
        instance_name: cfg.instance_name.clone(),
        tagline: cfg.tagline.clone(),
        icon_url: cfg.icon_url.clone(),
        user: Some(user),
        cfg,
        users,
    };
    let body = page
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Html(body).into_response())
}

fn parse_flag(v: &str) -> Option<bool> {
    match v.trim().to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub async fn update_config(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    require_admin(&state, &session, &headers).await?;
    let mut cfg: InstanceConfig = db::instance_config(&state.pool).await?;

    if let Some(v) = form.get("instance_name") {
        cfg.instance_name = v.trim().to_string();
    }
    if let Some(v) = form.get("tagline") {
        cfg.tagline = v.trim().to_string();
    }
    if let Some(v) = form.get("icon_url") {
        cfg.icon_url = v.trim().to_string();
    }
    for (key, slot) in [
        ("max_file_bytes", &mut cfg.max_file_bytes),
        ("max_paste_bytes", &mut cfg.max_paste_bytes),
        ("max_avatar_bytes", &mut cfg.max_avatar_bytes),
        ("min_expiry_secs", &mut cfg.min_expiry_secs),
        ("max_expiry_secs", &mut cfg.max_expiry_secs),
        ("default_expiry_secs", &mut cfg.default_expiry_secs),
        ("anonymous_max_bytes", &mut cfg.anonymous_max_bytes),
    ] {
        if let Some(v) = form.get(key) {
            *slot = v
                .trim()
                .parse::<i64>()
                .map_err(|_| AppError::bad_request(format!("{key} must be a number")))?;
        }
    }
    // Unchecked boxes are absent from the post → false.
    for (key, slot) in [
        ("allow_anonymous", &mut cfg.allow_anonymous),
        ("allow_registration", &mut cfg.allow_registration),
        ("allow_local_login", &mut cfg.allow_local_login),
        ("allow_oidc", &mut cfg.allow_oidc),
    ] {
        *slot = match form.get(key) {
            Some(v) => parse_flag(v)
                .ok_or_else(|| AppError::bad_request(format!("{key} must be true|false")))?,
            None => false,
        };
    }

    cfg.validate().map_err(AppError::bad_request)?;
    db::set_instance_config(&state.pool, &cfg).await?;
    tracing::info!("instance config updated");
    Ok(Redirect::to("/admin").into_response())
}

#[derive(Deserialize)]
pub struct GrantForm {
    pub action: String,
}

pub async fn grant(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<GrantForm>,
) -> Result<Response, AppError> {
    let admin = require_admin(&state, &session, &headers).await?;
    let id: Uuid = id
        .parse()
        .map_err(|_| AppError::bad_request("bad user id"))?;
    let make_admin = match f.action.as_str() {
        "grant" => true,
        "revoke" => false,
        _ => return Err(AppError::bad_request("action must be grant|revoke")),
    };
    if id == admin.id && !make_admin {
        return Err(AppError::bad_request("cannot revoke your own admin"));
    }
    db::find_user_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    db::set_admin(&state.pool, &id, make_admin).await?;
    Ok(Redirect::to("/admin").into_response())
}
