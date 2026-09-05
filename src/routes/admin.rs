//! Admin UI: instance config, users, roles, OIDC mappings, and invites.
//! Non-admins get 404 so admin-route probing reveals nothing.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    config::InstanceConfig,
    db::{self, User},
    error::AppError,
    identity::current_user,
    state::AppState,
    views::{AdminPage, AdminRoleOption, AdminRoleRow, AdminUserRow},
};

pub(crate) async fn require_admin(
    state: &AppState,
    session: &Session,
    headers: &HeaderMap,
) -> Result<User, AppError> {
    let user = current_user(&state.pool, &state.env.session_secret, session, headers).await;
    match user {
        Some(user) if user.is_admin => Ok(user),
        _ => Err(AppError::NotFound),
    }
}

pub async fn admin_page(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use askama::Template;

    let admin = require_admin(&state, &session, &headers).await?;
    let cfg = db::instance_config(&state.pool).await?;
    let raw_users = db::list_users(&state.pool).await?;
    let raw_roles = super::roles::list(&state.pool).await?;
    let mappings = super::roles::list_mappings(&state.pool).await?;
    let invites = super::invites::list(&state.pool).await?;

    let roles = raw_roles
        .iter()
        .cloned()
        .map(|role| AdminRoleRow {
            mappings: mappings
                .iter()
                .filter(|mapping| mapping.role_id == role.id)
                .cloned()
                .collect(),
            members: raw_users
                .iter()
                .filter(|user| user.role_id == Some(role.id))
                .map(|user| user.username.clone())
                .collect(),
            role,
        })
        .collect();
    let users = raw_users
        .into_iter()
        .map(|user| AdminUserRow {
            roles: raw_roles
                .iter()
                .map(|role| AdminRoleOption {
                    id: role.id,
                    name: role.name.clone(),
                    selected: user.role_id == Some(role.id),
                })
                .collect(),
            quota_override_value: user
                .quota_override_bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
            user,
        })
        .collect();
    let page = AdminPage {
        instance_name: cfg.instance_name.clone(),
        tagline: cfg.tagline.clone(),
        icon_url: cfg.icon_url.clone(),
        user: Some(admin),
        cfg,
        users,
        roles,
        invites,
    };
    let body = page
        .render()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(Html(body).into_response())
}

fn parse_flag(value: &str) -> Option<bool> {
    match value.trim().to_lowercase().as_str() {
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
    let actor = require_admin(&state, &session, &headers).await?;
    let mut cfg: InstanceConfig = db::instance_config(&state.pool).await?;
    let before: HashMap<&'static str, String> = cfg.as_pairs().into_iter().collect();

    if let Some(value) = form.get("instance_name") {
        cfg.instance_name = value.trim().to_string();
    }
    if let Some(value) = form.get("tagline") {
        cfg.tagline = value.trim().to_string();
    }
    if let Some(value) = form.get("icon_url") {
        cfg.icon_url = value.trim().to_string();
    }
    if let Some(value) = form.get("registration_mode") {
        cfg.registration_mode = value.trim().to_string();
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
        if let Some(value) = form.get(key) {
            *slot = value
                .trim()
                .parse::<i64>()
                .map_err(|_| AppError::bad_request(format!("{key} must be a number")))?;
        }
    }
    // Unchecked boxes are absent from the post. The legacy allow_registration
    // bool is deliberately ignored; registration_mode is the sole gate.
    for (key, slot) in [
        ("allow_anonymous", &mut cfg.allow_anonymous),
        ("allow_local_login", &mut cfg.allow_local_login),
        ("allow_oidc", &mut cfg.allow_oidc),
        ("scan_uploads", &mut cfg.scan_uploads),
        (
            "block_encrypted_archives",
            &mut cfg.block_encrypted_archives,
        ),
    ] {
        *slot = match form.get(key) {
            Some(value) => parse_flag(value)
                .ok_or_else(|| AppError::bad_request(format!("{key} must be true|false")))?,
            None => false,
        };
    }

    cfg.validate().map_err(AppError::bad_request)?;
    let changed_keys: Vec<&str> = cfg
        .as_pairs()
        .into_iter()
        .filter_map(|(key, value)| (before.get(key) != Some(&value)).then_some(key))
        .collect();
    if !changed_keys.is_empty() {
        db::set_instance_config(&state.pool, &cfg).await?;
        db::audit(
            &state.pool,
            Some(&actor.id),
            "config.update",
            Some("instance_config"),
            None,
            Some(json!({"changed_keys": changed_keys})),
        )
        .await?;
    }
    // Live cap, not a snapshot: a changed `max_file_bytes` applies to the
    // next request without a restart (storing an unchanged value is a no-op).
    state
        .body_limit
        .store(cfg.body_limit(), std::sync::atomic::Ordering::Relaxed);
    tracing::info!(?changed_keys, "instance config updated");
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
    Form(form): Form<GrantForm>,
) -> Result<Response, AppError> {
    let admin = require_admin(&state, &session, &headers).await?;
    let id: Uuid = id
        .parse()
        .map_err(|_| AppError::bad_request("bad user id"))?;
    let make_admin = match form.action.as_str() {
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
    db::audit(
        &state.pool,
        Some(&admin.id),
        "user.admin",
        Some("user"),
        Some(&id.to_string()),
        Some(json!({"is_admin": make_admin})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}
