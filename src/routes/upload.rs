//! `POST /api/upload`: multipart-only uploads, ID/ext logic, visibility and
//! expiry clamping, delete-token issue.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Multipart, State},
    http::{header::LOCATION, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use tower_sessions::Session;
use tracing::info;

use crate::{
    auth,
    db::{self},
    error::{AppError, JsonError},
    identity::current_user,
    ids, mime,
    routes::common::wants_html,
    state::AppState,
    storage::file_key,
};

pub async fn upload(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, JsonError> {
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|e| AppError::from(e).json())?;

    if user.is_none() && !cfg.allow_anonymous {
        return Err(AppError::forbidden("anonymous uploads are disabled").json());
    }
    if user.is_none() && !state.anon_limiter.check(addr.ip()) {
        return Err(AppError::RateLimited.json());
    }
    // Per-role cap, enforced while streaming so oversize bodies 413 without
    // being buffered first (tower-http's boot body limit is the outer guard).
    let role_cap = match &user {
        Some(_) => cfg.max_file_bytes,
        None => cfg.max_file_bytes.min(cfg.anonymous_max_bytes),
    };

    let mut filename: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    let mut expires_raw: Option<String> = None;
    let mut visibility_raw: Option<String> = None;
    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!(error = ?e, "multipart next_field failed");
        AppError::bad_request(format!("malformed multipart: {e}")).json()
    })? {
        match field.name().unwrap_or("") {
            "file" => {
                filename = Some(field.file_name().unwrap_or("upload").to_string());
                let mut data = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(|e| {
                    tracing::warn!(error = ?e, "multipart field read failed");
                    AppError::bad_request(format!("unreadable file field: {e}")).json()
                })? {
                    if data.len() as u64 + chunk.len() as u64 > role_cap as u64 + 1 {
                        return Err(AppError::TooLarge {
                            max_bytes: role_cap,
                        }
                        .json());
                    }
                    data.extend_from_slice(&chunk);
                }
                bytes = Some(data);
            }
            "expires_in_secs" => {
                expires_raw = Some(field.text().await.map_err(|e| {
                    AppError::bad_request(format!("bad expires_in_secs: {e}")).json()
                })?);
            }
            "visibility" => {
                visibility_raw =
                    Some(field.text().await.map_err(|e| {
                        AppError::bad_request(format!("bad visibility: {e}")).json()
                    })?);
            }
            _ => {}
        }
    }

    let filename = filename.unwrap_or_else(|| "upload".into());
    let bytes = bytes.ok_or_else(|| AppError::bad_request("missing file field").json())?;
    if bytes.is_empty() {
        return Err(AppError::bad_request("empty file").json());
    }

    let sniffed = mime::sniff_mime(&bytes);
    if mime::is_upload_blocked(&sniffed) {
        return Err(AppError::UnsupportedMedia { mime: sniffed }.json());
    }

    let visibility = match visibility_raw.as_deref().map(str::trim) {
        None | Some("") | Some("unlisted") => "unlisted",
        Some("public") => {
            if user.is_none() {
                return Err(AppError::bad_request("public visibility requires login").json());
            }
            "public"
        }
        Some(other) => {
            return Err(AppError::bad_request(format!("bad visibility: {other:?}")).json());
        }
    };

    let requested = ids::parse_expiry_param(expires_raw.as_deref())
        .map_err(|_| AppError::bad_request("bad expires_in_secs").json())?;
    let secs = ids::clamp_expiry(
        requested,
        cfg.min_expiry_secs,
        cfg.default_expiry_secs,
        cfg.max_expiry_secs,
    );
    let expires_at = Utc::now() + chrono::TimeDelta::seconds(secs);

    // PK-retry for the 8-char core (2^40 space; 5 tries then 500).
    let mut core = String::new();
    for _ in 0..5 {
        let c = ids::generate_core();
        let hit = db::find_file(&state.pool, &c)
            .await
            .map_err(|e| AppError::from(e).json())?;
        if hit.is_none() {
            core = c;
            break;
        }
    }
    if core.is_empty() {
        return Err(AppError::internal("id allocation failed").json());
    }

    let ext = ids::normalize_ext(&filename);
    let storage_key = file_key(&core, &ext);
    state
        .store
        .put(&storage_key, bytes::Bytes::from(bytes.clone()), &sniffed)
        .await
        .map_err(|e| AppError::from(e).json())?;

    let digest = Sha256::digest(&bytes);
    let delete_token_raw = auth::new_delete_token();
    let delete_token_hash = auth::delete_token_hash(&state.env.session_secret, &delete_token_raw);
    sqlx::query(
        "INSERT INTO files (id_core, ext, owner_id, original_name, size_bytes, mime_stored, sha256, storage_key, visibility, expires_at, delete_token_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&core)
    .bind(&ext)
    .bind(user.as_ref().map(|u| u.id))
    .bind(mime::sanitize_filename(&filename))
    .bind(bytes.len() as i64)
    .bind(&sniffed)
    .bind(digest.to_vec())
    .bind(&storage_key)
    .bind(visibility)
    .bind(expires_at)
    .bind(&delete_token_hash)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::from(e).json())?;

    info!(
        core = %core, size = bytes.len(), mime = %sniffed,
        user = user.as_ref().map(|u| u.username.as_str()).unwrap_or("-"),
        "upload stored"
    );

    let preview_url = format!("{}/f/{core}{ext}", state.env.base_url);
    let raw_url = format!("{}/{core}{ext}", state.env.base_url);
    if wants_html(&headers) {
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, preview_url)], "").into_response());
    }
    Ok(Json(json!({
        "id_core": core,
        "preview_url": preview_url,
        "raw_url": raw_url,
        "expires_at": expires_at,
        "delete_token": delete_token_raw,
    }))
    .into_response())
}
