//! File preview pages (`/f/:core`), raw bytes (`/:core`), delete + visibility.
//!
//! Lookup is exact-match on the core; any URL extension is ignored (the
//! canonical link always uses the stored ext).

use axum::{
    extract::{Path, State},
    http::{header::*, HeaderMap},
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;

use crate::{
    db::{self, FileRow},
    error::{AppError, JsonError},
    identity::current_user,
    ids, mime,
    routes::common::{check_delete_access, file_kind},
    state::AppState,
    views::{human_bytes, human_time, FilePreviewPage},
};

const TEXT_PREVIEW_LIMIT: i64 = 262_144;

async fn load_live_file(state: &AppState, segment: &str) -> Result<FileRow, AppError> {
    let core = ids::strip_to_core(segment);
    if core.is_empty() || ids::is_reserved(core) {
        return Err(AppError::NotFound);
    }
    let f = db::find_file(&state.pool, core)
        .await?
        .ok_or(AppError::NotFound)?;
    if f.expires_at < Utc::now() {
        return Err(AppError::NotFound);
    }
    Ok(f)
}

fn raw_response(file: &FileRow, bytes: &[u8]) -> Result<Response, AppError> {
    let inline = mime::should_inline(&file.mime_stored, bytes);
    let content_type = if inline {
        file.mime_stored.clone()
    } else {
        "application/octet-stream".into()
    };
    let content_type: axum::http::HeaderValue = content_type
        .parse()
        .map_err(|_| AppError::internal("bad stored mime"))?;

    let mut builder = Response::builder()
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, bytes.len())
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "sandbox")
        .header(CACHE_CONTROL, "public, max-age=86400");
    if !inline {
        let name = mime::sanitize_filename(&file.original_name);
        let disp: axum::http::HeaderValue = format!("attachment; filename=\"{name}\"")
            .parse()
            .map_err(|_| AppError::internal("bad filename"))?;
        builder = builder.header(CONTENT_DISPOSITION, disp);
    }
    builder
        .body(axum::body::Body::from(bytes.to_vec()))
        .map_err(|e| AppError::internal(e.to_string()))
}

pub async fn preview(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(segment): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use askama::Template;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let file = load_live_file(&state, &segment).await?;
    let cfg = db::instance_config(&state.pool).await?;
    let owner_name = match file.owner_id {
        Some(id) => db::find_user_by_id(&state.pool, &id)
            .await?
            .map(|u| u.username),
        None => None,
    };
    let is_owner = match (&user, file.owner_id) {
        (Some(u), Some(o)) => u.id == o,
        _ => false,
    };
    let kind = file_kind(&file.mime_stored);
    let text_snippet = if kind == "text" && file.size_bytes <= TEXT_PREVIEW_LIMIT {
        match state.store.get(&file.storage_key).await {
            Ok(b) => Some(String::from_utf8_lossy(&b).chars().take(20_000).collect()),
            Err(_) => None,
        }
    } else {
        None
    };
    let raw_url = format!(
        "{}/{}{}",
        state.env.base_url,
        file.id_core.trim_end(),
        file.ext
    );
    let preview_url = format!(
        "{}/f/{}{}",
        state.env.base_url,
        file.id_core.trim_end(),
        file.ext
    );
    let page = FilePreviewPage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user,
        size_human: human_bytes(file.size_bytes),
        expires_human: human_time(&file.expires_at),
        sha256_hex: hex::encode(&file.sha256),
        owner_name,
        is_owner,
        kind,
        text_snippet,
        raw_url,
        preview_url,
        file,
    };
    page.render()
        .map_err(|e| AppError::internal(e.to_string()))
        .map(axum::response::Html)
}

pub async fn raw(
    State(state): State<AppState>,
    Path(segment): Path<String>,
) -> Result<Response, AppError> {
    let file = load_live_file(&state, &segment).await?;
    // Missing key on download → 404 page, never 500.
    let bytes = match state.store.get(&file.storage_key).await {
        Ok(b) => b,
        Err(crate::storage::StorageError::NotFound(_)) => return Err(AppError::NotFound),
        Err(e) => return Err(AppError::from(e)),
    };
    raw_response(&file, &bytes)
}

#[derive(Deserialize)]
pub struct DeleteBody {
    pub delete_token: Option<String>,
}

/// Remove object then row; shared by the JSON API and dashboard form posts.
pub async fn remove_file(state: &AppState, row: &FileRow) -> Result<(), AppError> {
    state.store.delete(&row.storage_key).await?;
    sqlx::query("DELETE FROM files WHERE id_core = $1")
        .bind(&row.id_core)
        .execute(&state.pool)
        .await?;
    Ok(())
}

pub async fn delete_file(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(segment): Path<String>,
    body: Option<Json<DeleteBody>>,
) -> Result<impl IntoResponse, JsonError> {
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let core = ids::strip_to_core(&segment).to_string();
    let row = db::find_file(&state.pool, &core)
        .await
        .map_err(|e| AppError::from(e).json())?
        .ok_or(AppError::NotFound.json())?;
    let provided = body.as_ref().and_then(|b| b.delete_token.as_deref());
    if !check_delete_access(
        user.as_ref(),
        row.owner_id,
        row.delete_token_hash.as_deref(),
        &state.env.session_secret,
        provided,
    ) {
        return Err(AppError::forbidden("not allowed").json());
    }
    remove_file(&state, &row).await.map_err(|e| e.json())?;
    Ok(Json(json!({"deleted": core.trim_end()})))
}

#[derive(Deserialize)]
pub struct VisibilityBody {
    pub visibility: String,
}

pub async fn set_file_visibility(
    state: &AppState,
    core: &str,
    user_id: uuid::Uuid,
    visibility: &str,
) -> Result<(), AppError> {
    if !matches!(visibility, "public" | "unlisted") {
        return Err(AppError::bad_request("visibility must be public|unlisted"));
    }
    let row = db::find_file(&state.pool, core)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.owner_id != Some(user_id) {
        // Not-owner sees 404 so unlisted cores stay unenumerable.
        return Err(AppError::NotFound);
    }
    sqlx::query("UPDATE files SET visibility = $1 WHERE id_core = $2")
        .bind(visibility)
        .bind(core)
        .execute(&state.pool)
        .await?;
    Ok(())
}

pub async fn toggle_file(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(segment): Path<String>,
    Json(body): Json<VisibilityBody>,
) -> Result<impl IntoResponse, JsonError> {
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let Some(u) = user else {
        return Err(AppError::Unauthorized.json());
    };
    let core = ids::strip_to_core(&segment).to_string();
    set_file_visibility(&state, &core, u.id, body.visibility.trim())
        .await
        .map_err(|e| e.json())?;
    Ok(Json(
        json!({"id_core": core.trim_end(), "visibility": body.visibility.trim()}),
    ))
}
