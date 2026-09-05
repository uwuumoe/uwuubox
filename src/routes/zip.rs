//! On-demand ZIP bundles from live file and paste capability cores.

use std::{
    collections::HashSet,
    io::{Cursor, Write},
};

use axum::{
    body::Body,
    extract::State,
    http::{header::*, HeaderMap, Response, StatusCode},
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use tower_sessions::Session;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::{
    db,
    error::{AppError, JsonError},
    identity::{current_identity, require_scope},
    ids, mime,
    state::AppState,
};

const MAX_ITEMS: usize = 32;

#[derive(Debug, Deserialize)]
pub struct ZipRequest {
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub pastes: Vec<String>,
}

struct ArchiveEntry {
    name: String,
    bytes: Bytes,
}

pub async fn create(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(request): Json<ZipRequest>,
) -> Result<Response<Body>, JsonError> {
    create_inner(state, session, headers, request)
        .await
        .map_err(AppError::json)
}

async fn create_inner(
    state: AppState,
    session: Session,
    headers: HeaderMap,
    request: ZipRequest,
) -> Result<Response<Body>, AppError> {
    let item_count = request
        .files
        .len()
        .checked_add(request.pastes.len())
        .ok_or(AppError::TooLarge {
            max_bytes: MAX_ITEMS as i64,
        })?;
    if item_count == 0 {
        return Err(AppError::bad_request("files or pastes must not be empty"));
    }
    if item_count > MAX_ITEMS {
        return Err(AppError::TooLarge {
            max_bytes: MAX_ITEMS as i64,
        });
    }

    let identity =
        current_identity(&state.pool, &state.env.session_secret, &session, &headers).await;
    if headers.contains_key(AUTHORIZATION) {
        require_scope(&identity, "read")?;
    }
    let user = identity.as_ref().map(|identity| &identity.user);
    let cfg = db::instance_config(&state.pool).await?;
    let limits = db::effective_limits(&state.pool, &cfg, user).await?;

    let mut total = 0i64;
    let mut files = Vec::with_capacity(request.files.len());
    for requested_core in request.files {
        let core = ids::strip_to_core(&requested_core);
        if core.is_empty() || ids::is_reserved(core) {
            return Err(AppError::NotFound);
        }
        let file = db::find_file(&state.pool, core)
            .await?
            .filter(|file| !db::is_expired(file.expires_at))
            .ok_or(AppError::NotFound)?;
        if file.burn_after_read || file.access_password_hash.is_some() {
            return Err(AppError::bad_request(
                "burn-armed and password-protected files cannot be archived",
            ));
        }
        total = total
            .checked_add(file.size_bytes)
            .ok_or(AppError::TooLarge {
                max_bytes: limits.max_file_bytes,
            })?;
        if total > limits.max_file_bytes {
            return Err(AppError::TooLarge {
                max_bytes: limits.max_file_bytes,
            });
        }
        files.push(file);
    }

    let mut pastes = Vec::with_capacity(request.pastes.len());
    for requested_core in request.pastes {
        let core = ids::strip_to_core(&requested_core);
        if core.is_empty() || ids::is_reserved(core) {
            return Err(AppError::NotFound);
        }
        let paste = db::find_paste(&state.pool, core)
            .await?
            .filter(|paste| !db::is_expired(paste.expires_at))
            .ok_or(AppError::NotFound)?;
        if paste.burn_after_read || paste.access_password_hash.is_some() {
            return Err(AppError::bad_request(
                "burn-armed and password-protected pastes cannot be archived",
            ));
        }
        let paste_len = i64::try_from(paste.body.len())
            .map_err(|_| AppError::internal("paste length overflow"))?;
        total = total.checked_add(paste_len).ok_or(AppError::TooLarge {
            max_bytes: limits.max_file_bytes,
        })?;
        if total > limits.max_file_bytes {
            return Err(AppError::TooLarge {
                max_bytes: limits.max_file_bytes,
            });
        }
        pastes.push(paste);
    }

    let mut seen_names = HashSet::with_capacity(item_count);
    let mut entries = Vec::with_capacity(item_count);
    for file in files {
        let name = unique_name(&file.original_name, &mut seen_names);
        let bytes = state.store.get(&file.storage_key).await?;
        entries.push(ArchiveEntry { name, bytes });
    }
    for paste in pastes {
        let stem = paste
            .title
            .as_deref()
            .filter(|title| !title.trim().is_empty())
            .unwrap_or_else(|| paste.id_core.trim_end());
        let name = unique_name(
            &format!("{}.txt", mime::sanitize_filename(stem)),
            &mut seen_names,
        );
        entries.push(ArchiveEntry {
            name,
            bytes: Bytes::from(paste.body),
        });
    }

    let archive = tokio::task::spawn_blocking(move || build_archive(entries))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map_err(|error| AppError::internal(error.to_string()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(CONTENT_DISPOSITION, "attachment; filename=\"uwuubox.zip\"")
        .header(CONTENT_LENGTH, archive.len())
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(archive))
        .map_err(|error| AppError::internal(error.to_string()))
}

fn unique_name(requested: &str, seen: &mut HashSet<String>) -> String {
    let base = mime::sanitize_filename(requested);
    if seen.insert(base.clone()) {
        return base;
    }
    let (stem, extension) = match base.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, format!(".{extension}")),
        _ => (base.as_str(), String::new()),
    };
    for suffix in 2usize.. {
        let candidate = format!("{stem} ({suffix}){extension}");
        if seen.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!()
}

fn build_archive(entries: Vec<ArchiveEntry>) -> zip::result::ZipResult<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for entry in entries {
        writer.start_file(entry.name, options)?;
        writer.write_all(&entry.bytes)?;
    }
    Ok(writer.finish()?.into_inner())
}
