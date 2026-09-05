//! `POST /api/upload`: streamed multipart uploads, per-role caps, content
//! processing, deduplicated object storage, and delete-token issue.

use std::{io::Cursor, net::SocketAddr};

use axum::{
    extract::{ConnectInfo, Multipart, State},
    http::{header::LOCATION, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use chrono::Utc;
use img_parts::DynImage;
use serde_json::json;
use sha2::{Digest, Sha256};
use tower_sessions::Session;
use tracing::info;

use crate::{
    auth,
    db::{self},
    error::AppError,
    identity::{current_identity, require_scope},
    ids, mime,
    routes::common::wants_html,
    scan::{self, Verdict},
    state::AppState,
    storage::file_key,
};

pub async fn upload(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, crate::error::JsonError> {
    let metrics = state.metrics.clone();
    match upload_inner(state, addr, session, headers, multipart).await {
        Ok((response, accepted_bytes)) => {
            metrics.uploads.with_label_values(&["ok"]).inc();
            metrics.upload_bytes.inc_by(accepted_bytes);
            Ok(response)
        }
        Err(error) => {
            let status = match &error {
                AppError::TooLarge { .. } => "too_large",
                AppError::RateLimited => "rate_limited",
                AppError::BadRequest(_)
                | AppError::Unauthorized
                | AppError::Forbidden(_)
                | AppError::NotFound
                | AppError::UnsupportedMedia { .. }
                | AppError::Unprocessable(_) => "rejected",
                _ => "error",
            };
            metrics.uploads.with_label_values(&[status]).inc();
            Err(error.json())
        }
    }
}

async fn upload_inner(
    state: AppState,
    addr: SocketAddr,
    session: Session,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<(Response, u64), AppError> {
    let identity =
        current_identity(&state.pool, &state.env.session_secret, &session, &headers).await;
    if headers.contains_key(axum::http::header::AUTHORIZATION) {
        require_scope(&identity, "upload")?;
    }
    let user = identity.as_ref().map(|identity| &identity.user);
    let cfg = db::instance_config(&state.pool).await?;

    if user.is_none() && !cfg.allow_anonymous {
        return Err(AppError::forbidden("anonymous uploads are disabled"));
    }
    if user.is_none() && !state.anon_limiter.check(addr.ip()) {
        return Err(AppError::RateLimited);
    }

    let limits = db::effective_limits(&state.pool, &cfg, user).await?;
    let role_cap = if user.is_some() {
        limits.max_file_bytes
    } else {
        limits.max_file_bytes.min(cfg.anonymous_max_bytes)
    };
    let quota_remaining = match (user, limits.quota_bytes) {
        (Some(user), Some(quota)) => {
            let used = db::storage_used(&state.pool, &user.id).await?;
            let remaining = quota.saturating_sub(used).max(0);
            if used.saturating_add(1) > quota {
                return Err(AppError::TooLarge {
                    max_bytes: remaining,
                });
            }
            Some(remaining)
        }
        _ => None,
    };
    let stream_cap = quota_remaining
        .map(|remaining| role_cap.min(remaining))
        .unwrap_or(role_cap);

    let mut filename: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    let mut expires_raw: Option<String> = None;
    let mut visibility_raw: Option<String> = None;
    let mut burn_raw: Option<String> = None;
    let mut password_raw: Option<String> = None;
    let mut strip_exif_raw: Option<String> = None;
    while let Some(mut field) = multipart.next_field().await.map_err(|error| {
        tracing::warn!(error = ?error, "multipart next_field failed");
        AppError::bad_request(format!("malformed multipart: {error}"))
    })? {
        match field.name().unwrap_or("") {
            "file" => {
                filename = Some(field.file_name().unwrap_or("upload").to_string());
                let mut data = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(|error| {
                    tracing::warn!(error = ?error, "multipart field read failed");
                    AppError::bad_request(format!("unreadable file field: {error}"))
                })? {
                    let current = i64::try_from(data.len())
                        .map_err(|_| AppError::internal("upload length overflow"))?;
                    let incoming = i64::try_from(chunk.len())
                        .map_err(|_| AppError::internal("upload length overflow"))?;
                    if incoming > stream_cap.saturating_sub(current) {
                        return Err(AppError::TooLarge {
                            max_bytes: stream_cap,
                        });
                    }
                    data.extend_from_slice(&chunk);
                }
                bytes = Some(data);
            }
            "expires_in_secs" => {
                expires_raw = Some(field.text().await.map_err(|error| {
                    AppError::bad_request(format!("bad expires_in_secs: {error}"))
                })?);
            }
            "visibility" => {
                visibility_raw =
                    Some(field.text().await.map_err(|error| {
                        AppError::bad_request(format!("bad visibility: {error}"))
                    })?);
            }
            "burn_after_read" => {
                burn_raw = Some(field.text().await.map_err(|error| {
                    AppError::bad_request(format!("bad burn_after_read: {error}"))
                })?);
            }
            "access_password" => {
                password_raw = Some(field.text().await.map_err(|error| {
                    AppError::bad_request(format!("bad access_password field: {error}"))
                })?);
            }
            "strip_exif" => {
                strip_exif_raw =
                    Some(field.text().await.map_err(|error| {
                        AppError::bad_request(format!("bad strip_exif: {error}"))
                    })?);
            }
            _ => {}
        }
    }

    let filename = filename.unwrap_or_else(|| "upload".into());
    let raw_bytes = bytes.ok_or_else(|| AppError::bad_request("missing file field"))?;
    if raw_bytes.is_empty() {
        return Err(AppError::bad_request("empty file"));
    }

    let strip_default = user.map(|user| user.strip_exif_default).unwrap_or(false);
    let strip_exif = parse_bool_field(strip_exif_raw.as_deref(), strip_default, "strip_exif")?;
    let (bytes, exif_stripped) = if strip_exif {
        strip_image_metadata(Bytes::from(raw_bytes))?
    } else {
        (Bytes::from(raw_bytes), false)
    };
    if bytes.is_empty() {
        return Err(AppError::bad_request("empty file"));
    }

    let sniffed = mime::sniff_mime(&bytes);
    if mime::is_upload_blocked(&sniffed) {
        return Err(AppError::UnsupportedMedia { mime: sniffed });
    }
    if cfg.block_encrypted_archives && sniffed == "application/zip" {
        match zip_has_encrypted_entry(&bytes) {
            Ok(true) => {
                return Err(AppError::UnsupportedMedia {
                    mime: "encrypted application/zip".into(),
                })
            }
            Ok(false) => {}
            Err(_) => return Err(AppError::bad_request("invalid zip archive")),
        }
    }
    // ZIP exposes a reliable per-entry encryption bit. Other archive formats
    // remain best-effort through MIME policy and the configured scanner.

    let visibility = match visibility_raw.as_deref().map(str::trim) {
        None | Some("") | Some("unlisted") => "unlisted",
        Some("public") => {
            if user.is_some() && !limits.can_publish_public {
                return Err(AppError::forbidden(
                    "your role cannot publish public uploads",
                ));
            }
            "public"
        }
        Some(other) => return Err(AppError::bad_request(format!("bad visibility: {other:?}"))),
    };

    let burn_after_read = parse_bool_field(burn_raw.as_deref(), false, "burn_after_read")?;
    if burn_after_read && !limits.can_burn {
        return Err(AppError::bad_request(
            "burn-after-read is not allowed for your role",
        ));
    }
    let access_password_hash = match password_raw.as_deref() {
        None | Some("") => None,
        Some(password) => {
            if !(8..=72).contains(&password.chars().count()) {
                return Err(AppError::bad_request(
                    "access_password must be 8-72 characters",
                ));
            }
            Some(auth::hash_password(password).map_err(AppError::bad_request)?)
        }
    };

    let requested = ids::parse_expiry_param(expires_raw.as_deref())
        .map_err(|_| AppError::bad_request("bad expires_in_secs"))?;
    let secs = ids::clamp_expiry(
        requested,
        limits.min_expiry_secs,
        limits.default_expiry_secs,
        limits.max_expiry_secs,
    );
    let expires_at = Utc::now() + chrono::TimeDelta::seconds(secs);

    let scan_status = if cfg.scan_uploads {
        match scan::verdict(&state.env, &filename, &bytes, &sniffed).await {
            Verdict::Clean => "clean",
            Verdict::Skipped => "skipped",
            Verdict::Infected(reason) => return Err(AppError::Unprocessable(reason)),
        }
    } else {
        "skipped"
    };

    // Content processing is complete: this digest is the dedupe identity.
    let digest = Sha256::digest(&bytes).to_vec();

    // PK-retry for the 8-char core (2^40 space; 5 tries then 500).
    let mut core = String::new();
    for _ in 0..5 {
        let candidate = ids::generate_core();
        if db::find_file(&state.pool, &candidate).await?.is_none() {
            core = candidate;
            break;
        }
    }
    if core.is_empty() {
        return Err(AppError::internal("id allocation failed"));
    }

    let ext = ids::normalize_ext(&filename);
    let candidate_key = file_key(&core, &ext);
    let size_bytes =
        i64::try_from(bytes.len()).map_err(|_| AppError::internal("upload length overflow"))?;
    let (storage_key, is_new) =
        db::acquire_object(&state.pool, &digest, &candidate_key, size_bytes, &sniffed).await?;
    if is_new {
        if let Err(error) = state.store.put(&storage_key, bytes.clone(), &sniffed).await {
            rollback_object(&state, &storage_key).await;
            return Err(AppError::from(error));
        }
    }

    let delete_token_raw = auth::new_delete_token();
    let delete_token_hash = auth::delete_token_hash(&state.env.session_secret, &delete_token_raw);
    let inserted = sqlx::query(
        "INSERT INTO files
         (id_core, ext, owner_id, original_name, size_bytes, mime_stored, sha256,
          storage_key, visibility, burn_after_read, access_password_hash,
          scan_status, expires_at, delete_token_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(&core)
    .bind(&ext)
    .bind(user.map(|user| user.id))
    .bind(mime::sanitize_filename(&filename))
    .bind(size_bytes)
    .bind(&sniffed)
    .bind(&digest)
    .bind(&storage_key)
    .bind(visibility)
    .bind(burn_after_read)
    .bind(access_password_hash)
    .bind(scan_status)
    .bind(expires_at)
    .bind(&delete_token_hash)
    .execute(&state.pool)
    .await;
    if let Err(error) = inserted {
        rollback_object(&state, &storage_key).await;
        return Err(AppError::from(error));
    }

    info!(
        core = %core,
        size = bytes.len(),
        mime = %sniffed,
        user = user.map(|user| user.username.as_str()).unwrap_or("-"),
        "upload stored"
    );

    let preview_url = format!("{}/f/{core}{ext}", state.env.base_url);
    let raw_url = format!("{}/{core}{ext}", state.env.base_url);
    let response = if wants_html(&headers) {
        (StatusCode::SEE_OTHER, [(LOCATION, preview_url)], "").into_response()
    } else {
        Json(json!({
            "id_core": core,
            "preview_url": preview_url,
            "raw_url": raw_url,
            "expires_at": expires_at,
            "delete_token": delete_token_raw,
            "exif_stripped": exif_stripped,
        }))
        .into_response()
    };
    Ok((response, bytes.len() as u64))
}

fn parse_bool_field(raw: Option<&str>, default: bool, field: &str) -> Result<bool, AppError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(AppError::bad_request(format!("{field} must be a boolean"))),
    }
}

fn strip_image_metadata(bytes: Bytes) -> Result<(Bytes, bool), AppError> {
    let image = DynImage::from_bytes(bytes.clone())
        .map_err(|_| AppError::bad_request("could not strip metadata from malformed image"))?;
    let Some(mut image) = image else {
        return Ok((bytes, false));
    };

    let changed = match &mut image {
        DynImage::Jpeg(jpeg) => {
            const EXIF: &[u8] = b"Exif\0\0";
            const XMP: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
            const XMP_EXT: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
            let before = jpeg.segments().len();
            jpeg.segments_mut().retain(|segment| {
                let metadata_app = segment.marker() == img_parts::jpeg::markers::APP1
                    && (segment.contents().starts_with(EXIF)
                        || segment.contents().starts_with(XMP)
                        || segment.contents().starts_with(XMP_EXT));
                let comment = segment.marker() == img_parts::jpeg::markers::COM;
                let photoshop_metadata = segment.marker() == img_parts::jpeg::markers::APP13;
                !(metadata_app || comment || photoshop_metadata)
            });
            jpeg.segments().len() != before
        }
        DynImage::Png(png) => {
            let before = png.chunks().len();
            png.chunks_mut().retain(|chunk| {
                !matches!(
                    chunk.kind(),
                    [b'e', b'X', b'I', b'f']
                        | [b't', b'E', b'X', b't']
                        | [b'z', b'T', b'X', b't']
                        | [b'i', b'T', b'X', b't']
                        | [b't', b'I', b'M', b'E']
                )
            });
            png.chunks().len() != before
        }
        DynImage::WebP(webp) => {
            let before = webp.chunks().len();
            webp.remove_chunks_by_id(img_parts::webp::CHUNK_EXIF);
            webp.remove_chunks_by_id(img_parts::webp::CHUNK_XMP);
            webp.chunks().len() != before
        }
    };
    if changed {
        Ok((image.encoder().bytes(), true))
    } else {
        Ok((bytes, false))
    }
}

fn zip_has_encrypted_entry(bytes: &[u8]) -> Result<bool, zip::result::ZipError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    for index in 0..archive.len() {
        if archive.by_index_raw(index)?.encrypted() {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn rollback_object(state: &AppState, storage_key: &str) {
    match db::release_object(&state.pool, storage_key).await {
        Ok(true) => {
            if let Err(error) = state.store.delete(storage_key).await {
                tracing::error!(error = %error, key = %storage_key, "upload rollback object delete failed");
            }
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!(error = %error, key = %storage_key, "upload rollback refcount failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::{write::SimpleFileOptions, AesMode, CompressionMethod, ZipWriter};

    use super::zip_has_encrypted_entry;

    fn archive(options: SimpleFileOptions) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer.start_file("hello.txt", options).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn encrypted_zip_detector_reads_entry_flags() {
        let plain =
            archive(SimpleFileOptions::default().compression_method(CompressionMethod::Stored));
        assert!(!zip_has_encrypted_entry(&plain).unwrap());

        let encrypted = archive(
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .with_aes_encryption(AesMode::Aes256, "password"),
        );
        assert!(zip_has_encrypted_entry(&encrypted).unwrap());
    }
}
