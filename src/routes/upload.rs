//! `POST /api/upload`: streamed multipart uploads, per-role caps, content
//! processing, deduplicated object storage, and delete-token issue.

use std::net::SocketAddr;

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
    let mut spooled: Option<SpooledUpload> = None;
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
                // Stream straight to a 0600 temp file: RAM stays flat no
                // matter how large the upload is (fixes OOMKilled 502s).
                let upload = spool_file_field(&mut field, stream_cap).await?;
                // Last field wins, as before; dropping the previous spool
                // deletes its temp file.
                spooled = Some(upload);
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
    let mut spooled = spooled.ok_or_else(|| AppError::bad_request("missing file field"))?;
    if spooled.size == 0 {
        return Err(AppError::bad_request("empty file"));
    }

    let strip_default = user.map(|user| user.strip_exif_default).unwrap_or(false);
    let strip_exif = parse_bool_field(strip_exif_raw.as_deref(), strip_default, "strip_exif")?;
    // EXIF stripping parses the whole image, so it stays an in-memory step:
    // only for strippable image types, and capped. Anything else skips it
    // exactly as the old no-op parse did, without loading the file.
    let mut prefix = read_prefix(&spooled.path, SNIFF_PREFIX).await?;
    let mut exif_stripped = false;
    if strip_exif && is_strippable_image(mime::sniff_mime(&prefix).as_str()) {
        if spooled.size > STRIP_MAX_BYTES {
            return Err(AppError::bad_request(
                "image is too large for metadata stripping; retry with it disabled",
            ));
        }
        let raw = tokio::fs::read(&spooled.path)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        let (stripped, changed) = strip_image_metadata(Bytes::from(raw))?;
        exif_stripped = changed;
        tokio::fs::write(&spooled.path, &stripped)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        spooled.size = stripped.len() as u64;
        prefix = stripped.slice(..stripped.len().min(SNIFF_PREFIX));
    }

    let sniffed = mime::sniff_mime(&prefix);
    if mime::is_upload_blocked(&sniffed) {
        return Err(AppError::UnsupportedMedia { mime: sniffed });
    }
    if cfg.block_encrypted_archives && sniffed == "application/zip" {
        match zip_has_encrypted_entry_path(&spooled.path).await {
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
    let lifetime = ids::clamp_expiry(
        requested,
        limits.min_expiry_secs,
        limits.default_expiry_secs,
        limits.max_expiry_secs,
        cfg.allow_never(user.is_some()),
    )
    .map_err(|_| AppError::bad_request("never expiry is not allowed here"))?;
    let expires_at = lifetime.map(|secs| Utc::now() + chrono::TimeDelta::seconds(secs));

    let scan_status = if cfg.scan_uploads {
        match scan::verdict_path(&state.env, &filename, &spooled.path, &sniffed).await {
            Verdict::Clean => "clean",
            Verdict::Skipped => "skipped",
            Verdict::Infected(reason) => return Err(AppError::Unprocessable(reason)),
        }
    } else {
        "skipped"
    };

    // Content processing is complete: this digest is the dedupe identity.
    // Hashed back off disk so RAM stays flat for multi-GB files.
    let digest = hash_spooled_file(&spooled.path).await?;

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
        i64::try_from(spooled.size).map_err(|_| AppError::internal("upload length overflow"))?;
    let (storage_key, is_new) =
        db::acquire_object(&state.pool, &digest, &candidate_key, size_bytes, &sniffed).await?;
    if is_new {
        if let Err(error) = state
            .store
            .put_file(&storage_key, &spooled.path, spooled.size, &sniffed)
            .await
        {
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
        size = spooled.size,
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
    Ok((response, spooled.size))
}

fn parse_bool_field(raw: Option<&str>, default: bool, field: &str) -> Result<bool, AppError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(AppError::bad_request(format!("{field} must be a boolean"))),
    }
}

/// Bytes of the spooled file sniffed for the MIME type.
const SNIFF_PREFIX: usize = 32 * 1024;
/// EXIF stripping parses the whole image: refuse it above this instead of
/// OOMing. Non-image uploads never reach the strip step.
const STRIP_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// An upload body spooled to a 0600 temp file. Dropping deletes the file, so
/// every early return cleans up; the success path falls out of scope too.
struct SpooledUpload {
    path: std::path::PathBuf,
    size: u64,
}

impl Drop for SpooledUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Stream one multipart file field to a temp file, enforcing `cap` mid-stream
/// so oversize bodies 413 without ever residing in RAM.
async fn spool_file_field(
    field: &mut axum::extract::multipart::Field<'_>,
    cap: i64,
) -> Result<SpooledUpload, AppError> {
    let path = std::env::temp_dir().join(format!(
        "uwuubox-up-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().as_simple()
    ));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&path)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let mut size: u64 = 0;
    let cap = u64::try_from(cap.max(0)).unwrap_or(0);
    while let Some(chunk) = field.chunk().await.map_err(|error| {
        tracing::warn!(error = ?error, "multipart field read failed");
        AppError::bad_request(format!("unreadable file field: {error}"))
    })? {
        let incoming = chunk.len() as u64;
        if incoming > cap.saturating_sub(size) {
            return Err(AppError::TooLarge { max_bytes: cap as i64 });
        }
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        size += incoming;
    }
    Ok(SpooledUpload { path, size })
}

/// First `n` bytes of a spooled file (empty when the file is empty).
async fn read_prefix(path: &std::path::Path, n: usize) -> Result<Bytes, AppError> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(AppError::internal(e.to_string())),
        }
    }
    buf.truncate(filled);
    Ok(Bytes::from(buf))
}

/// SHA-256 over a spooled file in 8 MiB reads.
async fn hash_spooled_file(path: &std::path::Path) -> Result<Vec<u8>, AppError> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    loop {
        match file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return Err(AppError::internal(e.to_string())),
        }
    }
    Ok(hasher.finalize().to_vec())
}

/// `img_parts` only understands these containers (see the `DynImage` arms in
/// [`strip_image_metadata`]); anything else skips the strip step untouched.
fn is_strippable_image(sniffed: &str) -> bool {
    matches!(sniffed, "image/jpeg" | "image/png" | "image/webp")
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

/// True when any zip entry carries the encryption bit. Reads the spooled
/// file with positional I/O on a blocking thread: only the central
/// directory is touched, never the whole archive.
async fn zip_has_encrypted_entry_path(path: &std::path::Path) -> Result<bool, AppError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<bool, String> {
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        for index in 0..archive.len() {
            if archive
                .by_index_raw(index)
                .map_err(|e| e.to_string())?
                .encrypted()
            {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await
    .map_err(|e| AppError::internal(e.to_string()))?
    .map_err(AppError::bad_request)
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

    use super::zip_has_encrypted_entry_path;

    fn archive(options: SimpleFileOptions) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer.start_file("hello.txt", options).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn spool(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "uwuubox-test-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().as_simple()
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn encrypted_zip_detector_reads_entry_flags() {
        let plain =
            archive(SimpleFileOptions::default().compression_method(CompressionMethod::Stored));
        let plain_path = spool("plain", &plain);
        assert!(!zip_has_encrypted_entry_path(&plain_path).await.unwrap());
        std::fs::remove_file(&plain_path).unwrap();

        let encrypted = archive(
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .with_aes_encryption(AesMode::Aes256, "password"),
        );
        let encrypted_path = spool("encrypted", &encrypted);
        assert!(zip_has_encrypted_entry_path(&encrypted_path).await.unwrap());
        std::fs::remove_file(&encrypted_path).unwrap();
    }
}
