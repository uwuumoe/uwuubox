//! File preview pages (`/f/:core`), raw bytes (`/:core`), delete + visibility.
//!
//! Lookup is exact-match on the core; any URL extension is ignored (the
//! canonical link always uses the stored ext).

use axum::{
    body::Body,
    extract::{Form, Path, Query, State},
    http::{header::*, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tower_sessions::Session;

use crate::{
    auth,
    db::{self, FileRow},
    error::{AppError, JsonError},
    identity::current_user,
    ids, mime,
    range::{self, RangeOutcome},
    routes::common::{check_delete_access, file_kind},
    state::AppState,
    storage::Store,
    views::{human_bytes, human_expiry, FilePreviewPage},
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
    if db::is_expired(f.expires_at) {
        return Err(AppError::NotFound);
    }
    Ok(f)
}

fn unlock_key(file: &FileRow) -> String {
    format!("uwu_unlock_{}", file.id_core.trim_end())
}

async fn is_unlocked(session: &Session, file: &FileRow) -> bool {
    if file.access_password_hash.is_none() {
        return true;
    }
    session
        .get::<bool>(&unlock_key(file))
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

fn download_headers(file: &FileRow, headers: &mut HeaderMap) -> Result<(), AppError> {
    // text/plain is only persisted when the complete upload was valid UTF-8,
    // so a ranged slice splitting a multibyte character remains safe to serve.
    let inline = mime::should_inline(&file.mime_stored, &[]);
    let content_type = if inline {
        file.mime_stored.clone()
    } else {
        "application/octet-stream".into()
    };
    let content_type: axum::http::HeaderValue = content_type
        .parse()
        .map_err(|_| AppError::internal("bad stored mime"))?;

    headers.insert(CONTENT_TYPE, content_type);
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("Content-Security-Policy", "sandbox".parse().unwrap());
    headers.insert(
        CACHE_CONTROL,
        if file.burn_after_read || file.access_password_hash.is_some() {
            "private, no-store"
        } else {
            "public, max-age=86400"
        }
        .parse()
        .unwrap(),
    );
    if !inline {
        let name = mime::sanitize_filename(&file.original_name);
        let disp: axum::http::HeaderValue = format!("attachment; filename=\"{name}\"")
            .parse()
            .map_err(|_| AppError::internal("bad filename"))?;
        headers.insert(CONTENT_DISPOSITION, disp);
    }
    Ok(())
}

fn raw_response(
    file: &FileRow,
    outcome: RangeOutcome,
    full_len: u64,
    bytes: Bytes,
) -> Result<Response, AppError> {
    let mut response = range::response(outcome, full_len, bytes);
    download_headers(file, response.headers_mut())?;
    Ok(response)
}

fn raw_response_stream(
    file: &FileRow,
    outcome: RangeOutcome,
    full_len: u64,
    content_len: u64,
    body: Body,
) -> Result<Response, AppError> {
    let mut response = range::response_stream(outcome, full_len, content_len, body);
    download_headers(file, response.headers_mut())?;
    Ok(response)
}

/// Collect a storage stream (burn-after-read and other all-or-nothing paths).
/// Mid-stream storage failures become 500s, as before with buffered reads.
async fn collect_stream(
    mut stream: crate::storage::ObjectDataStream,
) -> Result<Vec<u8>, AppError> {
    use tokio_stream::StreamExt;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(AppError::from)?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Store thumbnail JPEG bytes as a deduped object; `None` on any failure
/// (thumbnails are best-effort, never fatal).
pub async fn store_thumbnail(state: &AppState, core: &str, jpeg: Vec<u8>) -> Option<String> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&jpeg).to_vec();
    let size = i64::try_from(jpeg.len()).ok()?;
    let candidate = format!("thumbs/{core}.jpg");
    let (key, is_new) =
        db::acquire_object(&state.pool, &digest, &candidate, size, "image/jpeg")
            .await
            .map_err(|error| {
                tracing::warn!(%core, error = %error, "thumbnail object acquire failed");
                error
            })
            .ok()?;
    if is_new {
        if let Err(error) = state.store.put(&key, Bytes::from(jpeg), "image/jpeg").await {
            tracing::warn!(%core, error = %error, "thumbnail store put failed");
            rollback_thumbnail(state, &key).await;
            return None;
        }
    }
    Some(key)
}

async fn rollback_thumbnail(state: &AppState, key: &str) {
    match db::release_object(&state.pool, key).await {
        Ok(true) => {
            if let Err(error) = state.store.delete(key).await {
                tracing::error!(error = %error, key = %key, "thumbnail rollback delete failed");
            }
        }
        Ok(false) => {}
        Err(error) => tracing::error!(error = %error, key = %key, "thumbnail rollback failed"),
    }
}

/// Backfill a missing thumbnail for an old video row: stream the stored
/// bytes to a temp file (never RAM), extract a frame, persist the object,
/// and link the row. Retried on the next crawler hit when anything fails.
pub async fn ensure_thumbnail(state: &AppState, file: &FileRow) -> Option<String> {
    if let Some(key) = file.thumb_key.clone() {
        return Some(key);
    }
    if !crate::thumb::thumbnailed_mime(&file.mime_stored)
        || file.burn_after_read
        || file.access_password_hash.is_some()
    {
        return None;
    }
    let core = file.id_core.trim_end().to_string();
    let size = u64::try_from(file.size_bytes).ok()?;
    let mut stream = state.store.get_stream(&file.storage_key, size).await.ok()?;
    let path = std::env::temp_dir().join(format!(
        "uwuubox-thumb-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().as_simple()
    ));
    let fetch = async {
        use tokio::io::AsyncWriteExt;
        use tokio_stream::StreamExt;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut out = options.open(&path).await?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| std::io::Error::other(error.to_string()))?;
            out.write_all(&chunk).await?;
        }
        out.flush().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    struct Sweep(std::path::PathBuf);
    impl Drop for Sweep {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _sweep = Sweep(path.clone());
    if let Err(error) = fetch {
        tracing::warn!(%core, error = %error, "thumbnail backfill fetch failed");
        return None;
    }
    let jpeg = crate::thumb::generate_video_thumb(&path, "ffmpeg")
        .await
        .map_err(|error| tracing::warn!(%core, error = %error, "thumbnail backfill generate failed"))
        .ok()?;
    let key = store_thumbnail(state, &core, jpeg).await?;
    let linked = sqlx::query("UPDATE files SET thumb_key = $1 WHERE id_core = $2 AND thumb_key IS NULL")
        .bind(&key)
        .bind(&file.id_core)
        .execute(&state.pool)
        .await
        .map_err(|error| {
            tracing::warn!(%core, error = %error, "thumbnail backfill link failed");
        })
        .ok()?;
    if linked.rows_affected() == 0 {
        // Lost the race with another backfill: drop our extra reference and
        // use the winner's key.
        rollback_thumbnail(state, &key).await;
        return db::find_file(&state.pool, &file.id_core)
            .await
            .ok()
            .flatten()
            .and_then(|row| row.thumb_key);
    }
    Some(key)
}
pub async fn thumb(
    State(state): State<AppState>,
    Path(segment): Path<String>,
) -> Result<Response, AppError> {
    let core = ids::strip_to_core(&segment);
    if core.is_empty() || ids::is_reserved(core) {
        return Err(AppError::NotFound);
    }
    let file = db::find_file(&state.pool, core).await?.ok_or(AppError::NotFound)?;
    if db::is_expired(file.expires_at)
        || file.burn_after_read
        || file.access_password_hash.is_some()
    {
        return Err(AppError::NotFound);
    }
    let key = file.thumb_key.as_deref().ok_or(AppError::NotFound)?;
    let bytes = state.store.get(key).await?;
    let mut response = range::response(range::RangeOutcome::Full, bytes.len() as u64, bytes)
        .into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, "image/jpeg".parse().unwrap());
    headers.insert(CACHE_CONTROL, "public, max-age=31536000, immutable".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    Ok(response)
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
    let unlocked = is_unlocked(&session, &file).await;
    let protected_and_locked = file.access_password_hash.is_some() && !unlocked;
    let kind = file_kind(&file.mime_stored);
    let crawler = crate::thumb::embed_crawler(
        headers.get(USER_AGENT).and_then(|value| value.to_str().ok()),
    );
    let thumbnailed = crate::thumb::thumbnailed_mime(&file.mime_stored)
        && !file.burn_after_read
        && file.access_password_hash.is_none();
    // Crawlers download the whole og:video before embedding; above the
    // ceiling that always times out, so point them at the thumbnail card.
    // Missing thumbs for old rows backfill in the background: this response
    // stays fast, the crawler's next fetch picks the card up.
    let large_video =
        thumbnailed && file.size_bytes > crate::thumb::EMBED_VIDEO_MAX_BYTES;
    if crawler && large_video && file.thumb_key.is_none() {
        let worker = state.clone();
        let row = file.clone();
        tokio::spawn(async move {
            ensure_thumbnail(&worker, &row).await;
        });
    }
    let text_snippet = if !file.burn_after_read
        && !protected_and_locked
        && kind == "text"
        && file.size_bytes <= TEXT_PREVIEW_LIMIT
    {
        match state.store.get(&file.storage_key).await {
            Ok(b) => Some(String::from_utf8_lossy(&b).chars().take(20_000).collect()),
            Err(_) => None,
        }
    } else {
        None
    };
    let raw_url = if protected_and_locked {
        String::new()
    } else {
        format!(
            "{}/{}{}",
            state.env.base_url,
            file.id_core.trim_end(),
            file.ext
        )
    };
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
        expires_human: human_expiry(&file.expires_at),
        sha256_hex: hex::encode(&file.sha256),
        owner_name,
        is_owner,
        kind,
        text_snippet,
        raw_url: raw_url.clone(),
        preview_url: preview_url.clone(),
        oembed_url: format!("{}/api/oembed?url={preview_url}", state.env.base_url),
        thumb_url: if file.burn_after_read || file.access_password_hash.is_some() {
            None
        } else {
            file.thumb_key.as_ref().map(|_| {
                format!("{}/thumbs/{}", state.env.base_url, file.id_core.trim_end())
            })
        },
        og_video_url: if crawler && large_video {
            None
        } else {
            Some(raw_url.clone())
        },
        file,
    };
    page.render()
        .map_err(|e| AppError::internal(e.to_string()))
        .map(axum::response::Html)
}

#[derive(Default, Deserialize)]
pub struct RawQuery {
    pub password: Option<String>,
}

pub async fn raw(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Query(query): Query<RawQuery>,
    Path(segment): Path<String>,
) -> Result<Response, AppError> {
    let file = load_live_file(&state, &segment).await?;
    if let Some(hash) = file.access_password_hash.as_deref() {
        let session_unlocked = is_unlocked(&session, &file).await;
        let query_unlocked = query
            .password
            .as_deref()
            .is_some_and(|password| auth::verify_password(hash, password));
        if !session_unlocked && !query_unlocked {
            return Err(AppError::Unauthorized);
        }
    }

    let range_header = match headers.get(RANGE) {
        Some(value) => Some(
            value
                .to_str()
                .map_err(|_| AppError::bad_request("invalid Range header"))?,
        ),
        None => None,
    };
    let full_len = u64::try_from(file.size_bytes)
        .map_err(|_| AppError::internal("negative stored file size"))?;
    let outcome = range::parse(range_header, full_len);
    if outcome == RangeOutcome::Invalid {
        return Err(AppError::bad_request("invalid Range header"));
    }
    if outcome == RangeOutcome::Unsatisfiable {
        return raw_response(&file, outcome, full_len, Bytes::new());
    }

    if file.burn_after_read {
        // Collect first so a transient storage failure does not consume the
        // one successful read. The following DELETE is the atomic winner.
        // Same RAM as before; burn files are not the streaming target.
        let all = collect_stream(
            state
                .store
                .get_stream(&file.storage_key, full_len)
                .await?,
        )
        .await?;
        if all.len() as u64 != full_len {
            return Err(AppError::internal("stored object size mismatch"));
        }
        if !remove_file(&state, &file).await? {
            return Err(AppError::NotFound);
        }
        let body = match outcome {
            RangeOutcome::Full => Bytes::from(all),
            RangeOutcome::Satisfiable { start, end } => {
                let start = usize::try_from(start)
                    .map_err(|_| AppError::internal("range offset is too large"))?;
                let end = usize::try_from(end + 1)
                    .map_err(|_| AppError::internal("range offset is too large"))?;
                Bytes::from(all).slice(start..end)
            }
            RangeOutcome::Invalid | RangeOutcome::Unsatisfiable => unreachable!(),
        };
        return raw_response(&file, outcome, full_len, body);
    }

    let (content_len, body) = match outcome {
        RangeOutcome::Full => {
            let stream = state
                .store
                .get_stream(&file.storage_key, full_len)
                .await?;
            (full_len, Body::from_stream(stream))
        }
        RangeOutcome::Satisfiable { start, end } => {
            let len = end - start + 1;
            let stream = state
                .store
                .get_range_stream(&file.storage_key, start, len)
                .await?;
            (len, Body::from_stream(stream))
        }
        RangeOutcome::Invalid | RangeOutcome::Unsatisfiable => unreachable!(),
    };
    raw_response_stream(&file, outcome, full_len, content_len, body)
}

#[derive(Deserialize)]
pub struct UnlockBody {
    pub password: String,
}

pub async fn unlock(
    State(state): State<AppState>,
    session: Session,
    Path(segment): Path<String>,
    Form(body): Form<UnlockBody>,
) -> Result<Response, AppError> {
    let file = load_live_file(&state, &segment).await?;
    if let Some(hash) = file.access_password_hash.as_deref() {
        if !auth::verify_password(hash, &body.password) {
            return Err(AppError::Unauthorized);
        }
        let key = unlock_key(&file);
        session
            .insert(&key, true)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    let location = format!("/f/{}{}", file.id_core.trim_end(), file.ext);
    Ok((StatusCode::SEE_OTHER, [(LOCATION, location)], "").into_response())
}

#[derive(Deserialize)]
pub struct DeleteBody {
    pub delete_token: Option<String>,
}

pub trait FileRemovalContext {
    fn pool(&self) -> &PgPool;
    fn store(&self) -> &Store;
}

impl FileRemovalContext for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn store(&self) -> &Store {
        &self.store
    }
}

impl<'a> FileRemovalContext for (&'a PgPool, &'a Store) {
    fn pool(&self) -> &PgPool {
        self.0
    }

    fn store(&self) -> &Store {
        self.1
    }
}

/// Atomically remove one file row and release its shared backing object.
/// `false` means another request already removed the row.
pub async fn remove_file<C: FileRemovalContext + ?Sized>(
    context: &C,
    row: &FileRow,
) -> Result<bool, AppError> {
    let removed: Option<(String, Option<String>)> =
        sqlx::query_as("DELETE FROM files WHERE id_core = $1 RETURNING storage_key, thumb_key")
            .bind(&row.id_core)
            .fetch_optional(context.pool())
            .await?;
    let Some((storage_key, thumb_key)) = removed else {
        return Ok(false);
    };
    if db::release_object(context.pool(), &storage_key).await? {
        context.store().delete(&storage_key).await?;
    }
    if let Some(thumb_key) = thumb_key {
        if db::release_object(context.pool(), &thumb_key).await? {
            context.store().delete(&thumb_key).await?;
        }
    }
    Ok(true)
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
