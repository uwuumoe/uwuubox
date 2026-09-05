//! Admin-only object-store garbage collection and reconciliation.

use std::collections::{BTreeMap, BTreeSet};

use askama::Template;
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header::CONTENT_TYPE, HeaderMap},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;
use tower_sessions::Session;

use crate::{db, error::AppError, state::AppState, storage::Store};

use super::{admin::require_admin, common::wants_html};

const INPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Orphan {
    pub key: String,
    pub bytes: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GcReport {
    pub checked_keys: usize,
    pub orphans: Vec<Orphan>,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct GcInput {
    #[serde(default = "default_dry_run")]
    dry_run: bool,
}

fn default_dry_run() -> bool {
    true
}

#[derive(Debug, FromRow)]
struct ObjectRow {
    storage_key: String,
    size_bytes: i64,
    refcount: i32,
}

#[derive(Template)]
#[template(path = "gc.html")]
struct GcPage {
    instance_name: String,
    tagline: String,
    icon_url: String,
    user: Option<db::User>,
    report: GcReport,
    dry_run: bool,
}

async fn parse_input(headers: &HeaderMap, request: Request) -> Result<GcInput, AppError> {
    let body = to_bytes(request.into_body(), INPUT_LIMIT)
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"))
    {
        if body.is_empty() {
            return Ok(GcInput { dry_run: true });
        }
        serde_json::from_slice(&body).map_err(|error| AppError::bad_request(error.to_string()))
    } else {
        serde_urlencoded::from_bytes(&body)
            .map_err(|error| AppError::bad_request(error.to_string()))
    }
}

async fn local_inventory(
    root: &std::path::Path,
    prefix: &str,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), AppError> {
    let start = root.join(prefix);
    let mut stack = vec![(start, prefix.to_string())];
    while let Some((directory, key_prefix)) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(AppError::internal(error.to_string())),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = format!("{key_prefix}/{name}");
            let file_type = entry
                .file_type()
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if file_type.is_dir() {
                stack.push((entry.path(), key));
            } else if file_type.is_file() {
                let bytes = entry
                    .metadata()
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .len();
                inventory.insert(key, bytes);
            }
        }
    }
    Ok(())
}

async fn s3_prefix_inventory(
    store: &crate::storage::S3Store,
    prefix: &str,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), AppError> {
    let mut continuation = None;
    loop {
        let output = store
            .client
            .list_objects_v2()
            .bucket(&store.bucket)
            .prefix(format!("{prefix}/"))
            .set_continuation_token(continuation)
            .send()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        for object in output.contents() {
            if let Some(key) = object.key() {
                inventory.insert(key.to_string(), object.size().unwrap_or(0).max(0) as u64);
            }
        }
        if output.is_truncated() != Some(true) {
            break;
        }
        continuation = Some(
            output
                .next_continuation_token()
                .filter(|token| !token.is_empty())
                .ok_or_else(|| {
                    AppError::internal("truncated S3 listing had no continuation token")
                })?
                .to_string(),
        );
    }
    Ok(())
}

async fn inventory(store: &Store) -> Result<BTreeMap<String, u64>, AppError> {
    let mut inventory = BTreeMap::new();
    match store {
        Store::Local(local) => {
            local_inventory(&local.root, "files", &mut inventory).await?;
            local_inventory(&local.root, "avatars", &mut inventory).await?;
        }
        Store::S3(s3) => {
            s3_prefix_inventory(s3, "files", &mut inventory).await?;
            s3_prefix_inventory(s3, "avatars", &mut inventory).await?;
        }
    }
    Ok(inventory)
}

async fn inspect(state: &AppState) -> Result<(GcReport, BTreeMap<String, u64>), AppError> {
    let inventory = inventory(&state.store).await?;
    let objects: Vec<ObjectRow> = sqlx::query_as(
        "SELECT storage_key, size_bytes, refcount FROM objects ORDER BY storage_key",
    )
    .fetch_all(&state.pool)
    .await?;
    let avatar_keys: Vec<Option<String>> =
        sqlx::query_scalar("SELECT avatar_key FROM users WHERE avatar_key IS NOT NULL")
            .fetch_all(&state.pool)
            .await?;
    let file_keys: Vec<String> = sqlx::query_scalar("SELECT DISTINCT storage_key FROM files")
        .fetch_all(&state.pool)
        .await?;

    let objects: BTreeMap<String, ObjectRow> = objects
        .into_iter()
        .map(|object| (object.storage_key.clone(), object))
        .collect();
    let avatar_keys: BTreeSet<String> = avatar_keys.into_iter().flatten().collect();
    let file_keys: BTreeSet<String> = file_keys.into_iter().collect();
    let checked: BTreeSet<String> = inventory
        .keys()
        .chain(objects.keys())
        .chain(avatar_keys.iter())
        .chain(file_keys.iter())
        .cloned()
        .collect();

    let mut orphans = Vec::new();
    for key in &checked {
        let stored_bytes = inventory.get(key).copied();
        let object = objects.get(key);
        let finding = if let Some(object) = object {
            if object.refcount <= 0 {
                Some((
                    "zero-ref",
                    stored_bytes.unwrap_or_else(|| object.size_bytes.max(0) as u64),
                ))
            } else if stored_bytes.is_none() {
                Some(("missing-bytes", object.size_bytes.max(0) as u64))
            } else {
                None
            }
        } else if key.starts_with("files/") {
            if let Some(bytes) = stored_bytes {
                Some(("unreferenced", bytes))
            } else if file_keys.contains(key) {
                Some(("missing-bytes", 0))
            } else {
                None
            }
        } else if key.starts_with("avatars/") {
            match (avatar_keys.contains(key), stored_bytes) {
                (false, Some(bytes)) => Some(("unreferenced", bytes)),
                (true, None) => Some(("missing-bytes", 0)),
                _ => None,
            }
        } else {
            None
        };
        if let Some((reason, bytes)) = finding {
            orphans.push(Orphan {
                key: key.clone(),
                bytes,
                reason: reason.to_string(),
            });
        }
    }

    let reclaimed_bytes = orphans
        .iter()
        .filter(|orphan| orphan.reason != "missing-bytes")
        .filter(|orphan| !file_keys.contains(&orphan.key) && !avatar_keys.contains(&orphan.key))
        .filter_map(|orphan| inventory.get(&orphan.key))
        .copied()
        .fold(0u64, u64::saturating_add);
    Ok((
        GcReport {
            checked_keys: checked.len(),
            orphans,
            reclaimed_bytes,
        },
        inventory,
    ))
}

async fn reclaim(
    state: &AppState,
    report: &mut GcReport,
    inventory: &BTreeMap<String, u64>,
) -> Result<(), AppError> {
    report.reclaimed_bytes = 0;
    for orphan in &report.orphans {
        if orphan.reason == "missing-bytes" {
            continue;
        }

        let mut tx = state.pool.begin().await?;
        let refcount: Option<i32> =
            sqlx::query_scalar("SELECT refcount FROM objects WHERE storage_key = $1 FOR UPDATE")
                .bind(&orphan.key)
                .fetch_optional(&mut *tx)
                .await?;
        let referenced: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM files WHERE storage_key = $1)
                 OR EXISTS (SELECT 1 FROM users WHERE avatar_key = $1)",
        )
        .bind(&orphan.key)
        .fetch_one(&mut *tx)
        .await?;
        if referenced || refcount.is_some_and(|count| count > 0) {
            tracing::warn!(key = %orphan.key, "gc skipped object that became referenced");
            tx.rollback().await?;
            continue;
        }

        if let Some(bytes) = inventory.get(&orphan.key) {
            state.store.delete(&orphan.key).await?;
            report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(*bytes);
        }
        if refcount.is_some_and(|count| count <= 0) {
            sqlx::query("DELETE FROM objects WHERE storage_key = $1 AND refcount <= 0")
                .bind(&orphan.key)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

pub async fn run(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let actor = require_admin(&state, &session, &headers).await?;
    let input = parse_input(&headers, request).await?;
    let (mut report, inventory) = inspect(&state).await?;
    if !input.dry_run {
        reclaim(&state, &mut report, &inventory).await?;
        db::audit(
            &state.pool,
            Some(&actor.id),
            "gc.run",
            Some("storage"),
            None,
            Some(json!({
                "checked_keys": report.checked_keys,
                "orphan_count": report.orphans.len(),
                "reclaimed_bytes": report.reclaimed_bytes,
            })),
        )
        .await?;
    }

    if wants_html(&headers) {
        let cfg = db::instance_config(&state.pool).await?;
        let page = GcPage {
            instance_name: cfg.instance_name,
            tagline: cfg.tagline,
            icon_url: cfg.icon_url,
            user: Some(actor),
            report,
            dry_run: input.dry_run,
        };
        let body = page
            .render()
            .map_err(|error| AppError::internal(error.to_string()))?;
        Ok(Html(body).into_response())
    } else {
        Ok(Json(report).into_response())
    }
}
