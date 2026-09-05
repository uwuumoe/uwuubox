//! Flat, paginated comments for files, pastes, and collections.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Json},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    db::{self, CommentRow},
    error::{AppError, JsonError},
    identity::{current_identity, require_scope, Identity},
    ids,
    state::AppState,
};

struct Target {
    kind: &'static str,
    core: String,
    owner_id: Option<Uuid>,
}

async fn resolve_target(
    state: &AppState,
    identity: Option<&Identity>,
    kind: &str,
    supplied_core: &str,
) -> Result<Target, AppError> {
    match kind.trim() {
        "file" => {
            let core = ids::strip_to_core(supplied_core);
            let file = db::find_file(&state.pool, core)
                .await?
                .ok_or(AppError::NotFound)?;
            if file.expires_at <= Utc::now() {
                return Err(AppError::NotFound);
            }
            let owner = identity
                .zip(file.owner_id)
                .is_some_and(|(identity, owner)| identity.user.id == owner);
            if !matches!(file.visibility.as_str(), "public" | "unlisted") && !owner {
                return Err(AppError::NotFound);
            }
            Ok(Target {
                kind: "file",
                core: file.id_core.trim_end().to_string(),
                owner_id: file.owner_id,
            })
        }
        "paste" => {
            let core = ids::strip_to_core(supplied_core);
            let paste = db::find_paste(&state.pool, core)
                .await?
                .ok_or(AppError::NotFound)?;
            if paste.expires_at <= Utc::now() {
                return Err(AppError::NotFound);
            }
            let owner = identity
                .zip(paste.owner_id)
                .is_some_and(|(identity, owner)| identity.user.id == owner);
            if !matches!(paste.visibility.as_str(), "public" | "unlisted") && !owner {
                return Err(AppError::NotFound);
            }
            Ok(Target {
                kind: "paste",
                core: paste.id_core.trim_end().to_string(),
                owner_id: paste.owner_id,
            })
        }
        "collection" => {
            let id = supplied_core
                .trim()
                .parse::<Uuid>()
                .map_err(|_| AppError::NotFound)?;
            let collection =
                sqlx::query_as::<_, db::Collection>("SELECT * FROM collections WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&state.pool)
                    .await?
                    .ok_or(AppError::NotFound)?;
            let owner = identity.is_some_and(|identity| identity.user.id == collection.owner_id);
            // `unlisted` is a capability URL: presenting the UUID is enough.
            // If a private mode is added later it remains owner-only here.
            if !matches!(collection.visibility.as_str(), "public" | "unlisted") && !owner {
                return Err(AppError::NotFound);
            }
            Ok(Target {
                kind: "collection",
                core: collection.id.to_string(),
                owner_id: Some(collection.owner_id),
            })
        }
        _ => Err(AppError::bad_request(
            "target_kind must be file|paste|collection",
        )),
    }
}

async fn comment_identity(
    state: &AppState,
    session: &Session,
    headers: &HeaderMap,
) -> Result<Identity, AppError> {
    let identity = current_identity(&state.pool, &state.env.session_secret, session, headers).await;
    require_scope(&identity, "paste")
}

#[derive(Debug, Deserialize)]
pub struct CreateComment {
    pub target_kind: String,
    pub target_core: String,
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct CommentView {
    pub id: i64,
    pub author_name: String,
    pub body: String,
    pub created_at: chrono::DateTime<Utc>,
    pub can_delete: bool,
}

fn view_comment(
    comment: CommentRow,
    identity: Option<&Identity>,
    target_owner_id: Option<Uuid>,
    can_moderate: bool,
) -> CommentView {
    let can_delete = identity.is_some_and(|identity| {
        comment.author_id == Some(identity.user.id)
            || target_owner_id == Some(identity.user.id)
            || can_moderate
    });
    CommentView {
        id: comment.id,
        author_name: comment.author_name.unwrap_or_else(|| "deleted user".into()),
        body: comment.body,
        created_at: comment.created_at,
        can_delete,
    }
}

pub async fn create(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(input): Json<CreateComment>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = comment_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?;
    let limits = db::effective_limits(&state.pool, &cfg, Some(&identity.user))
        .await
        .map_err(|error| AppError::from(error).json())?;
    if !limits.can_comment {
        return Err(AppError::forbidden("commenting is not allowed for your role").json());
    }
    let body = input.body.trim();
    if body.is_empty() {
        return Err(AppError::bad_request("comment must not be empty").json());
    }
    if body.chars().count() > 2_000 {
        return Err(AppError::bad_request("comment must be <= 2000 characters").json());
    }
    let target = resolve_target(
        &state,
        Some(&identity),
        &input.target_kind,
        &input.target_core,
    )
    .await
    .map_err(AppError::json)?;
    let row = sqlx::query_as::<_, CommentRow>(
        "WITH inserted AS (
             INSERT INTO comments (target_kind, target_core, author_id, body)
             VALUES ($1,$2,$3,$4)
             RETURNING id, target_kind, target_core, author_id, body, created_at
         )
         SELECT i.id, i.target_kind, i.target_core, i.author_id,
                u.username::text AS author_name, i.body, i.created_at
         FROM inserted i LEFT JOIN users u ON u.id = i.author_id",
    )
    .bind(target.kind)
    .bind(&target.core)
    .bind(identity.user.id)
    .bind(body)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(view_comment(
            row,
            Some(&identity),
            target.owner_id,
            limits.can_moderate,
        )),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub target_kind: String,
    pub target_core: String,
    pub page: Option<i64>,
}

pub async fn list(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, JsonError> {
    let identity =
        current_identity(&state.pool, &state.env.session_secret, &session, &headers).await;
    let target = resolve_target(
        &state,
        identity.as_ref(),
        &query.target_kind,
        &query.target_core,
    )
    .await
    .map_err(AppError::json)?;
    let page = query.page.unwrap_or(1).max(1);
    let offset = page.saturating_sub(1).saturating_mul(50);
    let mut rows = sqlx::query_as::<_, CommentRow>(
        "SELECT c.id, c.target_kind, c.target_core, c.author_id,
                u.username::text AS author_name, c.body, c.created_at
         FROM comments c LEFT JOIN users u ON u.id = c.author_id
         WHERE c.target_kind = $1 AND c.target_core = $2
         ORDER BY c.created_at DESC, c.id DESC LIMIT 51 OFFSET $3",
    )
    .bind(target.kind)
    .bind(&target.core)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?;
    let has_next = rows.len() > 50;
    rows.truncate(50);
    let can_moderate = if let Some(identity) = identity.as_ref() {
        let cfg = db::instance_config(&state.pool)
            .await
            .map_err(|error| AppError::from(error).json())?;
        db::effective_limits(&state.pool, &cfg, Some(&identity.user))
            .await
            .map_err(|error| AppError::from(error).json())?
            .can_moderate
    } else {
        false
    };
    let comments: Vec<_> = rows
        .into_iter()
        .map(|comment| view_comment(comment, identity.as_ref(), target.owner_id, can_moderate))
        .collect();
    Ok(Json(json!({
        "comments": comments,
        "page": page,
        "has_next": has_next,
    })))
}

pub async fn delete(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = comment_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    let comment = sqlx::query_as::<_, CommentRow>(
        "SELECT c.id, c.target_kind, c.target_core, c.author_id,
                u.username::text AS author_name, c.body, c.created_at
         FROM comments c LEFT JOIN users u ON u.id = c.author_id WHERE c.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?
    .ok_or(AppError::NotFound.json())?;
    let target = resolve_target(
        &state,
        Some(&identity),
        &comment.target_kind,
        &comment.target_core,
    )
    .await
    .map_err(AppError::json)?;
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?;
    let limits = db::effective_limits(&state.pool, &cfg, Some(&identity.user))
        .await
        .map_err(|error| AppError::from(error).json())?;
    if comment.author_id != Some(identity.user.id)
        && target.owner_id != Some(identity.user.id)
        && !limits.can_moderate
    {
        return Err(AppError::forbidden("not allowed to delete this comment").json());
    }
    let deleted = sqlx::query("DELETE FROM comments WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?
        .rows_affected();
    if deleted == 0 {
        return Err(AppError::NotFound.json());
    }
    Ok(Json(json!({"deleted": id})))
}
