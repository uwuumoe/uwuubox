//! Collection pages and owner-only collection mutations.

use std::collections::HashSet;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header::*, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    db::{self, Collection, CollectionItem},
    error::{AppError, JsonError},
    identity::{current_identity, current_user, require_scope, Identity},
    ids,
    routes::common::wants_html,
    state::AppState,
    views::{human_bytes, human_time, CollectionItemView, CollectionPage},
};

#[derive(Debug, Deserialize)]
struct CreateJson {
    title: Option<String>,
    description: Option<String>,
    visibility: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateForm {
    title: Option<String>,
    description: Option<String>,
    visibility: Option<String>,
}

struct CreateInput {
    title: String,
    description: String,
    visibility: String,
}

fn validate_title(value: &str) -> Result<String, AppError> {
    let title = value.trim();
    if title.is_empty() {
        return Err(AppError::bad_request("title must not be empty"));
    }
    if title.chars().count() > 120 {
        return Err(AppError::bad_request("title must be <= 120 characters"));
    }
    Ok(title.to_string())
}

fn validate_description(value: &str) -> Result<String, AppError> {
    let description = value.trim();
    if description.chars().count() > 2_000 {
        return Err(AppError::bad_request(
            "description must be <= 2000 characters",
        ));
    }
    Ok(description.to_string())
}

fn validate_visibility(value: &str) -> Result<&str, AppError> {
    match value.trim() {
        "" | "unlisted" => Ok("unlisted"),
        "public" => Ok("public"),
        _ => Err(AppError::bad_request("visibility must be public|unlisted")),
    }
}

fn parse_create(headers: &HeaderMap, body: &[u8]) -> Result<CreateInput, AppError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let (title, description, visibility) = if content_type.contains("application/json") {
        let input: CreateJson = serde_json::from_slice(body)
            .map_err(|error| AppError::bad_request(format!("bad JSON: {error}")))?;
        (input.title, input.description, input.visibility)
    } else {
        let input: CreateForm = serde_urlencoded::from_bytes(body)
            .map_err(|error| AppError::bad_request(format!("bad form: {error}")))?;
        (input.title, input.description, input.visibility)
    };
    Ok(CreateInput {
        title: validate_title(title.as_deref().unwrap_or(""))?,
        description: validate_description(description.as_deref().unwrap_or(""))?,
        visibility: validate_visibility(visibility.as_deref().unwrap_or("unlisted"))?.to_string(),
    })
}

async fn write_identity(
    state: &AppState,
    session: &Session,
    headers: &HeaderMap,
) -> Result<Identity, AppError> {
    let identity = current_identity(&state.pool, &state.env.session_secret, session, headers).await;
    require_scope(&identity, "paste")
}

async fn load_collection(state: &AppState, id: Uuid) -> Result<Collection, AppError> {
    sqlx::query_as::<_, Collection>("SELECT * FROM collections WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)
}

async fn owned_collection(
    state: &AppState,
    id: Uuid,
    owner_id: Uuid,
) -> Result<Collection, AppError> {
    let collection = load_collection(state, id).await?;
    if collection.owner_id != owner_id {
        return Err(AppError::NotFound);
    }
    Ok(collection)
}

pub async fn public_for_owner(
    pool: &sqlx::PgPool,
    owner_id: Uuid,
) -> Result<Vec<Collection>, sqlx::Error> {
    sqlx::query_as::<_, Collection>(
        "SELECT * FROM collections
         WHERE owner_id = $1 AND visibility = 'public'
         ORDER BY created_at DESC",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
}

pub async fn create(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, JsonError> {
    let identity = write_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?;
    let limits = db::effective_limits(&state.pool, &cfg, Some(&identity.user))
        .await
        .map_err(|error| AppError::from(error).json())?;
    if !limits.can_create_collections {
        return Err(
            AppError::bad_request("collection creation is not allowed for your role").json(),
        );
    }
    let input = parse_create(&headers, &body).map_err(AppError::json)?;
    if input.visibility == "public" && !limits.can_publish_public {
        return Err(AppError::forbidden("your role cannot publish public collections").json());
    }
    let collection = sqlx::query_as::<_, Collection>(
        "INSERT INTO collections (id, owner_id, title, description, visibility)
         VALUES ($1,$2,$3,$4,$5) RETURNING *",
    )
    .bind(Uuid::now_v7())
    .bind(identity.user.id)
    .bind(input.title)
    .bind(input.description)
    .bind(input.visibility)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?;
    let location = format!("/c/{}", collection.id);
    if wants_html(&headers) {
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, location)], "").into_response());
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": collection.id,
            "title": collection.title,
            "description": collection.description,
            "visibility": collection.visibility,
            "url": format!("{}{location}", state.env.base_url),
        })),
    )
        .into_response())
}

pub async fn view(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    use askama::Template;
    let id = id.parse::<Uuid>().map_err(|_| AppError::NotFound)?;
    let collection = load_collection(&state, id).await?;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let is_owner = user
        .as_ref()
        .is_some_and(|user| user.id == collection.owner_id);
    // Unlisted collections are capability URLs. A future private visibility
    // stays owner-only instead of accidentally becoming link-accessible.
    if !matches!(collection.visibility.as_str(), "public" | "unlisted") && !is_owner {
        return Err(AppError::NotFound);
    }
    let owner = db::find_user_by_id(&state.pool, &collection.owner_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let rows = sqlx::query_as::<_, CollectionItem>(
        "SELECT * FROM collection_items WHERE collection_id = $1 ORDER BY position, kind, core",
    )
    .bind(collection.id)
    .fetch_all(&state.pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        match row.kind.as_str() {
            "file" => {
                let Some(file) = db::find_file(&state.pool, row.core.trim()).await? else {
                    continue;
                };
                if db::is_expired(file.expires_at) {
                    continue;
                }
                let mut detail = format!(
                    "{} · {} · {}",
                    human_bytes(file.size_bytes),
                    file.mime_stored,
                    file.visibility
                );
                if file.burn_after_read {
                    detail.push_str(" · burn after read");
                }
                if file.access_password_hash.is_some() {
                    detail.push_str(" · password protected");
                }
                items.push(CollectionItemView {
                    kind: "file".into(),
                    core: file.id_core.trim_end().into(),
                    title: file.original_name,
                    url: format!("/f/{}{}", file.id_core.trim_end(), file.ext),
                    detail,
                });
            }
            "paste" => {
                let Some(paste) = db::find_paste(&state.pool, row.core.trim()).await? else {
                    continue;
                };
                if db::is_expired(paste.expires_at) {
                    continue;
                }
                let mut detail = format!("{} · {}", paste.format, paste.visibility);
                if paste.burn_after_read {
                    detail.push_str(" · burn after read");
                }
                if paste.access_password_hash.is_some() {
                    detail.push_str(" · password protected");
                }
                items.push(CollectionItemView {
                    kind: "paste".into(),
                    core: paste.id_core.trim_end().into(),
                    title: paste
                        .title
                        .unwrap_or_else(|| format!("paste {}", paste.id_core.trim_end())),
                    url: format!("/p/{}", paste.id_core.trim_end()),
                    detail,
                });
            }
            _ => {}
        }
    }
    let cfg = db::instance_config(&state.pool).await?;
    let canonical_url = format!("{}/c/{}", state.env.base_url, collection.id);
    let description = if collection.description.is_empty() {
        format!("a collection by {}", owner.username)
    } else {
        collection.description.chars().take(200).collect()
    };
    let page = CollectionPage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user,
        created_human: human_time(&collection.created_at),
        collection,
        items,
        owner_name: owner.username,
        is_owner,
        canonical_url: canonical_url.clone(),
        oembed_url: format!("/api/oembed?url={canonical_url}"),
        description,
    };
    let body = page
        .render()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(axum::response::Html(body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct PatchCollection {
    pub title: Option<String>,
    pub description: Option<String>,
    pub visibility: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PatchCollection>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = write_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    let collection = owned_collection(&state, id, identity.user.id)
        .await
        .map_err(AppError::json)?;
    if input.title.is_none() && input.description.is_none() && input.visibility.is_none() {
        return Err(AppError::bad_request("no collection fields supplied").json());
    }
    let title = input
        .title
        .as_deref()
        .map(validate_title)
        .transpose()
        .map_err(AppError::json)?;
    let description = input
        .description
        .as_deref()
        .map(validate_description)
        .transpose()
        .map_err(AppError::json)?;
    let visibility = input
        .visibility
        .as_deref()
        .map(validate_visibility)
        .transpose()
        .map_err(AppError::json)?;
    if visibility == Some("public") {
        let cfg = db::instance_config(&state.pool)
            .await
            .map_err(|error| AppError::from(error).json())?;
        let limits = db::effective_limits(&state.pool, &cfg, Some(&identity.user))
            .await
            .map_err(|error| AppError::from(error).json())?;
        if !limits.can_publish_public {
            return Err(AppError::forbidden("your role cannot publish public collections").json());
        }
    }
    let updated = sqlx::query_as::<_, Collection>(
        "UPDATE collections SET title = $2, description = $3, visibility = $4
         WHERE id = $1 RETURNING *",
    )
    .bind(collection.id)
    .bind(title.unwrap_or(collection.title))
    .bind(description.unwrap_or(collection.description))
    .bind(visibility.unwrap_or(&collection.visibility))
    .fetch_one(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?;
    Ok(Json(json!({
        "id": updated.id,
        "title": updated.title,
        "description": updated.description,
        "visibility": updated.visibility,
    })))
}

pub async fn delete(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = write_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    owned_collection(&state, id, identity.user.id)
        .await
        .map_err(AppError::json)?;
    let deleted: Option<Uuid> =
        sqlx::query_scalar("DELETE FROM collections WHERE id = $1 RETURNING id")
            .bind(id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|error| AppError::from(error).json())?;
    if deleted.is_none() {
        return Err(AppError::NotFound.json());
    }
    // collection_items cascade; the referenced files and pastes deliberately survive.
    Ok(Json(json!({"deleted": id})))
}

#[derive(Debug, Deserialize)]
pub struct ItemInput {
    pub kind: String,
    pub core: String,
}

async fn canonical_live_item(
    state: &AppState,
    kind: &str,
    core: &str,
) -> Result<(&'static str, String), AppError> {
    match kind.trim() {
        "file" => {
            let core = ids::strip_to_core(core);
            let file = db::find_file(&state.pool, core)
                .await?
                .ok_or(AppError::NotFound)?;
            if db::is_expired(file.expires_at) {
                return Err(AppError::NotFound);
            }
            Ok(("file", file.id_core.trim_end().to_string()))
        }
        "paste" => {
            let core = ids::strip_to_core(core);
            let paste = db::find_paste(&state.pool, core)
                .await?
                .ok_or(AppError::NotFound)?;
            if db::is_expired(paste.expires_at) {
                return Err(AppError::NotFound);
            }
            Ok(("paste", paste.id_core.trim_end().to_string()))
        }
        _ => Err(AppError::bad_request("kind must be file|paste")),
    }
}

pub async fn add_item(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ItemInput>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = write_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    let (kind, core) = canonical_live_item(&state, &input.kind, &input.core)
        .await
        .map_err(AppError::json)?;
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|error| AppError::from(error).json())?;
    let owner_id: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_id FROM collections WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| AppError::from(error).json())?;
    if owner_id != Some(identity.user.id) {
        return Err(AppError::NotFound.json());
    }
    let position: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position), -1)::bigint + 1 FROM collection_items WHERE collection_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| AppError::from(error).json())?;
    sqlx::query(
        "INSERT INTO collection_items (collection_id, kind, core, position)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (collection_id, kind, core) DO NOTHING",
    )
    .bind(id)
    .bind(kind)
    .bind(&core)
    .bind(position)
    .execute(&mut *transaction)
    .await
    .map_err(|error| AppError::from(error).json())?;
    transaction
        .commit()
        .await
        .map_err(|error| AppError::from(error).json())?;
    Ok(Json(
        json!({"collection_id": id, "kind": kind, "core": core, "position": position}),
    ))
}

pub async fn remove_item(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ItemInput>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = write_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    owned_collection(&state, id, identity.user.id)
        .await
        .map_err(AppError::json)?;
    let kind = match input.kind.trim() {
        "file" => "file",
        "paste" => "paste",
        _ => return Err(AppError::bad_request("kind must be file|paste").json()),
    };
    let core = ids::strip_to_core(&input.core);
    let deleted = sqlx::query(
        "DELETE FROM collection_items WHERE collection_id = $1 AND kind = $2 AND core = $3",
    )
    .bind(id)
    .bind(kind)
    .bind(core)
    .execute(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?
    .rows_affected();
    if deleted == 0 {
        return Err(AppError::NotFound.json());
    }
    Ok(Json(json!({"removed": {"kind": kind, "core": core}})))
}

#[derive(Debug, Deserialize)]
pub struct PositionInput {
    pub kind: String,
    pub core: String,
    pub position: i64,
}

#[derive(Debug, Deserialize)]
pub struct ReorderInput {
    pub positions: Vec<PositionInput>,
}

pub async fn reorder(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ReorderInput>,
) -> Result<impl IntoResponse, JsonError> {
    let identity = write_identity(&state, &session, &headers)
        .await
        .map_err(AppError::json)?;
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|error| AppError::from(error).json())?;
    let owner_id: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_id FROM collections WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| AppError::from(error).json())?;
    if owner_id != Some(identity.user.id) {
        return Err(AppError::NotFound.json());
    }
    let members = sqlx::query_as::<_, CollectionItem>(
        "SELECT * FROM collection_items WHERE collection_id = $1",
    )
    .bind(id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|error| AppError::from(error).json())?;
    if input.positions.len() != members.len() {
        return Err(AppError::bad_request(
            "positions must contain every collection item exactly once",
        )
        .json());
    }
    let member_keys: HashSet<(String, String)> = members
        .iter()
        .map(|item| (item.kind.clone(), item.core.trim().to_string()))
        .collect();
    let mut supplied_keys = HashSet::with_capacity(input.positions.len());
    let mut supplied_positions = HashSet::with_capacity(input.positions.len());
    for item in &input.positions {
        if item.position < 0 {
            return Err(AppError::bad_request("positions must be non-negative").json());
        }
        let kind = item.kind.trim().to_string();
        let core = ids::strip_to_core(&item.core).to_string();
        if !member_keys.contains(&(kind.clone(), core.clone()))
            || !supplied_keys.insert((kind, core))
            || !supplied_positions.insert(item.position)
        {
            return Err(AppError::bad_request(
                "positions must identify each member once with unique positions",
            )
            .json());
        }
    }
    for item in input.positions {
        sqlx::query(
            "UPDATE collection_items SET position = $4
             WHERE collection_id = $1 AND kind = $2 AND core = $3",
        )
        .bind(id)
        .bind(item.kind.trim())
        .bind(ids::strip_to_core(&item.core))
        .bind(item.position)
        .execute(&mut *transaction)
        .await
        .map_err(|error| AppError::from(error).json())?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| AppError::from(error).json())?;
    Ok(Json(json!({"collection_id": id, "reordered": true})))
}
