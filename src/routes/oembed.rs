//! Public oEmbed discovery for shareable file, paste, and collection URLs.

use axum::{
    extract::{Query, State},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

use crate::{
    db,
    error::{AppError, JsonError},
    ids,
    routes::common::file_kind,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct OembedQuery {
    pub url: String,
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

async fn author_name(
    state: &AppState,
    owner_id: Option<Uuid>,
    fallback: &str,
) -> Result<String, AppError> {
    match owner_id {
        Some(id) => Ok(db::find_user_by_id(&state.pool, &id)
            .await?
            .map(|user| user.username)
            .unwrap_or_else(|| fallback.to_string())),
        None => Ok(fallback.to_string()),
    }
}

fn rich(
    title: String,
    author: String,
    provider_name: &str,
    provider_url: &str,
    preview_url: &str,
) -> Value {
    json!({
        "version": "1.0",
        "type": "rich",
        "title": title,
        "author_name": author,
        "provider_name": provider_name,
        "provider_url": provider_url,
        "html": format!(
            "<iframe src=\"{}\" width=\"640\" height=\"360\" frameborder=\"0\" allowfullscreen></iframe>",
            preview_url
        ),
        "width": 640,
        "height": 360,
    })
}

pub async fn get(
    State(state): State<AppState>,
    Query(query): Query<OembedQuery>,
) -> Result<Json<Value>, JsonError> {
    let base = Url::parse(&state.env.base_url)
        .map_err(|_| AppError::internal("invalid configured base URL").json())?;
    let requested = Url::parse(query.url.trim()).map_err(|_| AppError::NotFound.json())?;
    if !same_origin(&base, &requested) {
        return Err(AppError::NotFound.json());
    }
    let segments: Vec<_> = requested
        .path_segments()
        .ok_or(AppError::NotFound.json())?
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.len() != 2 {
        return Err(AppError::NotFound.json());
    }
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?;
    let provider_url = base.as_str().trim_end_matches('/');
    let value = match segments[0] {
        "f" => {
            let core = ids::strip_to_core(segments[1]);
            let file = db::find_file(&state.pool, core)
                .await
                .map_err(|error| AppError::from(error).json())?
                .ok_or(AppError::NotFound.json())?;
            if db::is_expired(file.expires_at)
                || !matches!(file.visibility.as_str(), "public" | "unlisted")
            {
                return Err(AppError::NotFound.json());
            }
            let author = author_name(&state, file.owner_id, &cfg.instance_name)
                .await
                .map_err(AppError::json)?;
            let preview_url = format!("{}/f/{}{}", provider_url, file.id_core.trim_end(), file.ext);
            let raw_url = format!("{}/{}{}", provider_url, file.id_core.trim_end(), file.ext);
            // Never make a crawler consume a burn-on-read object or bypass a
            // password prompt. Its preview page is deliberately redacted.
            if file.burn_after_read || file.access_password_hash.is_some() {
                rich(
                    file.original_name,
                    author,
                    &cfg.instance_name,
                    provider_url,
                    &preview_url,
                )
            } else {
                match file_kind(&file.mime_stored) {
                    "image" => json!({
                        "version": "1.0",
                        "type": "photo",
                        "title": file.original_name,
                        "author_name": author,
                        "provider_name": cfg.instance_name,
                        "provider_url": provider_url,
                        "url": raw_url,
                    }),
                    "video" => json!({
                        "version": "1.0",
                        "type": "video",
                        "title": file.original_name,
                        "author_name": author,
                        "provider_name": cfg.instance_name,
                        "provider_url": provider_url,
                        "url": raw_url,
                    }),
                    _ => rich(
                        file.original_name,
                        author,
                        &cfg.instance_name,
                        provider_url,
                        &preview_url,
                    ),
                }
            }
        }
        "p" => {
            let core = ids::strip_to_core(segments[1]);
            let paste = db::find_paste(&state.pool, core)
                .await
                .map_err(|error| AppError::from(error).json())?
                .ok_or(AppError::NotFound.json())?;
            if db::is_expired(paste.expires_at)
                || !matches!(paste.visibility.as_str(), "public" | "unlisted")
            {
                return Err(AppError::NotFound.json());
            }
            let author = author_name(&state, paste.owner_id, &cfg.instance_name)
                .await
                .map_err(AppError::json)?;
            let title = paste
                .title
                .unwrap_or_else(|| format!("paste {}", paste.id_core.trim_end()));
            let preview_url = format!("{}/p/{}", provider_url, paste.id_core.trim_end());
            rich(
                title,
                author,
                &cfg.instance_name,
                provider_url,
                &preview_url,
            )
        }
        "c" => {
            let id = segments[1]
                .parse::<Uuid>()
                .map_err(|_| AppError::NotFound.json())?;
            let collection =
                sqlx::query_as::<_, db::Collection>("SELECT * FROM collections WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(|error| AppError::from(error).json())?
                    .ok_or(AppError::NotFound.json())?;
            if !matches!(collection.visibility.as_str(), "public" | "unlisted") {
                return Err(AppError::NotFound.json());
            }
            let author = author_name(&state, Some(collection.owner_id), &cfg.instance_name)
                .await
                .map_err(AppError::json)?;
            let preview_url = format!("{}/c/{}", provider_url, collection.id);
            rich(
                collection.title,
                author,
                &cfg.instance_name,
                provider_url,
                &preview_url,
            )
        }
        _ => return Err(AppError::NotFound.json()),
    };
    Ok(Json(value))
}
