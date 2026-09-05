//! Public, globally time-ordered file and paste feed.

use std::cmp::Reverse;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    db,
    error::AppError,
    identity::current_user,
    state::AppState,
    views::{human_bytes, human_time, ExploreItemView, ExplorePage},
};

#[derive(Debug, Deserialize)]
pub struct ExploreQuery {
    pub page: Option<i64>,
}

pub async fn page(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Query(query): Query<ExploreQuery>,
) -> Result<Response, AppError> {
    use askama::Template;
    let page = query.page.unwrap_or(1).clamp(1, 10_000);
    let skip = page.saturating_sub(1).saturating_mul(20) as usize;
    // public_feed returns one ordered stream per kind. Fetch through the end
    // of this combined page, merge by timestamp, then apply the global offset.
    let through = page.saturating_mul(20).saturating_add(1);
    let (files, pastes) = db::public_feed(&state.pool, through, 0).await?;
    let mut items = Vec::with_capacity(files.len() + pastes.len());
    for file in files {
        items.push(ExploreItemView {
            kind: "file".into(),
            title: file.original_name,
            url: format!("/f/{}{}", file.id_core.trim_end(), file.ext),
            detail: format!("{} · {}", human_bytes(file.size_bytes), file.mime_stored),
            created_human: human_time(&file.created_at),
            created_at: file.created_at,
        });
    }
    for paste in pastes {
        items.push(ExploreItemView {
            kind: "paste".into(),
            title: paste
                .title
                .unwrap_or_else(|| format!("paste {}", paste.id_core.trim_end())),
            url: format!("/p/{}", paste.id_core.trim_end()),
            detail: paste.format,
            created_human: human_time(&paste.created_at),
            created_at: paste.created_at,
        });
    }
    items.sort_unstable_by_key(|item| Reverse(item.created_at));
    let mut items: Vec<_> = items.into_iter().skip(skip).take(21).collect();
    let has_next = items.len() > 20;
    items.truncate(20);
    let cfg = db::instance_config(&state.pool).await?;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let canonical_url = if page == 1 {
        format!("{}/explore", state.env.base_url)
    } else {
        format!("{}/explore?page={page}", state.env.base_url)
    };
    let view = ExplorePage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user,
        items,
        page,
        has_next,
        canonical_url,
    };
    let body = view
        .render()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(Html(body).into_response())
}
