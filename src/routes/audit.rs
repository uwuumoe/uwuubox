//! Paginated admin audit-log viewer.

use askama::Template;
use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    db::{self, AuditEntry},
    error::AppError,
    state::AppState,
};

use super::admin::require_admin;

const PAGE_SIZE: i64 = 100;

#[derive(Debug, Deserialize)]
struct AuditQuery {
    page: Option<i64>,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    instance_name: String,
    tagline: String,
    icon_url: String,
    user: Option<db::User>,
    entries: Vec<AuditEntry>,
    page: i64,
    previous_page: i64,
    next_page: i64,
    has_previous: bool,
    has_next: bool,
}

pub async fn list(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, AppError> {
    let admin = require_admin(&state, &session, &headers).await?;
    let query = raw_query
        .as_deref()
        .map(serde_urlencoded::from_str::<AuditQuery>)
        .transpose()
        .map_err(|error| AppError::bad_request(error.to_string()))?
        .unwrap_or(AuditQuery { page: None });
    let page = query.page.unwrap_or(1).max(1);
    let offset = page.saturating_sub(1).saturating_mul(PAGE_SIZE);
    let mut entries = sqlx::query_as::<_, AuditEntry>(
        "SELECT a.id, a.actor_id, u.username AS actor_name, a.action,
                a.target_type, a.target_id, a.detail, a.created_at
         FROM admin_audit_log a
         LEFT JOIN users u ON u.id = a.actor_id
         ORDER BY a.created_at DESC, a.id DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(PAGE_SIZE + 1)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;
    let has_next = entries.len() > PAGE_SIZE as usize;
    entries.truncate(PAGE_SIZE as usize);

    let cfg = db::instance_config(&state.pool).await?;
    let page_view = AuditPage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user: Some(admin),
        entries,
        page,
        previous_page: page.saturating_sub(1).max(1),
        next_page: page.saturating_add(1),
        has_previous: page > 1,
        has_next,
    };
    let body = page_view
        .render()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(Html(body).into_response())
}
