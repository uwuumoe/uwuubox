//! Public pages: upload index, paste composer, health check.

use axum::{
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Json, Response},
};
use serde_json::json;
use tower_sessions::Session;

use crate::{db, error::AppError, identity::current_user, state::AppState, views::IndexPage};

pub async fn index(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use askama::Template;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let cfg = db::instance_config(&state.pool).await?;
    let body = IndexPage::new(&cfg, user, &state.env.base_url)
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Html(body).into_response())
}

pub async fn new_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    use askama::Template;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let cfg = db::instance_config(&state.pool).await?;
    let page = crate::views::PasteNewPage::new(&cfg, user);
    let body = page
        .render()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Html(body).into_response())
}

pub async fn health() -> impl IntoResponse {
    Json(json!({"ok": true}))
}
