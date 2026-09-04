//! Request identity: session cookie first, `Authorization: Bearer uwu_…`
//! API token second. Tokens carry `last_used_at` bookkeeping.

use axum::http::HeaderMap;
use sqlx::PgPool;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{api_token_hash, is_api_token_format, SESSION_USER_ID},
    db::{self, User},
};

pub async fn current_user(
    pool: &PgPool,
    secret: &[u8; 32],
    session: &Session,
    headers: &HeaderMap,
) -> Option<User> {
    if let Ok(Some(uid)) = session.get::<String>(SESSION_USER_ID).await {
        if let Ok(id) = uid.parse::<Uuid>() {
            match db::find_user_by_id(pool, &id).await {
                Ok(Some(u)) => return Some(u),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "identity: session user lookup failed"),
            }
        }
    }
    if let Some(token) = bearer(headers) {
        if is_api_token_format(token) {
            let hash = api_token_hash(secret, token);
            match db::find_user_by_token(pool, &hash).await {
                Ok(Some(u)) => {
                    if let Err(e) = db::touch_token(pool, &hash).await {
                        tracing::warn!(error = %e, "identity: token touch failed");
                    }
                    return Some(u);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "identity: token lookup failed"),
            }
        }
    }
    None
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}
