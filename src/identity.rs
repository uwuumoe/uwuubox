//! Request identity: session cookie first, `Authorization: Bearer uwu_…`
//! API token second. Tokens carry scopes and `last_used_at` bookkeeping.
//!
//! API scope map:
//! - `upload` => `POST /api/upload`
//! - `paste` => `POST /api/pastes` plus collection/comment writes
//! - `delete` => all `DELETE`/`PATCH` operations plus visibility toggles
//! - `read` => `/api/zip` plus collection reads through the API

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{api_token_hash, is_api_token_format, SESSION_USER_ID},
    db::{self, User},
    error::AppError,
};

pub const API_SCOPES: [&str; 4] = ["upload", "paste", "delete", "read"];

#[derive(Debug, Clone)]
pub struct Identity {
    pub user: User,
    pub scopes: Vec<String>,
}

#[derive(FromRow)]
struct TokenIdentityRow {
    id: Uuid,
    username: String,
    display_name: Option<String>,
    bio: Option<String>,
    avatar_key: Option<String>,
    password_hash: Option<String>,
    is_admin: bool,
    role_id: Option<Uuid>,
    quota_override_bytes: Option<i64>,
    strip_exif_default: bool,
    email: Option<String>,
    created_at: DateTime<Utc>,
    scopes: Vec<String>,
}

impl TokenIdentityRow {
    fn into_identity(self) -> Identity {
        Identity {
            user: User {
                id: self.id,
                username: self.username,
                display_name: self.display_name,
                bio: self.bio,
                avatar_key: self.avatar_key,
                password_hash: self.password_hash,
                is_admin: self.is_admin,
                role_id: self.role_id,
                quota_override_bytes: self.quota_override_bytes,
                strip_exif_default: self.strip_exif_default,
                email: self.email,
                created_at: self.created_at,
            },
            scopes: self.scopes,
        }
    }
}

async fn session_user(pool: &PgPool, session: &Session) -> Option<User> {
    let uid = session
        .get::<String>(SESSION_USER_ID)
        .await
        .ok()
        .flatten()?;
    let id = uid.parse::<Uuid>().ok()?;
    match db::find_user_by_id(pool, &id).await {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "identity: session user lookup failed");
            None
        }
    }
}

async fn bearer_identity(
    pool: &PgPool,
    secret: &[u8; 32],
    headers: &HeaderMap,
) -> Option<Identity> {
    let token = bearer(headers)?;
    if !is_api_token_format(token) {
        return None;
    }
    let hash = api_token_hash(secret, token);
    let row = sqlx::query_as::<_, TokenIdentityRow>(
        "SELECT u.id, u.username, u.display_name, u.bio, u.avatar_key,
                u.password_hash, u.is_admin, u.role_id, u.quota_override_bytes,
                u.strip_exif_default, u.email, u.created_at, t.scopes
         FROM users u
         JOIN api_tokens t ON t.user_id = u.id
         WHERE t.token_hash = $1
           AND (t.expires_at IS NULL OR t.expires_at > now())",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await;
    match row {
        Ok(Some(row)) => {
            if let Err(error) = db::touch_token(pool, &hash).await {
                tracing::warn!(%error, "identity: token touch failed");
            }
            Some(row.into_identity())
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "identity: token lookup failed");
            None
        }
    }
}

pub async fn current_identity(
    pool: &PgPool,
    secret: &[u8; 32],
    session: &Session,
    headers: &HeaderMap,
) -> Option<Identity> {
    if let Some(user) = session_user(pool, session).await {
        return Some(Identity {
            user,
            scopes: API_SCOPES
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
        });
    }
    bearer_identity(pool, secret, headers).await
}

pub async fn current_user(
    pool: &PgPool,
    secret: &[u8; 32],
    session: &Session,
    headers: &HeaderMap,
) -> Option<User> {
    if let Some(user) = session_user(pool, session).await {
        return Some(user);
    }
    bearer_identity(pool, secret, headers)
        .await
        .map(|identity| identity.user)
}

pub fn require_scope(identity: &Option<Identity>, scope: &str) -> Result<Identity, AppError> {
    let identity = identity.clone().ok_or(AppError::Unauthorized)?;
    if !identity.scopes.iter().any(|candidate| candidate == scope) {
        return Err(AppError::forbidden("token lacks required scope"));
    }
    Ok(identity)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}
