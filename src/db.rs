//! Postgres access: pool, row models, queries. Runtime `query_*` only —
//! no compile-time checked macros, so builds never need a live DB.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use uuid::Uuid;

use crate::config::InstanceConfig;

pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(10).connect(url).await
}

pub async fn instance_config(pool: &PgPool) -> Result<InstanceConfig, sqlx::Error> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM instance_config")
        .fetch_all(pool)
        .await?;
    Ok(InstanceConfig::from_map(
        &rows.into_iter().collect::<HashMap<_, _>>(),
    ))
}

pub async fn set_instance_config(pool: &PgPool, cfg: &InstanceConfig) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for (k, v) in cfg.as_pairs() {
        sqlx::query(
            "INSERT INTO instance_config (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(k)
        .bind(v)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_key: Option<String>,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct FileRow {
    pub id_core: String,
    pub ext: String,
    pub owner_id: Option<Uuid>,
    pub original_name: String,
    pub size_bytes: i64,
    pub mime_stored: String,
    pub sha256: Vec<u8>,
    pub storage_key: String,
    pub visibility: String,
    pub expires_at: DateTime<Utc>,
    pub delete_token_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PasteRow {
    pub id_core: String,
    pub owner_id: Option<Uuid>,
    pub title: Option<String>,
    pub body: String,
    pub language: Option<String>,
    pub visibility: String,
    pub expires_at: DateTime<Utc>,
    pub delete_token_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct TokenInfo {
    pub id: Uuid,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub async fn user_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
}

pub async fn find_user_by_id(pool: &PgPool, id: &Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_user_by_name(pool: &PgPool, name: &str) -> Result<Option<User>, sqlx::Error> {
    // `username` is citext: comparison is case-insensitive, URLs stay stable.
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
}

pub async fn username_taken(pool: &PgPool, name: &str) -> Result<bool, sqlx::Error> {
    Ok(find_user_by_name(pool, name).await?.is_some())
}

pub async fn insert_user(
    pool: &PgPool,
    id: &Uuid,
    username: &str,
    password_hash: Option<&str>,
    is_admin: bool,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, password_hash, is_admin)
         VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(id)
    .bind(username)
    .bind(password_hash)
    .bind(is_admin)
    .fetch_one(pool)
    .await
}

pub async fn list_users(pool: &PgPool) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at LIMIT 200")
        .fetch_all(pool)
        .await
}

pub async fn set_admin(pool: &PgPool, id: &Uuid, admin: bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET is_admin = $1 WHERE id = $2")
        .bind(admin)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_profile(
    pool: &PgPool,
    id: &Uuid,
    display_name: Option<&str>,
    bio: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET display_name = $1, bio = $2 WHERE id = $3")
        .bind(display_name)
        .bind(bio)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_avatar_key(
    pool: &PgPool,
    id: &Uuid,
    key: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET avatar_key = $1 WHERE id = $2")
        .bind(key)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn find_user_by_token(pool: &PgPool, hash: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT u.* FROM users u JOIN api_tokens t ON t.user_id = u.id WHERE t.token_hash = $1",
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
}

pub async fn touch_token(pool: &PgPool, hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE token_hash = $1")
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_tokens(pool: &PgPool, user_id: &Uuid) -> Result<Vec<TokenInfo>, sqlx::Error> {
    sqlx::query_as::<_, TokenInfo>(
        "SELECT id, label, created_at, last_used_at FROM api_tokens
         WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn insert_token(
    pool: &PgPool,
    id: &Uuid,
    user_id: &Uuid,
    hash: &str,
    label: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO api_tokens (id, user_id, token_hash, label) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(user_id)
        .bind(hash)
        .bind(label)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_token(pool: &PgPool, id: &Uuid, user_id: &Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM api_tokens WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn link_oidc(
    pool: &PgPool,
    issuer: &str,
    sub: &str,
    user_id: &Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oidc_identities (issuer, sub, user_id) VALUES ($1, $2, $3)
         ON CONFLICT (issuer, sub) DO UPDATE SET user_id = EXCLUDED.user_id",
    )
    .bind(issuer)
    .bind(sub)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find_oidc_user(
    pool: &PgPool,
    issuer: &str,
    sub: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT u.* FROM users u JOIN oidc_identities o ON o.user_id = u.id
         WHERE o.issuer = $1 AND o.sub = $2",
    )
    .bind(issuer)
    .bind(sub)
    .fetch_optional(pool)
    .await
}

pub async fn oidc_linked(pool: &PgPool, user_id: &Uuid) -> Result<bool, sqlx::Error> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_identities WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(n > 0)
}

pub async fn find_file(pool: &PgPool, core: &str) -> Result<Option<FileRow>, sqlx::Error> {
    sqlx::query_as::<_, FileRow>("SELECT * FROM files WHERE id_core = $1")
        .bind(core)
        .fetch_optional(pool)
        .await
}

pub async fn find_paste(pool: &PgPool, core: &str) -> Result<Option<PasteRow>, sqlx::Error> {
    sqlx::query_as::<_, PasteRow>("SELECT * FROM pastes WHERE id_core = $1")
        .bind(core)
        .fetch_optional(pool)
        .await
}

pub async fn public_items(
    pool: &PgPool,
    user_id: &Uuid,
    limit: i64,
    offset: i64,
) -> Result<(Vec<FileRow>, Vec<PasteRow>), sqlx::Error> {
    let files = sqlx::query_as::<_, FileRow>(
        "SELECT * FROM files WHERE owner_id = $1 AND visibility = 'public'
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let pastes = sqlx::query_as::<_, PasteRow>(
        "SELECT * FROM pastes WHERE owner_id = $1 AND visibility = 'public'
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok((files, pastes))
}

pub async fn own_items(
    pool: &PgPool,
    user_id: &Uuid,
) -> Result<(Vec<FileRow>, Vec<PasteRow>), sqlx::Error> {
    let files = sqlx::query_as::<_, FileRow>(
        "SELECT * FROM files WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let pastes = sqlx::query_as::<_, PasteRow>(
        "SELECT * FROM pastes WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok((files, pastes))
}

/// Expired rows (oldest first) for the sweeper.
pub async fn expired_files(pool: &PgPool, limit: i64) -> Result<Vec<FileRow>, sqlx::Error> {
    sqlx::query_as::<_, FileRow>(
        "SELECT * FROM files WHERE expires_at < now() ORDER BY expires_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn expired_pastes(pool: &PgPool, limit: i64) -> Result<Vec<PasteRow>, sqlx::Error> {
    sqlx::query_as::<_, PasteRow>(
        "SELECT * FROM pastes WHERE expires_at < now() ORDER BY expires_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}
