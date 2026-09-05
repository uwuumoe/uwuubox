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
    pub role_id: Option<Uuid>,
    pub quota_override_bytes: Option<i64>,
    pub strip_exif_default: bool,
    pub email: Option<String>,
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
    pub burn_after_read: bool,
    pub access_password_hash: Option<String>,
    pub scan_status: String,
    pub expires_at: Option<DateTime<Utc>>,
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
    pub format: String,
    pub visibility: String,
    pub burn_after_read: bool,
    pub access_password_hash: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub delete_token_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, FromRow)]
pub struct TokenInfo {
    pub id: Uuid,
    pub label: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
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

pub async fn touch_token(pool: &PgPool, hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE token_hash = $1")
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_tokens(pool: &PgPool, user_id: &Uuid) -> Result<Vec<TokenInfo>, sqlx::Error> {
    sqlx::query_as::<_, TokenInfo>(
        "SELECT id, label, scopes, expires_at, created_at, last_used_at FROM api_tokens
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
    scopes: &[String],
    expires_at: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, token_hash, label, scopes, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(user_id)
    .bind(hash)
    .bind(label)
    .bind(scopes)
    .bind(expires_at)
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

/// True when a `NULL`-able `expires_at` has passed. `None` (never-expire)
/// content is never expired.
pub fn is_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    expires_at.is_some_and(|at| at < Utc::now())
}

/// Expired rows (oldest first) for the sweeper.
pub async fn expired_files(pool: &PgPool, limit: i64) -> Result<Vec<FileRow>, sqlx::Error> {
    sqlx::query_as::<_, FileRow>(
        "SELECT * FROM files WHERE expires_at IS NOT NULL AND expires_at < now() ORDER BY expires_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn expired_pastes(pool: &PgPool, limit: i64) -> Result<Vec<PasteRow>, sqlx::Error> {
    sqlx::query_as::<_, PasteRow>(
        "SELECT * FROM pastes WHERE expires_at IS NOT NULL AND expires_at < now() ORDER BY expires_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub max_file_bytes: Option<i64>,
    pub max_paste_bytes: Option<i64>,
    pub max_avatar_bytes: Option<i64>,
    pub min_expiry_secs: Option<i64>,
    pub max_expiry_secs: Option<i64>,
    pub default_expiry_secs: Option<i64>,
    pub quota_bytes: Option<i64>,
    pub can_publish_public: bool,
    pub can_burn: bool,
    pub can_comment: bool,
    pub can_create_collections: bool,
    pub can_moderate: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct Collection {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub description: String,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct CollectionItem {
    pub kind: String,
    pub core: String,
}
#[derive(Debug, Clone, FromRow)]
pub struct CommentRow {
    pub id: i64,
    pub target_kind: String,
    pub target_core: String,
    pub author_id: Option<Uuid>,
    pub author_name: Option<String>,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct InviteCode {
    pub code: String,
    pub max_uses: Option<i32>,
    pub uses: i32,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditEntry {
    pub actor_name: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Resolved per-request caps for a user (role overrides, NULL falls back to
/// instance defaults). Anonymous callers pass `None` for the user.
#[derive(Debug, Clone)]
pub struct EffectiveLimits {
    pub max_file_bytes: i64,
    pub max_paste_bytes: i64,
    pub max_avatar_bytes: i64,
    pub min_expiry_secs: i64,
    pub max_expiry_secs: i64,
    pub default_expiry_secs: i64,
    pub quota_bytes: Option<i64>,
    pub can_publish_public: bool,
    pub can_burn: bool,
    pub can_comment: bool,
    pub can_create_collections: bool,
    pub can_moderate: bool,
}

pub async fn find_role(pool: &PgPool, id: &Uuid) -> Result<Option<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn effective_limits(
    pool: &PgPool,
    cfg: &InstanceConfig,
    user: Option<&User>,
) -> Result<EffectiveLimits, sqlx::Error> {
    let role = match user.and_then(|u| u.role_id.as_ref()) {
        Some(id) => find_role(pool, id).await?,
        None => None,
    };
    let pick = |r: Option<i64>, d: i64| r.unwrap_or(d);
    Ok(EffectiveLimits {
        max_file_bytes: pick(
            role.as_ref().and_then(|r| r.max_file_bytes),
            cfg.max_file_bytes,
        ),
        max_paste_bytes: pick(
            role.as_ref().and_then(|r| r.max_paste_bytes),
            cfg.max_paste_bytes,
        ),
        max_avatar_bytes: pick(
            role.as_ref().and_then(|r| r.max_avatar_bytes),
            cfg.max_avatar_bytes,
        ),
        min_expiry_secs: pick(
            role.as_ref().and_then(|r| r.min_expiry_secs),
            cfg.min_expiry_secs,
        ),
        max_expiry_secs: pick(
            role.as_ref().and_then(|r| r.max_expiry_secs),
            cfg.max_expiry_secs,
        ),
        default_expiry_secs: pick(
            role.as_ref().and_then(|r| r.default_expiry_secs),
            cfg.default_expiry_secs,
        ),
        quota_bytes: user
            .and_then(|u| u.quota_override_bytes)
            .or_else(|| role.as_ref().and_then(|r| r.quota_bytes)),
        can_publish_public: role.as_ref().map(|r| r.can_publish_public).unwrap_or(true),
        can_burn: role.as_ref().map(|r| r.can_burn).unwrap_or(true),
        can_comment: role.as_ref().map(|r| r.can_comment).unwrap_or(true),
        can_create_collections: role
            .as_ref()
            .map(|r| r.can_create_collections)
            .unwrap_or(true),
        can_moderate: role.as_ref().map(|r| r.can_moderate).unwrap_or(false),
    })
}

/// Logical bytes owned by a user (deduped files count once per link).
pub async fn storage_used(pool: &PgPool, user_id: &Uuid) -> Result<i64, sqlx::Error> {
    let files: Option<i64> = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM files WHERE owner_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(files.unwrap_or(0))
}

pub async fn audit(
    pool: &PgPool,
    actor: Option<&Uuid>,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    detail: Option<serde_json::Value>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_audit_log (actor_id, action, target_type, target_id, detail)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

/// Dedupe bookkeeping. Returns `(storage_key, is_new)`: when `is_new` the
/// caller must PUT the bytes, otherwise another row already owns an object
/// with this hash. Serialized by the `objects` PK: exactly one caller wins.
pub async fn acquire_object(
    pool: &PgPool,
    sha256: &[u8],
    candidate_key: &str,
    size_bytes: i64,
    mime_stored: &str,
) -> Result<(String, bool), sqlx::Error> {
    if let Some(row) = sqlx::query_as::<_, (String,)>(
        "INSERT INTO objects (sha256, storage_key, size_bytes, mime_stored)
         VALUES ($1, $2, $3, $4) ON CONFLICT (sha256) DO NOTHING RETURNING storage_key",
    )
    .bind(sha256)
    .bind(candidate_key)
    .bind(size_bytes)
    .bind(mime_stored)
    .fetch_optional(pool)
    .await?
    {
        return Ok((row.0, true));
    }
    let key: String = sqlx::query_scalar(
        "UPDATE objects SET refcount = refcount + 1 WHERE sha256 = $1 RETURNING storage_key",
    )
    .bind(sha256)
    .fetch_one(pool)
    .await?;
    Ok((key, false))
}

/// Drop one reference to an object. Returns true when the caller must now
/// delete the backing bytes (refcount hit zero and the row was removed).
pub async fn release_object(pool: &PgPool, storage_key: &str) -> Result<bool, sqlx::Error> {
    let left: Option<i32> = sqlx::query_scalar(
        "UPDATE objects SET refcount = refcount - 1 WHERE storage_key = $1 RETURNING refcount",
    )
    .bind(storage_key)
    .fetch_optional(pool)
    .await?;
    match left {
        Some(n) if n <= 0 => {
            sqlx::query("DELETE FROM objects WHERE storage_key = $1")
                .bind(storage_key)
                .execute(pool)
                .await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Newest-first global public feed for the explore page.
pub async fn public_feed(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<FileRow>, Vec<PasteRow>), sqlx::Error> {
    let files = sqlx::query_as::<_, FileRow>(
        "SELECT * FROM files WHERE visibility = 'public' AND (expires_at IS NULL OR expires_at > now())
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let pastes = sqlx::query_as::<_, PasteRow>(
        "SELECT * FROM pastes WHERE visibility = 'public' AND (expires_at IS NULL OR expires_at > now())
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok((files, pastes))
}
