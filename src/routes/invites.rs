//! Invite-code administration and atomic invite registration.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    db::{self, InviteCode, User},
    error::AppError,
    state::AppState,
};

pub async fn list(pool: &PgPool) -> Result<Vec<InviteCode>, sqlx::Error> {
    sqlx::query_as::<_, InviteCode>(
        "SELECT * FROM invite_codes ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await
}

pub async fn create(
    pool: &PgPool,
    code: &str,
    created_by: &Uuid,
    max_uses: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<InviteCode, sqlx::Error> {
    sqlx::query_as::<_, InviteCode>(
        "INSERT INTO invite_codes (code, created_by, max_uses, expires_at)
         VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(code)
    .bind(created_by)
    .bind(max_uses)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn revoke(pool: &PgPool, code: &str) -> Result<Option<InviteCode>, sqlx::Error> {
    sqlx::query_as::<_, InviteCode>(
        "UPDATE invite_codes SET expires_at = now() WHERE code = $1 RETURNING *",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Error)]
pub enum InviteRegistrationError {
    #[error("invite code is invalid, expired, or fully used")]
    Invalid,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Atomically consume one use, create the user, and record the redemption.
/// The conditional UPDATE is the concurrency gate: no preflight count can race.
pub async fn create_user(
    pool: &PgPool,
    id: &Uuid,
    username: &str,
    password_hash: Option<&str>,
    email: Option<&str>,
    is_admin: bool,
    code: &str,
) -> Result<User, InviteRegistrationError> {
    let mut tx = pool.begin().await?;
    let redeemed = redeem(&mut tx, code).await?;
    if !redeemed {
        return Err(InviteRegistrationError::Invalid);
    }
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, password_hash, email, is_admin)
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(id)
    .bind(username)
    .bind(password_hash)
    .bind(email)
    .bind(is_admin)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO invite_redemptions (code, user_id) VALUES ($1, $2)")
        .bind(code)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(user)
}

async fn redeem(
    tx: &mut Transaction<'_, Postgres>,
    code: &str,
) -> Result<bool, sqlx::Error> {
    let redeemed: Option<String> = sqlx::query_scalar(
        "UPDATE invite_codes SET uses=uses+1
         WHERE code=$1
           AND (max_uses IS NULL OR uses<max_uses)
           AND (expires_at IS NULL OR expires_at>now())
         RETURNING code",
    )
    .bind(code)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(redeemed.is_some())
}

fn random_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    let suffix: String = (0..12)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect();
    format!("uwu-inv-{suffix}")
}

#[derive(Debug, Deserialize)]
pub struct CreateInviteForm {
    max_uses: Option<String>,
    expires_at: Option<String>,
}

fn parse_optional_max_uses(value: Option<String>) -> Result<Option<i32>, AppError> {
    let value = value.unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed: i32 = value
        .parse()
        .map_err(|_| AppError::bad_request("max_uses must be a number"))?;
    if parsed < 1 {
        return Err(AppError::bad_request("max_uses must be at least 1"));
    }
    Ok(Some(parsed))
}

fn parse_optional_expiry(value: Option<String>) -> Result<Option<DateTime<Utc>>, AppError> {
    let value = value.unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if let Ok(value) = DateTime::parse_from_rfc3339(value) {
        return Ok(Some(value.with_timezone(&Utc)));
    }
    NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M")
        .map(|value| Some(value.and_utc()))
        .map_err(|_| AppError::bad_request("expires_at must be a valid date and time"))
}

pub async fn create_invite(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<CreateInviteForm>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    let max_uses = parse_optional_max_uses(form.max_uses)?;
    let expires_at = parse_optional_expiry(form.expires_at)?;
    let code = random_code();
    let invite = create(&state.pool, &code, &actor.id, max_uses, expires_at).await?;
    db::audit(
        &state.pool,
        Some(&actor.id),
        "invite.create",
        Some("invite"),
        Some(&invite.code),
        Some(json!({"max_uses": invite.max_uses, "expires_at": invite.expires_at})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

pub async fn revoke_invite(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    let invite = revoke(&state.pool, &code).await?.ok_or(AppError::NotFound)?;
    db::audit(
        &state.pool,
        Some(&actor.id),
        "invite.revoke",
        Some("invite"),
        Some(&invite.code),
        None,
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}
