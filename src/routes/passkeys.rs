//! WebAuthn passkey registration, authentication, listing, and removal.

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use crate::{
    auth::SESSION_USER_ID,
    db::{self, User},
    error::{AppError, JsonError},
    state::AppState,
};

const REGISTRATION_STATE: &str = "passkey_registration";
const REGISTRATION_USER: &str = "passkey_registration_user";
const REGISTRATION_NAME: &str = "passkey_registration_name";
const AUTHENTICATION_STATE: &str = "passkey_authentication";
const AUTHENTICATION_USER: &str = "passkey_authentication_user";

#[derive(Debug, Clone, FromRow)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct StoredCredential {
    cred_id: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(FromRow)]
struct CounterRow {
    id: Uuid,
    public_key: Vec<u8>,
    counter: i64,
}

pub async fn list_for_user(
    pool: &PgPool,
    user_id: &Uuid,
) -> Result<Vec<PasskeyInfo>, sqlx::Error> {
    sqlx::query_as::<_, PasskeyInfo>(
        "SELECT id, name, created_at FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

async fn session_user(state: &AppState, session: &Session) -> Result<User, AppError> {
    let id = session
        .get::<String>(SESSION_USER_ID)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .and_then(|id| id.parse::<Uuid>().ok())
        .ok_or(AppError::Unauthorized)?;
    db::find_user_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::Unauthorized)
}

fn webauthn(state: &AppState) -> Result<&webauthn_rs::Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::ServiceUnavailable("passkeys are unavailable".into()))
}

fn ceremony_error(error: impl std::fmt::Display) -> AppError {
    tracing::warn!(error = %error, "passkey ceremony failed");
    AppError::bad_request("passkey ceremony failed")
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[derive(Deserialize)]
pub struct RegistrationStart {
    pub name: Option<String>,
}

pub async fn registration_start(
    State(state): State<AppState>,
    session: Session,
    Json(input): Json<RegistrationStart>,
) -> Result<Response, JsonError> {
    let user = session_user(&state, &session)
        .await
        .map_err(AppError::json)?;
    let webauthn = webauthn(&state).map_err(AppError::json)?;
    let name = input
        .name
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "passkey".to_string());
    if name.len() > 64 {
        return Err(AppError::bad_request("passkey name must be <= 64 chars").json());
    }
    let existing: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT cred_id FROM passkeys WHERE user_id = $1")
            .bind(user.id)
            .fetch_all(&state.pool)
            .await
            .map_err(|error| AppError::from(error).json())?;
    let exclude = (!existing.is_empty())
        .then(|| existing.into_iter().map(CredentialID::from).collect());
    let display_name = user.display_name.as_deref().unwrap_or(&user.username);
    let (options, registration) = webauthn
        .start_passkey_registration(user.id, &user.username, display_name, exclude)
        .map_err(|error| ceremony_error(error).json())?;

    session
        .insert(REGISTRATION_STATE, registration)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    session
        .insert(REGISTRATION_USER, user.id.to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    session
        .insert(REGISTRATION_NAME, name)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    Ok(Json(options).into_response())
}

pub async fn registration_finish(
    State(state): State<AppState>,
    session: Session,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Result<Response, JsonError> {
    let user = session_user(&state, &session)
        .await
        .map_err(AppError::json)?;
    let registration = session
        .remove::<PasskeyRegistration>(REGISTRATION_STATE)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?
        .ok_or_else(|| AppError::bad_request("passkey registration was not started").json())?;
    let registration_user = session
        .remove::<String>(REGISTRATION_USER)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?
        .and_then(|id| id.parse::<Uuid>().ok());
    let name = session
        .remove::<String>(REGISTRATION_NAME)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?
        .unwrap_or_else(|| "passkey".to_string());
    if registration_user != Some(user.id) {
        return Err(AppError::bad_request("passkey registration session changed").json());
    }

    let passkey = webauthn(&state)
        .map_err(AppError::json)?
        .finish_passkey_registration(&credential, &registration)
        .map_err(|error| ceremony_error(error).json())?;
    let credential_id = passkey.cred_id().as_slice().to_vec();
    // A Passkey is entirely public credential material. Persist its serialized
    // form so webauthn-rs retains the COSE key plus transport/backup policy
    // needed to authenticate it later.
    let public_key = serde_json::to_vec(&passkey)
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    let counter = serialized_counter(&passkey).map_err(AppError::json)?;
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO passkeys (id, user_id, cred_id, public_key, counter, name)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(user.id)
    .bind(credential_id)
    .bind(public_key)
    .bind(counter)
    .bind(&name)
    .execute(&state.pool)
    .await;
    match inserted {
        Ok(_) => Ok(Json(json!({"id": id, "name": name})).into_response()),
        Err(error) if is_unique_violation(&error) => {
            Err(AppError::bad_request("passkey is already registered").json())
        }
        Err(error) => Err(AppError::from(error).json()),
    }
}

fn serialized_counter(passkey: &Passkey) -> Result<i64, AppError> {
    let value = serde_json::to_value(passkey).map_err(|error| AppError::internal(error.to_string()))?;
    let counter = value
        .pointer("/cred/counter")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| AppError::internal("serialized passkey has no counter"))?;
    i64::try_from(counter).map_err(|error| AppError::internal(error.to_string()))
}

#[derive(Deserialize)]
pub struct AuthenticationStart {
    pub username: String,
}

pub async fn authentication_start(
    State(state): State<AppState>,
    session: Session,
    Json(input): Json<AuthenticationStart>,
) -> Result<Response, JsonError> {
    let webauthn = webauthn(&state).map_err(AppError::json)?;
    let user = db::find_user_by_name(&state.pool, input.username.trim())
        .await
        .map_err(|error| AppError::from(error).json())?
        .ok_or_else(|| AppError::bad_request("passkey login failed").json())?;
    let rows = sqlx::query_as::<_, StoredCredential>(
        "SELECT cred_id, public_key FROM passkeys WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| AppError::from(error).json())?;
    let credentials: Vec<Passkey> = rows
        .into_iter()
        .map(|row| {
            let passkey: Passkey = serde_json::from_slice(&row.public_key)
                .map_err(|error| AppError::internal(error.to_string()))?;
            if passkey.cred_id().as_slice() != row.cred_id {
                return Err(AppError::internal("stored passkey id does not match credential"));
            }
            Ok(passkey)
        })
        .collect::<Result<_, _>>()
        .map_err(AppError::json)?;
    if credentials.is_empty() {
        return Err(AppError::bad_request("passkey login failed").json());
    }
    let (options, authentication) = webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|error| ceremony_error(error).json())?;
    session
        .insert(AUTHENTICATION_STATE, authentication)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    session
        .insert(AUTHENTICATION_USER, user.id.to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    Ok(Json(options).into_response())
}

pub async fn authentication_finish(
    State(state): State<AppState>,
    session: Session,
    Json(credential): Json<PublicKeyCredential>,
) -> Result<Response, JsonError> {
    let authentication = session
        .remove::<PasskeyAuthentication>(AUTHENTICATION_STATE)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?
        .ok_or_else(|| AppError::bad_request("passkey authentication was not started").json())?;
    let user_id = session
        .remove::<String>(AUTHENTICATION_USER)
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?
        .and_then(|id| id.parse::<Uuid>().ok())
        .ok_or_else(|| AppError::bad_request("passkey authentication session changed").json())?;
    let result = webauthn(&state)
        .map_err(AppError::json)?
        .finish_passkey_authentication(&credential, &authentication)
        .map_err(|error| ceremony_error(error).json())?;
    let credential_id = result.cred_id().as_slice();
    let next_counter = i64::from(result.counter());

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AppError::from(error).json())?;
    let row = sqlx::query_as::<_, CounterRow>(
        "SELECT id, public_key, counter FROM passkeys
         WHERE user_id = $1 AND cred_id = $2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(credential_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| AppError::from(error).json())?
    .ok_or_else(|| AppError::bad_request("passkey login failed").json())?;
    if row.counter > 0 && next_counter <= row.counter {
        return Err(AppError::forbidden("passkey counter did not advance").json());
    }
    let mut passkey: Passkey = serde_json::from_slice(&row.public_key)
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    if passkey.update_credential(&result).is_none() {
        return Err(AppError::internal("stored passkey id does not match authentication").json());
    }
    let public_key = serde_json::to_vec(&passkey)
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    let updated = sqlx::query(
        "UPDATE passkeys SET counter = $1, public_key = $2
         WHERE id = $3 AND user_id = $4 AND counter = $5",
    )
    .bind(next_counter)
    .bind(public_key)
    .bind(row.id)
    .bind(user_id)
    .bind(row.counter)
    .execute(&mut *tx)
    .await
    .map_err(|error| AppError::from(error).json())?;
    if updated.rows_affected() != 1 {
        return Err(AppError::bad_request("passkey changed during authentication").json());
    }
    tx.commit()
        .await
        .map_err(|error| AppError::from(error).json())?;

    session
        .insert(SESSION_USER_ID, user_id.to_string())
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    session
        .cycle_id()
        .await
        .map_err(|error| AppError::internal(error.to_string()).json())?;
    Ok(Json(json!({"ok": true, "redirect": "/account"})).into_response())
}

pub async fn delete_passkey(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let user = session_user(&state, &session).await?;
    let result = sqlx::query("DELETE FROM passkeys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    Ok(Redirect::to("/account").into_response())
}
