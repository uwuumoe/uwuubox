//! Role management, per-user role assignment, and OIDC group mappings.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    db::{self, Role},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone)]
pub struct RoleInput {
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

pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if !(3..=32).contains(&name.len()) {
        return Err("role name must be 3 to 32 characters");
    }
    if !name
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
    {
        return Err("role name may contain only lowercase a-z, 0-9, _ and -");
    }
    Ok(())
}

fn validate(input: &RoleInput) -> Result<(), AppError> {
    validate_name(&input.name).map_err(AppError::bad_request)?;
    if input.quota_bytes.is_some_and(|quota| quota < 0) {
        return Err(AppError::bad_request("quota_bytes must be at least 0"));
    }
    if let (Some(min), Some(default), Some(max)) = (
        input.min_expiry_secs,
        input.default_expiry_secs,
        input.max_expiry_secs,
    ) {
        if !(min <= default && default <= max) {
            return Err(AppError::bad_request(
                "expiry limits must satisfy min <= default <= max",
            ));
        }
    }
    Ok(())
}

pub async fn list(pool: &PgPool) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles ORDER BY name")
        .fetch_all(pool)
        .await
}

pub async fn get(pool: &PgPool, id: &Uuid) -> Result<Option<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn create(pool: &PgPool, input: &RoleInput) -> Result<Role, AppError> {
    validate(input)?;
    let id = Uuid::now_v7();
    sqlx::query_as::<_, Role>(
        "INSERT INTO roles (
            id, name, max_file_bytes, max_paste_bytes, max_avatar_bytes,
            min_expiry_secs, max_expiry_secs, default_expiry_secs, quota_bytes,
            can_publish_public, can_burn, can_comment, can_create_collections, can_moderate
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *",
    )
    .bind(id)
    .bind(&input.name)
    .bind(input.max_file_bytes)
    .bind(input.max_paste_bytes)
    .bind(input.max_avatar_bytes)
    .bind(input.min_expiry_secs)
    .bind(input.max_expiry_secs)
    .bind(input.default_expiry_secs)
    .bind(input.quota_bytes)
    .bind(input.can_publish_public)
    .bind(input.can_burn)
    .bind(input.can_comment)
    .bind(input.can_create_collections)
    .bind(input.can_moderate)
    .fetch_one(pool)
    .await
    .map_err(map_role_db_error)
}

pub async fn update(pool: &PgPool, id: &Uuid, input: &RoleInput) -> Result<Option<Role>, AppError> {
    validate(input)?;
    sqlx::query_as::<_, Role>(
        "UPDATE roles SET
            name=$2, max_file_bytes=$3, max_paste_bytes=$4, max_avatar_bytes=$5,
            min_expiry_secs=$6, max_expiry_secs=$7, default_expiry_secs=$8,
            quota_bytes=$9, can_publish_public=$10, can_burn=$11, can_comment=$12,
            can_create_collections=$13, can_moderate=$14
         WHERE id=$1 RETURNING *",
    )
    .bind(id)
    .bind(&input.name)
    .bind(input.max_file_bytes)
    .bind(input.max_paste_bytes)
    .bind(input.max_avatar_bytes)
    .bind(input.min_expiry_secs)
    .bind(input.max_expiry_secs)
    .bind(input.default_expiry_secs)
    .bind(input.quota_bytes)
    .bind(input.can_publish_public)
    .bind(input.can_burn)
    .bind(input.can_comment)
    .bind(input.can_create_collections)
    .bind(input.can_moderate)
    .fetch_optional(pool)
    .await
    .map_err(map_role_db_error)
}

pub async fn delete(pool: &PgPool, id: &Uuid) -> Result<bool, sqlx::Error> {
    // users.role_id is ON DELETE SET NULL; deleting a role never deletes members.
    Ok(sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

pub async fn set_user_role(
    pool: &PgPool,
    user_id: &Uuid,
    role_id: Option<&Uuid>,
    quota_override_bytes: Option<i64>,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("UPDATE users SET role_id = $2, quota_override_bytes = $3 WHERE id = $1")
            .bind(user_id)
            .bind(role_id)
            .bind(quota_override_bytes)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

fn map_role_db_error(error: sqlx::Error) -> AppError {
    if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")) {
        AppError::bad_request("role name already exists")
    } else {
        AppError::from(error)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct RoleOidcGroup {
    pub role_id: Uuid,
    pub issuer: String,
    pub group_name: String,
    pub priority: i32,
}

pub async fn list_mappings(pool: &PgPool) -> Result<Vec<RoleOidcGroup>, sqlx::Error> {
    sqlx::query_as::<_, RoleOidcGroup>(
        "SELECT role_id, issuer, group_name, priority
         FROM role_oidc_groups ORDER BY role_id, priority, issuer, group_name",
    )
    .fetch_all(pool)
    .await
}

pub async fn add_mapping(
    pool: &PgPool,
    role_id: &Uuid,
    issuer: &str,
    group_name: &str,
    priority: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO role_oidc_groups (role_id, issuer, group_name, priority)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (role_id, issuer, group_name) DO UPDATE SET priority = EXCLUDED.priority",
    )
    .bind(role_id)
    .bind(issuer)
    .bind(group_name)
    .bind(priority)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_mapping(
    pool: &PgPool,
    role_id: &Uuid,
    issuer: &str,
    group_name: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM role_oidc_groups WHERE role_id = $1 AND issuer = $2 AND group_name = $3",
    )
    .bind(role_id)
    .bind(issuer)
    .bind(group_name)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Assign the highest-priority mapping for an exact issuer and one of the
/// asserted groups. The conditional UPDATE keeps explicit admin roles sticky.
pub async fn assign_from_oidc_groups(
    pool: &PgPool,
    user_id: &Uuid,
    issuer: &str,
    groups: &[String],
) -> Result<Option<Uuid>, sqlx::Error> {
    if groups.is_empty() {
        return Ok(None);
    }
    let role_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT role_id FROM role_oidc_groups
         WHERE issuer = $1 AND group_name = ANY($2)
         ORDER BY priority, role_id, group_name LIMIT 1",
    )
    .bind(issuer)
    .bind(groups)
    .fetch_optional(pool)
    .await?;
    let Some(role_id) = role_id else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, Uuid>(
        "UPDATE users SET role_id = $2
         WHERE id = $1 AND role_id IS NULL RETURNING role_id",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Deserialize)]
pub struct RoleForm {
    name: String,
    max_file_bytes: Option<String>,
    max_paste_bytes: Option<String>,
    max_avatar_bytes: Option<String>,
    min_expiry_secs: Option<String>,
    max_expiry_secs: Option<String>,
    default_expiry_secs: Option<String>,
    quota_bytes: Option<String>,
    can_publish_public: Option<String>,
    can_burn: Option<String>,
    can_comment: Option<String>,
    can_create_collections: Option<String>,
    can_moderate: Option<String>,
}

fn optional_i64(value: Option<String>, field: &str) -> Result<Option<i64>, AppError> {
    let value = value.unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| AppError::bad_request(format!("{field} must be a number")))
}

impl RoleForm {
    fn into_input(self) -> Result<RoleInput, AppError> {
        Ok(RoleInput {
            name: self.name.trim().to_string(),
            max_file_bytes: optional_i64(self.max_file_bytes, "max_file_bytes")?,
            max_paste_bytes: optional_i64(self.max_paste_bytes, "max_paste_bytes")?,
            max_avatar_bytes: optional_i64(self.max_avatar_bytes, "max_avatar_bytes")?,
            min_expiry_secs: optional_i64(self.min_expiry_secs, "min_expiry_secs")?,
            max_expiry_secs: optional_i64(self.max_expiry_secs, "max_expiry_secs")?,
            default_expiry_secs: optional_i64(self.default_expiry_secs, "default_expiry_secs")?,
            quota_bytes: optional_i64(self.quota_bytes, "quota_bytes")?,
            can_publish_public: self.can_publish_public.is_some(),
            can_burn: self.can_burn.is_some(),
            can_comment: self.can_comment.is_some(),
            can_create_collections: self.can_create_collections.is_some(),
            can_moderate: self.can_moderate.is_some(),
        })
    }
}

pub async fn create_role(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<RoleForm>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    let role = create(&state.pool, &form.into_input()?).await?;
    db::audit(
        &state.pool,
        Some(&actor.id),
        "role.create",
        Some("role"),
        Some(&role.id.to_string()),
        Some(json!({"name": role.name})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

pub async fn update_role(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<RoleForm>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    let role = update(&state.pool, &id, &form.into_input()?)
        .await?
        .ok_or(AppError::NotFound)?;
    db::audit(
        &state.pool,
        Some(&actor.id),
        "role.update",
        Some("role"),
        Some(&role.id.to_string()),
        Some(json!({"name": role.name})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

pub async fn delete_role(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    let role = get(&state.pool, &id).await?.ok_or(AppError::NotFound)?;
    delete(&state.pool, &id).await?;
    db::audit(
        &state.pool,
        Some(&actor.id),
        "role.delete",
        Some("role"),
        Some(&id.to_string()),
        Some(json!({"name": role.name})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

#[derive(Debug, Deserialize)]
pub struct UserRoleForm {
    role_id: Option<String>,
    quota_override_bytes: Option<String>,
}

pub async fn update_user_role(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Form(form): Form<UserRoleForm>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    let role_id = match form
        .role_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(value) => Some(
            value
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("bad role id"))?,
        ),
        None => None,
    };
    if let Some(role_id) = role_id.as_ref() {
        get(&state.pool, role_id).await?.ok_or(AppError::NotFound)?;
    }
    let quota = optional_i64(form.quota_override_bytes, "quota_override_bytes")?;
    if quota.is_some_and(|value| value < 0) {
        return Err(AppError::bad_request(
            "quota_override_bytes must be at least 0",
        ));
    }
    if !set_user_role(&state.pool, &user_id, role_id.as_ref(), quota).await? {
        return Err(AppError::NotFound);
    }
    db::audit(
        &state.pool,
        Some(&actor.id),
        "user.role",
        Some("user"),
        Some(&user_id.to_string()),
        Some(json!({"role_id": role_id, "quota_override_bytes": quota})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

#[derive(Debug, Deserialize)]
pub struct MappingForm {
    issuer: String,
    group_name: String,
    priority: i32,
}

pub async fn add_oidc_mapping(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(role_id): Path<Uuid>,
    Form(form): Form<MappingForm>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    get(&state.pool, &role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let issuer = form.issuer.trim();
    let group_name = form.group_name.trim();
    if issuer.is_empty() || group_name.is_empty() {
        return Err(AppError::bad_request("issuer and group name are required"));
    }
    add_mapping(&state.pool, &role_id, issuer, group_name, form.priority).await?;
    db::audit(
        &state.pool,
        Some(&actor.id),
        "role.oidc_group.add",
        Some("role"),
        Some(&role_id.to_string()),
        Some(json!({"issuer": issuer, "group_name": group_name, "priority": form.priority})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

#[derive(Debug, Deserialize)]
pub struct RemoveMappingForm {
    issuer: String,
    group_name: String,
}

pub async fn remove_oidc_mapping(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(role_id): Path<Uuid>,
    Form(form): Form<RemoveMappingForm>,
) -> Result<Response, AppError> {
    let actor = super::admin::require_admin(&state, &session, &headers).await?;
    if !remove_mapping(
        &state.pool,
        &role_id,
        form.issuer.trim(),
        form.group_name.trim(),
    )
    .await?
    {
        return Err(AppError::NotFound);
    }
    db::audit(
        &state.pool,
        Some(&actor.id),
        "role.oidc_group.remove",
        Some("role"),
        Some(&role_id.to_string()),
        Some(json!({"issuer": form.issuer.trim(), "group_name": form.group_name.trim()})),
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

#[cfg(test)]
mod tests {
    use super::validate_name;

    #[test]
    fn role_names_enforce_public_contract() {
        for valid in [
            "abc",
            "uploaders",
            "oidc-admin_2",
            "a2345678901234567890123456789012",
        ] {
            assert!(validate_name(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "ab",
            "a23456789012345678901234567890123",
            "Admin",
            "has space",
            "olé",
        ] {
            assert!(validate_name(invalid).is_err(), "{invalid}");
        }
    }
}
