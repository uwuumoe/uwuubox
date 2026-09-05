//! Password-reset request and completion routes.
//!
//! There is intentionally no separate email-verification flow: a reset is sent
//! to whatever address is currently stored on the account. Request responses
//! never reveal whether an address belongs to a user.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{auth, db, error::AppError, state::AppState};

#[derive(Template)]
#[template(
    source = r#"{% extends "layout.html" %}
{% block title %}{{ title }} · {{ instance_name }}{% endblock %}
{% block content %}
<h1>{{ title }}</h1>
{% match message %}{% when Some with (m) %}<p class="notice">{{ m }}</p>{% when None %}{% endmatch %}
{% if mode == "forgot" %}
<form method="post" action="/forgot">
<label class="field">email
<input type="email" name="email" autocomplete="email" required>
</label>
<button type="submit">send reset link</button>
</form>
{% else if mode == "reset" %}
<form method="post" action="/reset/{{ token }}">
<label class="field">new password
<input type="password" name="password" autocomplete="new-password" minlength="8" required>
</label>
<label class="field">confirm new password
<input type="password" name="password_confirm" autocomplete="new-password" minlength="8" required>
</label>
<button type="submit">set new password</button>
</form>
{% endif %}
{% endblock %}"#,
    ext = "html"
)]
struct ResetPage {
    instance_name: String,
    tagline: String,
    icon_url: String,
    user: Option<db::User>,
    title: &'static str,
    mode: &'static str,
    token: String,
    message: Option<String>,
}

async fn page(
    state: &AppState,
    title: &'static str,
    mode: &'static str,
    token: String,
    message: Option<String>,
    status: StatusCode,
) -> Result<Response, AppError> {
    let cfg = db::instance_config(&state.pool).await?;
    let body = ResetPage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user: None,
        title,
        mode,
        token,
        message,
    }
    .render()
    .map_err(|e| AppError::internal(e.to_string()))?;
    Ok((status, Html(body)).into_response())
}

#[derive(Deserialize)]
pub struct ForgotForm {
    pub email: String,
}

pub async fn forgot_form(State(state): State<AppState>) -> Result<Response, AppError> {
    if state.mailer.is_none() {
        return Err(AppError::ServiceUnavailable(
            "password-reset email is not configured".into(),
        ));
    }
    page(
        &state,
        "forgot password",
        "forgot",
        String::new(),
        None,
        StatusCode::OK,
    )
    .await
}

pub async fn forgot_post(
    State(state): State<AppState>,
    Form(form): Form<ForgotForm>,
) -> Result<Response, AppError> {
    let Some(mailer) = state.mailer.as_ref() else {
        return Err(AppError::ServiceUnavailable(
            "password-reset email is not configured".into(),
        ));
    };

    let email = form.email.trim().to_lowercase();
    let account =
        sqlx::query_as::<_, (Uuid, String)>("SELECT id, email::text FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await?;

    if let Some((user_id, destination)) = account {
        let raw = auth::new_reset_token();
        let hash = auth::reset_token_hash(&state.env.session_secret, &raw);
        sqlx::query(
            "INSERT INTO password_resets (token_hash, user_id, expires_at)
             VALUES ($1, $2, $3)",
        )
        .bind(&hash)
        .bind(user_id)
        .bind(Utc::now() + Duration::hours(1))
        .execute(&state.pool)
        .await?;

        let link = format!("{}/reset/{raw}", state.env.base_url.trim_end_matches('/'));
        if let Err(error) = mailer.send_password_reset(&destination, &link).await {
            tracing::warn!(%error, "password-reset email delivery failed");
            if let Err(delete_error) =
                sqlx::query("DELETE FROM password_resets WHERE token_hash = $1")
                    .bind(&hash)
                    .execute(&state.pool)
                    .await
            {
                tracing::warn!(error = %delete_error, "password-reset token cleanup failed");
            }
        }
    }

    page(
        &state,
        "check your email",
        "message",
        String::new(),
        Some("If an account exists for that address, a reset link has been sent.".into()),
        StatusCode::OK,
    )
    .await
}

pub async fn reset_form(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let hash = auth::reset_token_hash(&state.env.session_secret, &token);
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM password_resets
             WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
         )",
    )
    .bind(hash)
    .fetch_one(&state.pool)
    .await?;
    if !valid {
        return Err(AppError::NotFound);
    }
    page(
        &state,
        "reset password",
        "reset",
        token,
        None,
        StatusCode::OK,
    )
    .await
}

#[derive(Deserialize)]
pub struct ResetForm {
    pub password: String,
    pub password_confirm: String,
}

pub async fn reset_post(
    State(state): State<AppState>,
    _session: Session,
    Path(token): Path<String>,
    Form(form): Form<ResetForm>,
) -> Result<Response, AppError> {
    if form.password != form.password_confirm {
        return page(
            &state,
            "reset password",
            "reset",
            token,
            Some("passwords do not match".into()),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    let password_hash = match auth::hash_password(&form.password) {
        Ok(hash) => hash,
        Err(message) => {
            return page(
                &state,
                "reset password",
                "reset",
                token,
                Some(message),
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
    };

    let token_hash = auth::reset_token_hash(&state.env.session_secret, &token);
    let mut tx = state.pool.begin().await?;
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE password_resets
         SET used_at = now()
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING user_id",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Err(AppError::bad_request("reset link is invalid or expired"));
    };
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(password_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM password_resets WHERE user_id = $1 AND token_hash <> $2")
        .bind(user_id)
        .bind(&token_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    page(
        &state,
        "password changed",
        "message",
        String::new(),
        Some("Your password has been changed. You can log in now.".into()),
        StatusCode::OK,
    )
    .await
}
