//! `AppError`: status + JSON-vs-HTML rendering.
//!
//! Convention: `/api/*` handlers call `.json()` so clients get
//! `{"error": ...}`; page handlers return the error bare for an HTML page.

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("payload too large")]
    TooLarge { max_bytes: i64 },
    #[error("unsupported media type: {mime}")]
    UnsupportedMedia { mime: String },
    #[error("{0}")]
    Unprocessable(String),
    #[error("rate limited")]
    RateLimited,
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct JsonError(pub AppError);

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        tracing::error!(error = %msg.into(), "internal error");
        Self::Internal("something went wrong".into())
    }
    /// Mark for JSON rendering (`/api/*` handlers).
    pub fn json(self) -> JsonError {
        JsonError(self)
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMedia { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound => "not_found",
            Self::TooLarge { .. } => "too_large",
            Self::UnsupportedMedia { .. } => "unsupported_media_type",
            Self::Unprocessable(_) => "unprocessable",
            Self::RateLimited => "rate_limited",
            Self::Internal(_) => "internal_error",
        }
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn error_page(status: StatusCode, title: &str, detail: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} · {title}</title>
<style>:root{{color-scheme:light dark}}body{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}}a{{color:inherit}}</style>
</head><body><h1>{code} · {title}</h1><p>{detail}</p><p><a href="/">← uwuubox home</a></p></body></html>"#,
        code = status.as_u16(),
        title = esc(title),
        detail = esc(detail),
    ))
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let (title, detail) = match &self {
            Self::BadRequest(m) | Self::Forbidden(m) => ("error", m.clone()),
            Self::Unauthorized => ("unauthorized", "log in first".into()),
            Self::NotFound => ("not found", "nothing here".into()),
            Self::TooLarge { max_bytes } => (
                "too large",
                format!("payload exceeds the {max_bytes}-byte limit"),
            ),
            Self::UnsupportedMedia { mime } => {
                ("unsupported media", format!("refusing to serve {mime}"))
            }
            Self::RateLimited => ("too many requests", "slow down and retry later".into()),
            Self::Unprocessable(m) => ("rejected", m.clone()),
            Self::Internal(m) => ("internal error", m.clone()),
        };
        (status, error_page(status, title, &detail)).into_response()
    }
}

impl IntoResponse for JsonError {
    fn into_response(self) -> Response {
        let status = self.0.status();
        let body = match &self.0 {
            AppError::BadRequest(m) | AppError::Forbidden(m) | AppError::Internal(m) => {
                json!({"error": self.0.code(), "message": m})
            }
            AppError::Unauthorized => json!({"error": "unauthorized"}),
            AppError::NotFound => json!({"error": "not_found"}),
            AppError::TooLarge { max_bytes } => {
                json!({"error": "too_large", "max_bytes": max_bytes})
            }
            AppError::UnsupportedMedia { mime } => {
                json!({"error": "unsupported_media_type", "mime": mime})
            }
            AppError::Unprocessable(m) => {
                json!({"error": "unprocessable", "message": m})
            }
            AppError::RateLimited => json!({"error": "rate_limited"}),
        };
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        Self::internal(e.to_string())
    }
}

impl From<crate::storage::StorageError> for AppError {
    fn from(e: crate::storage::StorageError) -> Self {
        use crate::storage::StorageError as S;
        match e {
            S::NotFound(_) => Self::NotFound,
            S::Backend(msg) => Self::internal(msg),
        }
    }
}
