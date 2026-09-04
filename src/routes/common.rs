//! Small shared route helpers: HTML-vs-JSON, preview kinds, delete access.

use axum::http::HeaderMap;

use crate::{auth, db::User};
use uuid::Uuid;

/// Browsers posting the HTML form get redirects/pages; curl gets JSON.
pub fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
}

/// Preview widget selector from the stored MIME.
pub fn file_kind(mime: &str) -> &'static str {
    if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else if mime.starts_with("audio/") {
        "audio"
    } else if mime == "text/plain" {
        "text"
    } else {
        "other"
    }
}

/// Owner session/bearer, or a matching anonymous delete token. Tokens equal
/// the user (resolved earlier); delete tokens cover anonymous uploads.
pub fn check_delete_access(
    user: Option<&User>,
    owner_id: Option<Uuid>,
    stored_hash: Option<&str>,
    secret: &[u8; 32],
    provided_token: Option<&str>,
) -> bool {
    if let (Some(u), Some(o)) = (user, owner_id) {
        if u.id == o {
            return true;
        }
    }
    match (stored_hash, provided_token) {
        (Some(s), Some(p)) => auth::tokens_equal(&auth::delete_token_hash(secret, p), s),
        _ => false,
    }
}

/// `/a/<basename>` from a stored `avatars/<uuid>.<ext>` key.
pub fn avatar_url(key: Option<&str>) -> Option<String> {
    key.and_then(|k| k.rsplit('/').next())
        .filter(|b| !b.is_empty() && !b.contains(".."))
        .map(|b| format!("/a/{b}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(file_kind("image/png"), "image");
        assert_eq!(file_kind("video/mp4"), "video");
        assert_eq!(file_kind("audio/mpeg"), "audio");
        assert_eq!(file_kind("text/plain"), "text");
        assert_eq!(file_kind("application/octet-stream"), "other");
        assert_eq!(file_kind("image/svg+xml"), "image"); // preview page still gates on should_inline
    }
}
