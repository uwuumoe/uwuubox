//! Pastes: JSON-or-form create, syntect server highlight, raw plaintext.
//!
//! The syntect boundary lives here and nowhere else: `language` is resolved
//! once at create time and stored, so rendering is a pure function of the row.

use std::sync::OnceLock;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header::*, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use syntect::{
    highlighting::ThemeSet,
    html::{css_for_theme_with_class_style, highlighted_html_for_string, ClassStyle},
    parsing::SyntaxSet,
};
use tower_sessions::Session;
use tracing::info;

use crate::{
    auth,
    db::{self, PasteRow},
    error::{AppError, JsonError},
    identity::current_user,
    ids,
    routes::common::{check_delete_access, wants_html},
    state::AppState,
    views::{human_time, PastePage},
};

static SYNTAXES: OnceLock<SyntaxSet> = OnceLock::new();
static THEMES: OnceLock<ThemeSet> = OnceLock::new();

fn syntaxes() -> &'static SyntaxSet {
    SYNTAXES.get_or_init(SyntaxSet::load_defaults_newlines)
}
fn themes() -> &'static ThemeSet {
    THEMES.get_or_init(ThemeSet::load_defaults)
}

/// Alias → canonical syntect syntax name. Unknown → `None` (Plain Text).
pub fn canonical_language(input: &str) -> Option<String> {
    let ss = syntaxes();
    let t = input.trim();
    if t.is_empty() || t.len() > 32 {
        return None;
    }
    if let Some(s) = ss.find_syntax_by_name(t) {
        return Some(s.name.clone());
    }
    let lower = t.to_lowercase();
    const ALIASES: &[(&str, &str)] = &[
        ("rs", "Rust"),
        ("rust", "Rust"),
        ("py", "Python"),
        ("python", "Python"),
        ("js", "JavaScript"),
        ("javascript", "JavaScript"),
        ("ts", "TypeScript"),
        ("typescript", "TypeScript"),
        ("sh", "Bourne Again Shell (bash)"),
        ("bash", "Bourne Again Shell (bash)"),
        ("json", "JSON"),
        ("toml", "TOML"),
        ("yaml", "YAML"),
        ("yml", "YAML"),
        ("md", "Markdown"),
        ("markdown", "Markdown"),
        ("html", "HTML"),
        ("css", "CSS"),
        ("go", "Go"),
        ("c", "C"),
        ("cpp", "C++"),
        ("c++", "C++"),
        ("java", "Java"),
        ("rb", "Ruby"),
        ("ruby", "Ruby"),
        ("sql", "SQL"),
        ("xml", "XML"),
        ("txt", "Plain Text"),
        ("text", "Plain Text"),
    ];
    if let Some((_, name)) = ALIASES.iter().find(|(a, _)| *a == lower) {
        return Some(name.to_string());
    }
    // Extension lookup on bundled syntaxes (`rs` etc. also match here).
    if let Some(s) = ss.find_syntax_by_extension(&lower) {
        return Some(s.name.clone());
    }
    None
}

pub fn detect_language(explicit: Option<&str>, body: &str) -> Option<String> {
    if let Some(e) = explicit {
        return canonical_language(e);
    }
    let ss = syntaxes();
    let first = body.lines().next().unwrap_or("");
    if let Some(s) = ss.find_syntax_by_first_line(first) {
        return Some(s.name.clone());
    }
    None
}

/// Highlight + inline theme CSS; per-line spans feed CSS-counter line numbers.
/// (Multi-line tokens can split a span across `.line` wrappers — browsers
/// still color them acceptably; no JS highlighter is worth the tradeoff.)
pub fn render_highlight(language: Option<&str>, body: &str) -> Result<(String, String), String> {
    let ss = syntaxes();
    let ts = themes();
    let theme = ts
        .themes
        .get("base16-ocean.dark")
        .or_else(|| ts.themes.values().next())
        .ok_or_else(|| "no syntect themes available".to_string())?;
    let syntax = language
        .and_then(|l| ss.find_syntax_by_name(l))
        .unwrap_or_else(|| ss.find_syntax_plain_text());
    let html = highlighted_html_for_string(body, ss, syntax, theme).map_err(|e| e.to_string())?;
    let css =
        css_for_theme_with_class_style(theme, ClassStyle::Spaced).map_err(|e| e.to_string())?;
    // syntect wraps everything in its own <pre style="background…">; the
    // template provides the <pre>, so unwrap to the inner token spans.
    let inner = html.trim();
    let inner = inner
        .strip_prefix("<pre")
        .and_then(|s| s.find('>').map(|i| &s[i + 1..]))
        .unwrap_or(inner);
    let inner = inner.strip_suffix("</pre>").unwrap_or(inner);
    let inner = inner.strip_suffix('\n').unwrap_or(inner);
    // Exactly one leading newline is syntect's <pre> formatting, not content.
    let inner = inner.strip_prefix('\n').unwrap_or(inner);
    let mut wrapped = String::with_capacity(inner.len() + 64);
    for line in inner.split('\n') {
        wrapped.push_str("<span class=\"line\">");
        wrapped.push_str(line);
        wrapped.push_str("</span>\n");
    }
    Ok((wrapped, css))
}

#[derive(Debug, Deserialize)]
struct PasteJson {
    title: Option<String>,
    body: Option<String>,
    language: Option<String>,
    visibility: Option<String>,
    expires_in_secs: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct PasteForm {
    title: Option<String>,
    body: Option<String>,
    language: Option<String>,
    visibility: Option<String>,
    expires_in_secs: Option<String>,
}

#[derive(Debug, Serialize)]
struct PasteOut {
    id_core: String,
    preview_url: String,
    raw_url: String,
    expires_at: chrono::DateTime<Utc>,
    delete_token: String,
}

pub async fn create_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, JsonError> {
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|e| AppError::from(e).json())?;
    if user.is_none() && !cfg.allow_anonymous {
        return Err(AppError::forbidden("anonymous pastes are disabled").json());
    }

    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (title, text, language, visibility_raw, requested): (
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
    ) = if ct.contains("application/json") {
        let v: PasteJson = serde_json::from_slice(&body)
            .map_err(|e| AppError::bad_request(format!("bad JSON: {e}")).json())?;
        (
            v.title,
            v.body.unwrap_or_default(),
            v.language,
            v.visibility,
            v.expires_in_secs,
        )
    } else {
        let f: PasteForm = serde_urlencoded::from_bytes(&body)
            .map_err(|e| AppError::bad_request(format!("bad form: {e}")).json())?;
        let exp = ids::parse_expiry_param(f.expires_in_secs.as_deref())
            .map_err(|_| AppError::bad_request("bad expires_in_secs").json())?;
        (
            f.title,
            f.body.unwrap_or_default(),
            f.language,
            f.visibility,
            exp,
        )
    };

    if text.is_empty() {
        return Err(AppError::bad_request("empty paste").json());
    }
    if text.len() as i64 > cfg.max_paste_bytes {
        return Err(AppError::TooLarge {
            max_bytes: cfg.max_paste_bytes,
        }
        .json());
    }
    let title = title
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if title.as_ref().is_some_and(|t| t.len() > 140) {
        return Err(AppError::bad_request("title must be <= 140 chars").json());
    }
    let visibility = match visibility_raw.as_deref().map(str::trim) {
        None | Some("") | Some("unlisted") => "unlisted",
        Some("public") => {
            if user.is_none() {
                return Err(AppError::bad_request("public visibility requires login").json());
            }
            "public"
        }
        Some(other) => {
            return Err(AppError::bad_request(format!("bad visibility: {other:?}")).json())
        }
    };
    let secs = ids::clamp_expiry(
        requested,
        cfg.min_expiry_secs,
        cfg.default_expiry_secs,
        cfg.max_expiry_secs,
    );
    let expires_at = Utc::now() + chrono::TimeDelta::seconds(secs);
    let language = detect_language(language.as_deref(), &text);

    let mut core = String::new();
    for _ in 0..5 {
        let c = ids::generate_core();
        let hit = db::find_paste(&state.pool, &c)
            .await
            .map_err(|e| AppError::from(e).json())?;
        if hit.is_none() {
            core = c;
            break;
        }
    }
    if core.is_empty() {
        return Err(AppError::internal("id allocation failed").json());
    }

    let delete_token_raw = auth::new_delete_token();
    let delete_token_hash = auth::delete_token_hash(&state.env.session_secret, &delete_token_raw);
    sqlx::query(
        "INSERT INTO pastes (id_core, owner_id, title, body, language, visibility, expires_at, delete_token_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&core)
    .bind(user.as_ref().map(|u| u.id))
    .bind(&title)
    .bind(&text)
    .bind(&language)
    .bind(visibility)
    .bind(expires_at)
    .bind(&delete_token_hash)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::from(e).json())?;

    info!(core = %core, bytes = text.len(), user = user.as_ref().map(|u| u.username.as_str()).unwrap_or("-"), "paste stored");

    let preview_url = format!("{}/p/{}", state.env.base_url, core.trim_end());
    let raw_url = format!("{}/p/{}/raw", state.env.base_url, core.trim_end());
    if wants_html(&headers) {
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, preview_url)], "").into_response());
    }
    Ok(Json(PasteOut {
        id_core: core.trim_end().to_string(),
        preview_url,
        raw_url,
        expires_at,
        delete_token: delete_token_raw,
    })
    .into_response())
}

async fn load_live_paste(state: &AppState, core: &str) -> Result<PasteRow, AppError> {
    if core.is_empty() || ids::is_reserved(core) {
        return Err(AppError::NotFound);
    }
    let p = db::find_paste(&state.pool, core)
        .await?
        .ok_or(AppError::NotFound)?;
    if p.expires_at < Utc::now() {
        return Err(AppError::NotFound);
    }
    Ok(p)
}

pub async fn view_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(core): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use askama::Template;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let paste = load_live_paste(&state, core.trim()).await?;
    let cfg = db::instance_config(&state.pool).await?;
    let (highlighted, highlight_css) =
        render_highlight(paste.language.as_deref(), &paste.body).map_err(AppError::internal)?;
    let owner_name = match paste.owner_id {
        Some(id) => db::find_user_by_id(&state.pool, &id)
            .await?
            .map(|u| u.username),
        None => None,
    };
    let title = paste
        .title
        .clone()
        .unwrap_or_else(|| format!("paste {}", paste.id_core.trim_end()));
    let desc: String = paste.body.chars().take(160).collect();
    let page = PastePage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user,
        title,
        highlighted,
        highlight_css,
        language: paste
            .language
            .clone()
            .unwrap_or_else(|| "Plain Text".into()),
        expires_human: human_time(&paste.expires_at),
        owner_name,
        raw_url: format!("{}/p/{}/raw", state.env.base_url, paste.id_core.trim_end()),
        desc,
    };
    page.render()
        .map_err(|e| AppError::internal(e.to_string()))
        .map(axum::response::Html)
}

pub async fn raw_paste(
    State(state): State<AppState>,
    Path(core): Path<String>,
) -> Result<Response, AppError> {
    let paste = load_live_paste(&state, core.trim()).await?;
    Response::builder()
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, paste.body.len())
        .header(CACHE_CONTROL, "public, max-age=86400")
        .body(axum::body::Body::from(paste.body))
        .map_err(|e| AppError::internal(e.to_string()))
}

#[derive(Deserialize)]
pub struct PasteDeleteBody {
    pub delete_token: Option<String>,
}

pub async fn delete_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(core): Path<String>,
    body: Option<Json<PasteDeleteBody>>,
) -> Result<impl IntoResponse, JsonError> {
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let core = core.trim().to_string();
    let row = db::find_paste(&state.pool, &core)
        .await
        .map_err(|e| AppError::from(e).json())?
        .ok_or(AppError::NotFound.json())?;
    let provided = body.as_ref().and_then(|b| b.delete_token.as_deref());
    if !check_delete_access(
        user.as_ref(),
        row.owner_id,
        row.delete_token_hash.as_deref(),
        &state.env.session_secret,
        provided,
    ) {
        return Err(AppError::forbidden("not allowed").json());
    }
    sqlx::query("DELETE FROM pastes WHERE id_core = $1")
        .bind(&core)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::from(e).json())?;
    Ok(Json(json!({"deleted": core})))
}

#[derive(Deserialize)]
pub struct PasteVisibilityBody {
    pub visibility: String,
}

pub async fn toggle_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(core): Path<String>,
    Json(body): Json<PasteVisibilityBody>,
) -> Result<impl IntoResponse, JsonError> {
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let Some(u) = user else {
        return Err(AppError::Unauthorized.json());
    };
    if !matches!(body.visibility.trim(), "public" | "unlisted") {
        return Err(AppError::bad_request("visibility must be public|unlisted").json());
    }
    let row = db::find_paste(&state.pool, core.trim())
        .await
        .map_err(|e| AppError::from(e).json())?
        .ok_or(AppError::NotFound.json())?;
    if row.owner_id != Some(u.id) {
        return Err(AppError::NotFound.json());
    }
    sqlx::query("UPDATE pastes SET visibility = $1 WHERE id_core = $2")
        .bind(body.visibility.trim())
        .bind(core.trim())
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::from(e).json())?;
    Ok(Json(
        json!({"id_core": core.trim(), "visibility": body.visibility.trim()}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_aliases() {
        assert_eq!(canonical_language("rs").as_deref(), Some("Rust"));
        assert_eq!(canonical_language("Python").as_deref(), Some("Python"));
        assert_eq!(canonical_language("definitely-not-a-lang").as_deref(), None);
        assert_eq!(canonical_language("").as_deref(), None);
    }

    #[test]
    fn highlight_falls_back_to_plain() {
        // Highlighted spans split tokens across tags; assert on text content.
        fn text_of(html: &str) -> String {
            let mut out = String::new();
            let mut tag = false;
            for c in html.chars() {
                match c {
                    '<' => tag = true,
                    '>' => tag = false,
                    _ if !tag => out.push(c),
                    _ => {}
                }
            }
            out
        }
        let (html, css) = render_highlight(None, "fn main() {}").unwrap();
        assert!(text_of(&html).contains("fn main() {}"));
        assert!(!css.is_empty());
        let (html, _) = render_highlight(Some("Rust"), "fn main() {}").unwrap();
        assert!(text_of(&html).contains("fn main() {}"));
        // Rust highlighting actually emits styled spans, plain text does not split.
        assert!(html.contains("<span"));
    }
}
