//! Pastes: JSON-or-form create, safe markdown, highlighted code, protected raw reads.

use std::sync::OnceLock;

use axum::{
    body::Bytes,
    extract::{Form, Path, Query, State},
    http::{header::*, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use pulldown_cmark::{html, Options, Parser};
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
    identity::{current_identity, current_user, require_scope},
    ids,
    range::{self, RangeOutcome},
    routes::common::{check_delete_access, wants_html},
    state::AppState,
    views::{human_expiry, PastePage},
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
    if let Some((_, name)) = ALIASES.iter().find(|(alias, _)| *alias == lower) {
        return Some(name.to_string());
    }
    ss.find_syntax_by_extension(&lower)
        .map(|syntax| syntax.name.clone())
}

pub fn detect_language(explicit: Option<&str>, body: &str) -> Option<String> {
    if let Some(explicit) = explicit {
        return canonical_language(explicit);
    }
    syntaxes()
        .find_syntax_by_first_line(body.lines().next().unwrap_or(""))
        .map(|syntax| syntax.name.clone())
}

/// Highlight + inline theme CSS; per-line spans feed CSS-counter line numbers.
pub fn render_highlight(language: Option<&str>, body: &str) -> Result<(String, String), String> {
    let ss = syntaxes();
    let theme = themes()
        .themes
        .get("base16-ocean.dark")
        .or_else(|| themes().themes.values().next())
        .ok_or_else(|| "no syntect themes available".to_string())?;
    let syntax = language
        .and_then(|language| ss.find_syntax_by_name(language))
        .unwrap_or_else(|| ss.find_syntax_plain_text());
    let rendered =
        highlighted_html_for_string(body, ss, syntax, theme).map_err(|error| error.to_string())?;
    let css =
        css_for_theme_with_class_style(theme, ClassStyle::Spaced).map_err(|e| e.to_string())?;
    let inner = rendered.trim();
    let inner = inner
        .strip_prefix("<pre")
        .and_then(|value| value.find('>').map(|index| &value[index + 1..]))
        .unwrap_or(inner);
    let inner = inner.strip_suffix("</pre>").unwrap_or(inner);
    let inner = inner.strip_suffix('\n').unwrap_or(inner);
    let inner = inner.strip_prefix('\n').unwrap_or(inner);
    let mut wrapped = String::with_capacity(inner.len() + 64);
    for line in inner.split('\n') {
        wrapped.push_str("<span class=\"line\">");
        wrapped.push_str(line);
        wrapped.push_str("</span>\n");
    }
    Ok((wrapped, css))
}

pub fn render_markdown(body: &str) -> String {
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut rendered = String::with_capacity(body.len());
    html::push_html(&mut rendered, Parser::new_ext(body, options));
    ammonia::clean(&rendered)
}

#[derive(Debug, Deserialize)]
struct PasteJson {
    title: Option<String>,
    body: Option<String>,
    language: Option<String>,
    format: Option<String>,
    visibility: Option<String>,
    expires_in_secs: Option<serde_json::Value>,
    burn_after_read: Option<bool>,
    access_password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PasteForm {
    title: Option<String>,
    body: Option<String>,
    language: Option<String>,
    format: Option<String>,
    visibility: Option<String>,
    expires_in_secs: Option<String>,
    burn_after_read: Option<String>,
    access_password: Option<String>,
}

#[derive(Debug, Serialize)]
struct PasteOut {
    id_core: String,
    preview_url: String,
    raw_url: String,
    expires_at: Option<chrono::DateTime<Utc>>,
    delete_token: String,
}

struct PasteInput {
    title: Option<String>,
    body: String,
    language: Option<String>,
    format: Option<String>,
    visibility: Option<String>,
    expires_in_secs: ids::ExpiryRequest,
    burn_after_read: bool,
    access_password: Option<String>,
}

fn form_bool(value: Option<&str>, field: &str) -> Result<bool, AppError> {
    match value.map(str::trim) {
        None | Some("") | Some("0") | Some("false") | Some("off") | Some("no") => Ok(false),
        Some("1") | Some("true") | Some("on") | Some("yes") => Ok(true),
        Some(_) => Err(AppError::bad_request(format!("{field} must be a boolean"))),
    }
}

fn parse_input(headers: &HeaderMap, body: &[u8]) -> Result<PasteInput, AppError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/json") {
        let input: PasteJson = serde_json::from_slice(body)
            .map_err(|error| AppError::bad_request(format!("bad JSON: {error}")))?;
        Ok(PasteInput {
            title: input.title,
            body: input.body.unwrap_or_default(),
            language: input.language,
            format: input.format,
            visibility: input.visibility,
            expires_in_secs: ids::parse_expiry_json(input.expires_in_secs.as_ref())
                .map_err(|_| AppError::bad_request("bad expires_in_secs"))?,
            burn_after_read: input.burn_after_read.unwrap_or(false),
            access_password: input.access_password,
        })
    } else {
        let input: PasteForm = serde_urlencoded::from_bytes(body)
            .map_err(|error| AppError::bad_request(format!("bad form: {error}")))?;
        let expires_in_secs = ids::parse_expiry_param(input.expires_in_secs.as_deref())
            .map_err(|_| AppError::bad_request("bad expires_in_secs"))?;
        Ok(PasteInput {
            title: input.title,
            body: input.body.unwrap_or_default(),
            language: input.language,
            format: input.format,
            visibility: input.visibility,
            expires_in_secs,
            burn_after_read: form_bool(input.burn_after_read.as_deref(), "burn_after_read")?,
            access_password: input.access_password,
        })
    }
}

pub async fn create_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, JsonError> {
    let metrics = state.metrics.clone();
    match create_paste_inner(state, session, headers, body).await {
        Ok(response) => {
            metrics.pastes.with_label_values(&["ok"]).inc();
            Ok(response)
        }
        Err(error) => {
            let status = match &error {
                AppError::TooLarge { .. } => "too_large",
                AppError::BadRequest(_)
                | AppError::Unauthorized
                | AppError::Forbidden(_)
                | AppError::NotFound
                | AppError::UnsupportedMedia { .. }
                | AppError::Unprocessable(_)
                | AppError::RateLimited => "rejected",
                AppError::ServiceUnavailable(_) | AppError::Internal(_) => "error",
            };
            metrics.pastes.with_label_values(&[status]).inc();
            Err(error.json())
        }
    }
}

async fn create_paste_inner(
    state: AppState,
    session: Session,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let identity =
        current_identity(&state.pool, &state.env.session_secret, &session, &headers).await;
    if headers.contains_key(AUTHORIZATION) {
        require_scope(&identity, "paste")?;
    }
    let user = identity.as_ref().map(|identity| &identity.user);
    let cfg = db::instance_config(&state.pool).await?;
    if user.is_none() && !cfg.allow_anonymous {
        return Err(AppError::forbidden("anonymous pastes are disabled"));
    }
    let limits = db::effective_limits(&state.pool, &cfg, user).await?;
    let input = parse_input(&headers, &body)?;

    if input.body.is_empty() {
        return Err(AppError::bad_request("empty paste"));
    }
    let body_len =
        i64::try_from(input.body.len()).map_err(|_| AppError::internal("paste length overflow"))?;
    if body_len > limits.max_paste_bytes {
        return Err(AppError::TooLarge {
            max_bytes: limits.max_paste_bytes,
        });
    }
    // Account quotas intentionally count stored file bytes only. Pastes have
    // no persisted size column, so the role's max_paste_bytes is their cap.

    let title = input
        .title
        .map(|title| title.trim().to_string())
        .filter(|title| !title.is_empty());
    if title
        .as_ref()
        .is_some_and(|title| title.chars().count() > 140)
    {
        return Err(AppError::bad_request("title must be <= 140 characters"));
    }
    let format = match input.format.as_deref().map(str::trim) {
        None | Some("") | Some("code") => "code",
        Some("markdown") => "markdown",
        Some(_) => return Err(AppError::bad_request("format must be code|markdown")),
    };
    let visibility = match input.visibility.as_deref().map(str::trim) {
        None | Some("") | Some("unlisted") => "unlisted",
        Some("public") => {
            // Anonymous public pastes are allowed (same as files): they can
            // surface on the explore page. Role gate applies when authed.
            if user.is_some() && !limits.can_publish_public {
                return Err(AppError::forbidden(
                    "your role cannot publish public pastes",
                ));
            }
            "public"
        }
        Some(other) => return Err(AppError::bad_request(format!("bad visibility: {other:?}"))),
    };
    if input.burn_after_read && !limits.can_burn {
        return Err(AppError::bad_request(
            "burn-after-read is not allowed for your role",
        ));
    }
    let access_password_hash = match input.access_password.as_deref() {
        None | Some("") => None,
        Some(password) => {
            if !(8..=72).contains(&password.chars().count()) {
                return Err(AppError::bad_request(
                    "access_password must be 8-72 characters",
                ));
            }
            Some(auth::hash_password(password).map_err(AppError::bad_request)?)
        }
    };
    let lifetime = ids::clamp_expiry(
        input.expires_in_secs,
        limits.min_expiry_secs,
        limits.default_expiry_secs,
        limits.max_expiry_secs,
        cfg.allow_never(user.is_some()),
    )
    .map_err(|_| AppError::bad_request("never expiry is not allowed here"))?;
    let expires_at = lifetime.map(|secs| Utc::now() + chrono::TimeDelta::seconds(secs));
    let language = (format == "code")
        .then(|| detect_language(input.language.as_deref(), &input.body))
        .flatten();

    let mut core = String::new();
    for _ in 0..5 {
        let candidate = ids::generate_core();
        if db::find_paste(&state.pool, &candidate).await?.is_none() {
            core = candidate;
            break;
        }
    }
    if core.is_empty() {
        return Err(AppError::internal("id allocation failed"));
    }

    let delete_token = auth::new_delete_token();
    let delete_token_hash = auth::delete_token_hash(&state.env.session_secret, &delete_token);
    sqlx::query(
        "INSERT INTO pastes
         (id_core, owner_id, title, body, language, format, visibility,
          burn_after_read, access_password_hash, expires_at, delete_token_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(&core)
    .bind(user.map(|user| user.id))
    .bind(&title)
    .bind(&input.body)
    .bind(&language)
    .bind(format)
    .bind(visibility)
    .bind(input.burn_after_read)
    .bind(&access_password_hash)
    .bind(expires_at)
    .bind(&delete_token_hash)
    .execute(&state.pool)
    .await?;

    info!(
        core = %core,
        bytes = input.body.len(),
        user = user.map(|user| user.username.as_str()).unwrap_or("-"),
        "paste stored"
    );
    let preview_url = format!("{}/p/{}", state.env.base_url, core.trim_end());
    let raw_url = format!("{preview_url}/raw");
    if wants_html(&headers) {
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, preview_url)], "").into_response());
    }
    Ok(Json(PasteOut {
        id_core: core.trim_end().to_string(),
        preview_url,
        raw_url,
        expires_at,
        delete_token,
    })
    .into_response())
}

pub async fn load_live_paste(state: &AppState, core: &str) -> Result<PasteRow, AppError> {
    let core = ids::strip_to_core(core);
    if core.is_empty() || ids::is_reserved(core) {
        return Err(AppError::NotFound);
    }
    let paste = db::find_paste(&state.pool, core)
        .await?
        .ok_or(AppError::NotFound)?;
    if db::is_expired(paste.expires_at) {
        return Err(AppError::NotFound);
    }
    Ok(paste)
}

fn unlock_key(paste: &PasteRow) -> String {
    format!("uwu_unlock_{}", paste.id_core.trim_end())
}

async fn is_unlocked(session: &Session, paste: &PasteRow) -> bool {
    if paste.access_password_hash.is_none() {
        return true;
    }
    session
        .get::<bool>(&unlock_key(paste))
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

pub async fn view_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Path(core): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use askama::Template;
    let user = current_user(&state.pool, &state.env.session_secret, &session, &headers).await;
    let paste = load_live_paste(&state, &core).await?;
    let cfg = db::instance_config(&state.pool).await?;
    let unlocked = is_unlocked(&session, &paste).await;
    let locked = paste.access_password_hash.is_some() && !unlocked;
    let redacted = locked || paste.burn_after_read;
    let is_markdown = paste.format == "markdown";
    let (content_html, highlight_css) = if redacted {
        (String::new(), String::new())
    } else if is_markdown {
        (render_markdown(&paste.body), String::new())
    } else {
        render_highlight(paste.language.as_deref(), &paste.body).map_err(AppError::internal)?
    };
    let owner_name = match paste.owner_id {
        Some(id) => db::find_user_by_id(&state.pool, &id)
            .await?
            .map(|owner| owner.username),
        None => None,
    };
    let is_owner = matches!((&user, paste.owner_id), (Some(user), Some(owner)) if user.id == owner);
    let title = paste
        .title
        .clone()
        .unwrap_or_else(|| format!("paste {}", paste.id_core.trim_end()));
    let desc = if redacted {
        "Protected paste content".to_string()
    } else {
        paste.body.chars().take(160).collect()
    };
    let canonical_url = format!("{}/p/{}", state.env.base_url, paste.id_core.trim_end());
    let raw_url = if locked {
        String::new()
    } else {
        format!("{canonical_url}/raw")
    };
    let page = PastePage {
        instance_name: cfg.instance_name,
        tagline: cfg.tagline,
        icon_url: cfg.icon_url,
        user,
        core: paste.id_core.trim_end().to_string(),
        title,
        content_html,
        highlight_css,
        language: if is_markdown {
            "Markdown".into()
        } else {
            paste
                .language
                .clone()
                .unwrap_or_else(|| "Plain Text".into())
        },
        format: paste.format,
        is_markdown,
        locked,
        burn_after_read: paste.burn_after_read,
        expires_human: human_expiry(&paste.expires_at),
        owner_name,
        is_owner,
        raw_url,
        canonical_url: canonical_url.clone(),
        oembed_url: format!("/api/oembed?url={canonical_url}"),
        desc,
    };
    page.render()
        .map_err(|error| AppError::internal(error.to_string()))
        .map(axum::response::Html)
}

#[derive(Default, Deserialize)]
pub struct RawQuery {
    pub password: Option<String>,
}

fn raw_response(paste: &PasteRow, outcome: RangeOutcome, full_len: u64, body: Bytes) -> Response {
    let mut response = range::response(outcome, full_len, body);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert(
        CACHE_CONTROL,
        if paste.burn_after_read || paste.access_password_hash.is_some() {
            "private, no-store"
        } else {
            "public, max-age=86400"
        }
        .parse()
        .unwrap(),
    );
    response
}

pub async fn raw_paste(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Query(query): Query<RawQuery>,
    Path(core): Path<String>,
) -> Result<Response, AppError> {
    let paste = load_live_paste(&state, &core).await?;
    if let Some(hash) = paste.access_password_hash.as_deref() {
        let session_unlocked = is_unlocked(&session, &paste).await;
        let query_unlocked = query
            .password
            .as_deref()
            .is_some_and(|password| auth::verify_password(hash, password));
        if !session_unlocked && !query_unlocked {
            return Err(AppError::Unauthorized);
        }
    }
    let range_header = match headers.get(RANGE) {
        Some(value) => Some(
            value
                .to_str()
                .map_err(|_| AppError::bad_request("invalid Range header"))?,
        ),
        None => None,
    };
    let full_len =
        u64::try_from(paste.body.len()).map_err(|_| AppError::internal("paste length overflow"))?;
    let outcome = range::parse(range_header, full_len);
    if outcome == RangeOutcome::Invalid {
        return Err(AppError::bad_request("invalid Range header"));
    }
    if outcome == RangeOutcome::Unsatisfiable {
        return Ok(raw_response(&paste, outcome, full_len, Bytes::new()));
    }

    let all = Bytes::from(paste.body.clone());
    if paste.burn_after_read {
        // The bytes are already fetched. DELETE is the atomic winner; a
        // concurrent loser cannot receive the one-read body.
        let deleted: Option<String> =
            sqlx::query_scalar("DELETE FROM pastes WHERE id_core = $1 RETURNING id_core")
                .bind(&paste.id_core)
                .fetch_optional(&state.pool)
                .await?;
        if deleted.is_none() {
            return Err(AppError::NotFound);
        }
    }
    let body = match outcome {
        RangeOutcome::Full => all,
        RangeOutcome::Satisfiable { start, end } => {
            let start = usize::try_from(start)
                .map_err(|_| AppError::internal("range offset is too large"))?;
            let end = usize::try_from(end + 1)
                .map_err(|_| AppError::internal("range offset is too large"))?;
            all.slice(start..end)
        }
        RangeOutcome::Invalid | RangeOutcome::Unsatisfiable => unreachable!(),
    };
    Ok(raw_response(&paste, outcome, full_len, body))
}

#[derive(Deserialize)]
pub struct UnlockBody {
    pub password: String,
}

pub async fn unlock(
    State(state): State<AppState>,
    session: Session,
    Path(core): Path<String>,
    Form(body): Form<UnlockBody>,
) -> Result<Response, AppError> {
    let paste = load_live_paste(&state, &core).await?;
    if let Some(hash) = paste.access_password_hash.as_deref() {
        if !auth::verify_password(hash, &body.password) {
            return Err(AppError::Unauthorized);
        }
        session
            .insert(&unlock_key(&paste), true)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    Ok((
        StatusCode::SEE_OTHER,
        [(LOCATION, format!("/p/{}", paste.id_core.trim_end()))],
        "",
    )
        .into_response())
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
    let identity =
        current_identity(&state.pool, &state.env.session_secret, &session, &headers).await;
    if headers.contains_key(AUTHORIZATION) {
        require_scope(&identity, "delete").map_err(|error| error.json())?;
    }
    let core = ids::strip_to_core(&core).to_string();
    let row = db::find_paste(&state.pool, &core)
        .await
        .map_err(|error| AppError::from(error).json())?
        .ok_or(AppError::NotFound.json())?;
    let provided = body.as_ref().and_then(|body| body.delete_token.as_deref());
    if !check_delete_access(
        identity.as_ref().map(|identity| &identity.user),
        row.owner_id,
        row.delete_token_hash.as_deref(),
        &state.env.session_secret,
        provided,
    ) {
        return Err(AppError::forbidden("not allowed").json());
    }
    let deleted = sqlx::query("DELETE FROM pastes WHERE id_core = $1")
        .bind(&core)
        .execute(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?
        .rows_affected();
    if deleted == 0 {
        return Err(AppError::NotFound.json());
    }
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
    let identity =
        current_identity(&state.pool, &state.env.session_secret, &session, &headers).await;
    let identity = require_scope(&identity, "delete").map_err(|error| error.json())?;
    let visibility = body.visibility.trim();
    if !matches!(visibility, "public" | "unlisted") {
        return Err(AppError::bad_request("visibility must be public|unlisted").json());
    }
    let cfg = db::instance_config(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?;
    let limits = db::effective_limits(&state.pool, &cfg, Some(&identity.user))
        .await
        .map_err(|error| AppError::from(error).json())?;
    if visibility == "public" && !limits.can_publish_public {
        return Err(AppError::forbidden("your role cannot publish public pastes").json());
    }
    let core = ids::strip_to_core(&core).to_string();
    let row = db::find_paste(&state.pool, &core)
        .await
        .map_err(|error| AppError::from(error).json())?
        .ok_or(AppError::NotFound.json())?;
    if row.owner_id != Some(identity.user.id) {
        return Err(AppError::NotFound.json());
    }
    sqlx::query("UPDATE pastes SET visibility = $1 WHERE id_core = $2")
        .bind(visibility)
        .bind(&core)
        .execute(&state.pool)
        .await
        .map_err(|error| AppError::from(error).json())?;
    Ok(Json(json!({"id_core": core, "visibility": visibility})))
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
        fn text_of(html: &str) -> String {
            let mut out = String::new();
            let mut tag = false;
            for character in html.chars() {
                match character {
                    '<' => tag = true,
                    '>' => tag = false,
                    _ if !tag => out.push(character),
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
        assert!(html.contains("<span"));
    }

    #[test]
    fn markdown_is_sanitized() {
        let html = render_markdown(
            "# safe\n\n~~gone~~\n\n<script>alert(1)</script><img src=x onerror=alert(2)>",
        );
        assert!(html.contains("<h1>safe</h1>"));
        assert!(html.contains("<del>gone</del>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("onerror"));
    }
}
