//! Askama page models. Every page carries the branding fields the layout
//! needs (`extends` shares the child context, so parents can't add their own).

use askama::Template;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    config::InstanceConfig,
    db::{Collection, FileRow, InviteCode, PasteRow, Role, TokenInfo, User},
    routes::{passkeys::PasskeyInfo, roles::RoleOidcGroup},
};

pub fn human_bytes(n: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n.max(0) as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} {}", n.max(0), UNITS[u])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn human_time(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// Display for a nullable expiry: `None` (never-expire) renders as "never".
pub fn human_expiry(expires_at: &Option<DateTime<Utc>>) -> String {
    expires_at.as_ref().map(human_time).unwrap_or_else(|| "never".into())
}

fn brand(cfg: &InstanceConfig) -> (String, String, String) {
    (
        cfg.instance_name.clone(),
        cfg.tagline.clone(),
        cfg.icon_url.clone(),
    )
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub allow_anonymous: bool,
    pub max_file_human: String,
    pub base_url: String,
    pub max_expiry_secs: i64,
    pub show_never: bool,
}

impl IndexPage {
    pub fn new(cfg: &InstanceConfig, user: Option<User>, base_url: &str) -> Self {
        let show_never = cfg.allow_never(user.is_some());
        Self {
            instance_name: cfg.instance_name.clone(),
            tagline: cfg.tagline.clone(),
            icon_url: cfg.icon_url.clone(),
            user,
            allow_anonymous: cfg.allow_anonymous,
            max_file_human: human_bytes(cfg.max_file_bytes),
            base_url: base_url.to_string(),
            max_expiry_secs: cfg.max_expiry_secs,
            show_never,
        }
    }
}

#[derive(Template)]
#[template(path = "file_preview.html")]
pub struct FilePreviewPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub file: FileRow,
    pub size_human: String,
    pub expires_human: String,
    pub sha256_hex: String,
    pub owner_name: Option<String>,
    pub is_owner: bool,
    pub kind: &'static str, // "image" | "video" | "audio" | "text" | "other"
    pub text_snippet: Option<String>,
    pub raw_url: String,
    pub preview_url: String,
}

#[derive(Template)]
#[template(path = "paste_view.html")]
pub struct PastePage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub core: String,
    pub title: String,
    pub content_html: String,
    pub highlight_css: String,
    pub language: String,
    pub format: String,
    pub is_markdown: bool,
    pub locked: bool,
    pub burn_after_read: bool,
    pub expires_human: String,
    pub owner_name: Option<String>,
    pub is_owner: bool,
    pub raw_url: String,
    pub canonical_url: String,
    pub oembed_url: String,
    pub desc: String,
}

#[derive(Template)]
#[template(path = "paste_new.html")]
pub struct PasteNewPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub max_paste_bytes: i64,
    pub max_expiry_secs: i64,
    pub show_never: bool,
}

impl PasteNewPage {
    pub fn new(cfg: &InstanceConfig, user: Option<User>) -> Self {
        let show_never = cfg.allow_never(user.is_some());
        Self {
            max_paste_bytes: cfg.max_paste_bytes,
            max_expiry_secs: cfg.max_expiry_secs,
            show_never,
            instance_name: cfg.instance_name.clone(),
            tagline: cfg.tagline.clone(),
            icon_url: cfg.icon_url.clone(),
            user,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CollectionItemView {
    pub kind: String,
    pub core: String,
    pub title: String,
    pub url: String,
    pub detail: String,
}
#[derive(Template)]
#[template(path = "collection.html")]
pub struct CollectionPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub collection: Collection,
    pub items: Vec<CollectionItemView>,
    pub owner_name: String,
    pub is_owner: bool,
    pub created_human: String,
    pub canonical_url: String,
    pub oembed_url: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ExploreItemView {
    pub kind: String,
    pub title: String,
    pub url: String,
    pub detail: String,
    pub created_human: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Template)]
#[template(path = "explore.html")]
pub struct ExplorePage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub items: Vec<ExploreItemView>,
    pub page: i64,
    pub has_next: bool,
    pub canonical_url: String,
}

#[derive(Template)]
#[template(path = "profile.html")]
pub struct ProfilePage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub profile: User,
    pub avatar_url: Option<String>,
    pub files: Vec<FileRow>,
    pub pastes: Vec<PasteRow>,
    pub collections: Vec<Collection>,
    pub page: i64,
    pub has_next: bool,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub files: Vec<FileRow>,
    pub pastes: Vec<PasteRow>,
    pub tokens: Vec<TokenInfo>,
    pub passkeys: Vec<PasskeyInfo>,
    pub just_created_token: Option<String>,
    pub profile_error: Option<String>,
    pub now: DateTime<Utc>,
    pub oidc_enabled: bool,
    pub oidc_linked: bool,
    pub webauthn_enabled: bool,
    pub avatar_url: Option<String>,
    pub base_url: String,
    pub storage_used: i64,
    pub storage_used_human: String,
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AdminRoleOption {
    pub id: Uuid,
    pub name: String,
    pub selected: bool,
}

#[derive(Debug, Clone)]
pub struct AdminUserRow {
    pub user: User,
    pub roles: Vec<AdminRoleOption>,
    pub quota_override_value: String,
}

#[derive(Debug, Clone)]
pub struct AdminRoleRow {
    pub role: Role,
    pub mappings: Vec<RoleOidcGroup>,
    pub members: Vec<String>,
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct AdminPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub cfg: InstanceConfig,
    pub users: Vec<AdminUserRow>,
    pub roles: Vec<AdminRoleRow>,
    pub invites: Vec<InviteCode>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub mode: &'static str, // "login" | "register"
    pub error: Option<String>,
    pub allow_registration: bool,
    pub local_login_enabled: bool,
    pub oidc_enabled: bool,
}

pub fn login_page(cfg: &InstanceConfig, error: Option<String>) -> LoginPage {
    let (instance_name, tagline, icon_url) = brand(cfg);
    LoginPage {
        instance_name,
        tagline,
        icon_url,
        user: None,
        mode: "login",
        error,
        // Legacy allow_registration is deliberately ignored; registration_mode
        // is the source of truth. The field name remains a login-template concern.
        allow_registration: cfg.registration_mode != "closed",
        local_login_enabled: cfg.allow_local_login,
        oidc_enabled: cfg.allow_oidc,
    }
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub error: Option<String>,
    pub invite_required: bool,
    pub local_login_enabled: bool,
    pub oidc_enabled: bool,
}

pub fn register_page(cfg: &InstanceConfig, error: Option<String>) -> RegisterPage {
    let (instance_name, tagline, icon_url) = brand(cfg);
    RegisterPage {
        instance_name,
        tagline,
        icon_url,
        user: None,
        error,
        invite_required: cfg.registration_mode == "invite",
        local_login_enabled: cfg.allow_local_login,
        oidc_enabled: cfg.allow_oidc,
    }
}
