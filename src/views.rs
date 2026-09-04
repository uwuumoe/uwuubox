//! Askama page models. Every page carries the branding fields the layout
//! needs (`extends` shares the child context, so parents can't add their own).

use askama::Template;
use chrono::{DateTime, Utc};

use crate::{
    config::InstanceConfig,
    db::{FileRow, PasteRow, TokenInfo, User},
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
}

impl IndexPage {
    pub fn new(cfg: &InstanceConfig, user: Option<User>, base_url: &str) -> Self {
        Self {
            instance_name: cfg.instance_name.clone(),
            tagline: cfg.tagline.clone(),
            icon_url: cfg.icon_url.clone(),
            user,
            allow_anonymous: cfg.allow_anonymous,
            max_file_human: human_bytes(cfg.max_file_bytes),
            base_url: base_url.to_string(),
            max_expiry_secs: cfg.max_expiry_secs,
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
    pub title: String,
    pub highlighted: String,
    pub highlight_css: String,
    pub language: String,
    pub expires_human: String,
    pub owner_name: Option<String>,
    pub raw_url: String,
    pub desc: String,
}

#[derive(Template)]
#[template(path = "paste_new.html")]
pub struct PasteNewPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub authed: bool,
    pub max_paste_bytes: i64,
    pub max_expiry_secs: i64,
}

impl PasteNewPage {
    pub fn new(cfg: &InstanceConfig, user: Option<User>) -> Self {
        Self {
            authed: user.is_some(),
            max_paste_bytes: cfg.max_paste_bytes,
            max_expiry_secs: cfg.max_expiry_secs,
            instance_name: cfg.instance_name.clone(),
            tagline: cfg.tagline.clone(),
            icon_url: cfg.icon_url.clone(),
            user,
        }
    }
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
    pub just_created_token: Option<String>,
    pub oidc_enabled: bool,
    pub oidc_linked: bool,
    pub avatar_url: Option<String>,
    pub base_url: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct AdminPage {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub user: Option<User>,
    pub cfg: InstanceConfig,
    pub users: Vec<User>,
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
        allow_registration: cfg.allow_registration,
        oidc_enabled: cfg.allow_oidc,
    }
}

pub fn register_page(cfg: &InstanceConfig, error: Option<String>) -> LoginPage {
    let mut p = login_page(cfg, error);
    p.mode = "register";
    p
}
