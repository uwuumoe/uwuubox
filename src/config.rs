//! Env (`UWUU_` prefixed) + DB-backed instance config overlay.
//!
//! Env carries infra/secrets (never defaulted); branding/limits live in the
//! `instance_config` table, seeded by migration, edited via admin UI.

use std::{collections::HashMap, env, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var {0}")]
    Missing(&'static str),
    #[error("invalid {0}: {1}")]
    Invalid(&'static str, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    Local,
    S3,
}

#[derive(Debug, Clone)]
pub struct Env {
    pub database_url: String,
    pub port: u16,
    pub session_secret: [u8; 32],
    pub storage_backend: StorageBackend,
    pub local_dir: PathBuf,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: String,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub s3_path_style: bool,
    pub oidc_enabled: bool,
    pub oidc_discovery_url: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_url: Option<String>,
    pub base_url: String,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    pub smtp_from: Option<String>,
    pub smtp_starttls: bool,
    pub scan_command: Option<String>,
    pub scan_timeout_secs: u64,
    pub scan_fail_open: bool,
    pub otel_endpoint: Option<String>,
}

fn var(name: &'static str) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(Some(v)),
        Ok(_) => Ok(None),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(ConfigError::Invalid(name, "not valid unicode".into())),
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    var(name)?.ok_or(ConfigError::Missing(name))
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn flag(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match var(name)? {
        None => Ok(default),
        Some(v) => {
            parse_bool(&v).ok_or_else(|| ConfigError::Invalid(name, format!("{v:?} is not a bool")))
        }
    }
}

impl Env {
    pub fn load() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        let database_url = required("UWUU_DATABASE_URL")?;
        let port: u16 = match var("UWUU_PORT")? {
            None => 3000,
            Some(v) => v
                .parse()
                .map_err(|_| ConfigError::Invalid("UWUU_PORT", v.clone()))?,
        };
        let secret_hex = required("UWUU_SESSION_SECRET")?;
        let secret_bytes = hex::decode(secret_hex.trim())
            .map_err(|e| ConfigError::Invalid("UWUU_SESSION_SECRET", e.to_string()))?;
        if secret_bytes.len() != 32 {
            return Err(ConfigError::Invalid(
                "UWUU_SESSION_SECRET",
                format!(
                    "want 64 hex chars (32 bytes), got {} bytes",
                    secret_bytes.len()
                ),
            ));
        }
        let mut session_secret = [0u8; 32];
        session_secret.copy_from_slice(&secret_bytes);

        let storage_backend = match var("UWUU_STORAGE_BACKEND")?
            .as_deref()
            .unwrap_or("local")
            .to_lowercase()
            .as_str()
        {
            "local" => StorageBackend::Local,
            "s3" => StorageBackend::S3,
            other => {
                return Err(ConfigError::Invalid(
                    "UWUU_STORAGE_BACKEND",
                    format!("{other:?}: want local|s3"),
                ));
            }
        };
        let local_dir = var("UWUU_LOCAL_DIR")?
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./data"));
        let s3_endpoint = var("UWUU_S3_ENDPOINT")?;
        let s3_bucket = var("UWUU_S3_BUCKET")?;
        let s3_region = var("UWUU_S3_REGION")?.unwrap_or_else(|| "auto".into());
        let s3_access_key = var("UWUU_S3_ACCESS_KEY")?;
        let s3_secret_key = var("UWUU_S3_SECRET_KEY")?;
        let s3_path_style = flag("UWUU_S3_PATH_STYLE", true)?;
        if storage_backend == StorageBackend::S3 {
            if s3_endpoint.is_none() {
                return Err(ConfigError::Missing("UWUU_S3_ENDPOINT"));
            }
            if s3_bucket.is_none() {
                return Err(ConfigError::Missing("UWUU_S3_BUCKET"));
            }
            if s3_access_key.is_none() {
                return Err(ConfigError::Missing("UWUU_S3_ACCESS_KEY"));
            }
            if s3_secret_key.is_none() {
                return Err(ConfigError::Missing("UWUU_S3_SECRET_KEY"));
            }
        }

        let oidc_enabled = flag("UWUU_OIDC_ENABLED", false)?;
        let oidc_discovery_url = var("UWUU_OIDC_DISCOVERY_URL")?;
        let oidc_client_id = var("UWUU_OIDC_CLIENT_ID")?;
        let oidc_client_secret = var("UWUU_OIDC_CLIENT_SECRET")?;
        let oidc_redirect_url = var("UWUU_OIDC_REDIRECT_URL")?;
        if oidc_enabled {
            if oidc_discovery_url.is_none() {
                return Err(ConfigError::Missing("UWUU_OIDC_DISCOVERY_URL"));
            }
            if oidc_client_id.is_none() {
                return Err(ConfigError::Missing("UWUU_OIDC_CLIENT_ID"));
            }
            if oidc_client_secret.is_none() {
                return Err(ConfigError::Missing("UWUU_OIDC_CLIENT_SECRET"));
            }
            if oidc_redirect_url.is_none() {
                return Err(ConfigError::Missing("UWUU_OIDC_REDIRECT_URL"));
            }
        }
        let base_url = var("UWUU_BASE_URL")?
            .map(|mut u| {
                while u.ends_with('/') {
                    u.pop();
                }
                u
            })
            .unwrap_or_else(|| format!("http://127.0.0.1:{port}"));

        let smtp_host = var("UWUU_SMTP_HOST")?;
        let smtp_port: u16 = match var("UWUU_SMTP_PORT")? {
            None => 587,
            Some(v) => v
                .parse()
                .map_err(|_| ConfigError::Invalid("UWUU_SMTP_PORT", v.clone()))?,
        };
        let smtp_user = var("UWUU_SMTP_USER")?;
        let smtp_pass = var("UWUU_SMTP_PASS")?;
        let smtp_from = var("UWUU_SMTP_FROM")?;
        let smtp_starttls = flag("UWUU_SMTP_STARTTLS", true)?;
        if smtp_host.is_some() && smtp_from.is_none() {
            return Err(ConfigError::Missing("UWUU_SMTP_FROM"));
        }

        let scan_command = var("UWUU_SCAN_COMMAND")?;
        let scan_timeout_secs: u64 = match var("UWUU_SCAN_TIMEOUT_SECS")? {
            None => 30,
            Some(v) => v
                .parse()
                .map_err(|_| ConfigError::Invalid("UWUU_SCAN_TIMEOUT_SECS", v.clone()))?,
        };
        let scan_fail_open = flag("UWUU_SCAN_FAIL_OPEN", false)?;
        let otel_endpoint = var("UWUU_OTEL_ENDPOINT")?;
        Ok(Self {
            database_url,
            port,
            session_secret,
            storage_backend,
            local_dir,
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_access_key,
            s3_secret_key,
            s3_path_style,
            oidc_enabled,
            oidc_discovery_url,
            oidc_client_id,
            oidc_client_secret,
            oidc_redirect_url,
            base_url,
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_pass,
            smtp_from,
            smtp_starttls,
            scan_command,
            scan_timeout_secs,
            scan_fail_open,
            otel_endpoint,
        })
    }
}

/// Branding + limits + toggles. Every limit/toggle in the app reads this.
#[derive(Debug, Clone)]
pub struct InstanceConfig {
    pub instance_name: String,
    pub tagline: String,
    pub icon_url: String,
    pub max_file_bytes: i64,
    pub max_paste_bytes: i64,
    pub max_avatar_bytes: i64,
    pub min_expiry_secs: i64,
    pub max_expiry_secs: i64,
    pub default_expiry_secs: i64,
    pub allow_anonymous: bool,
    pub allow_registration: bool,
    pub allow_local_login: bool,
    pub allow_oidc: bool,
    pub anonymous_max_bytes: i64,
    pub registration_mode: String,
    pub scan_uploads: bool,
    pub block_encrypted_archives: bool,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            instance_name: "uwuubox".into(),
            tagline: String::new(),
            icon_url: String::new(),
            max_file_bytes: 104_857_600,
            max_paste_bytes: 1_048_576,
            max_avatar_bytes: 2_097_152,
            min_expiry_secs: 600,
            max_expiry_secs: 2_592_000,
            default_expiry_secs: 86_400,
            allow_anonymous: true,
            allow_registration: true,
            allow_local_login: true,
            allow_oidc: false,
            anonymous_max_bytes: 26_214_400,
            registration_mode: "open".into(),
            scan_uploads: false,
            block_encrypted_archives: false,
        }
    }
}

impl InstanceConfig {
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        let mut cfg = Self::default();
        let get = |k: &str| map.get(k).map(String::as_str).unwrap_or("");
        if !get("instance_name").is_empty() {
            cfg.instance_name = get("instance_name").to_string();
        }
        // tagline/icon_url may legitimately be empty: presence (not non-emptiness) wins.
        if let Some(v) = map.get("tagline") {
            cfg.tagline = v.clone();
        }
        if let Some(v) = map.get("icon_url") {
            cfg.icon_url = v.clone();
        }
        let num = |k: &str, cur: i64| {
            map.get(k)
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(cur)
        };
        cfg.max_file_bytes = num("max_file_bytes", cfg.max_file_bytes);
        cfg.max_paste_bytes = num("max_paste_bytes", cfg.max_paste_bytes);
        cfg.max_avatar_bytes = num("max_avatar_bytes", cfg.max_avatar_bytes);
        cfg.min_expiry_secs = num("min_expiry_secs", cfg.min_expiry_secs);
        cfg.max_expiry_secs = num("max_expiry_secs", cfg.max_expiry_secs);
        cfg.default_expiry_secs = num("default_expiry_secs", cfg.default_expiry_secs);
        cfg.anonymous_max_bytes = num("anonymous_max_bytes", cfg.anonymous_max_bytes);
        let flag = |k: &str, cur: bool| map.get(k).and_then(|v| parse_bool(v)).unwrap_or(cur);
        cfg.allow_anonymous = flag("allow_anonymous", cfg.allow_anonymous);
        cfg.allow_registration = flag("allow_registration", cfg.allow_registration);
        cfg.allow_local_login = flag("allow_local_login", cfg.allow_local_login);
        cfg.allow_oidc = flag("allow_oidc", cfg.allow_oidc);
        cfg.scan_uploads = flag("scan_uploads", cfg.scan_uploads);
        cfg.block_encrypted_archives = flag("block_encrypted_archives", cfg.block_encrypted_archives);
        if !get("registration_mode").is_empty() {
            cfg.registration_mode = get("registration_mode").to_string();
        }
        cfg
    }

    /// Names the violated inequality on failure (surfaced as 400 by admin UI).
    pub fn validate(&self) -> Result<(), String> {
        if self.instance_name.is_empty() || self.instance_name.len() > 48 {
            return Err("instance_name must be 1..=48 chars".into());
        }
        if self.tagline.len() > 140 {
            return Err("tagline must be <= 140 chars".into());
        }
        if self.icon_url.len() > 512 {
            return Err("icon_url must be <= 512 chars".into());
        }
        if !(self.icon_url.is_empty()
            || self.icon_url.starts_with("https://")
            || self.icon_url.starts_with('/'))
        {
            return Err("icon_url must be https:// or a site-relative path".into());
        }
        for (k, v) in [
            ("max_file_bytes", self.max_file_bytes),
            ("max_paste_bytes", self.max_paste_bytes),
            ("max_avatar_bytes", self.max_avatar_bytes),
            ("min_expiry_secs", self.min_expiry_secs),
            ("max_expiry_secs", self.max_expiry_secs),
            ("default_expiry_secs", self.default_expiry_secs),
            ("anonymous_max_bytes", self.anonymous_max_bytes),
        ] {
            if v <= 0 {
                return Err(format!("{k} must be positive"));
            }
        }
        if self.anonymous_max_bytes > self.max_file_bytes {
            return Err("anonymous_max_bytes <= max_file_bytes violated".into());
        }
        if self.min_expiry_secs > self.default_expiry_secs {
            return Err("min_expiry_secs <= default_expiry_secs violated".into());
        }
        if self.default_expiry_secs > self.max_expiry_secs {
            return Err("default_expiry_secs <= max_expiry_secs violated".into());
        }
        match self.registration_mode.as_str() {
            "open" | "invite" | "closed" => {}
            _ => return Err("registration_mode must be open|invite|closed".into()),
        }
        Ok(())
    }

    pub fn as_pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("instance_name", self.instance_name.clone()),
            ("tagline", self.tagline.clone()),
            ("icon_url", self.icon_url.clone()),
            ("max_file_bytes", self.max_file_bytes.to_string()),
            ("max_paste_bytes", self.max_paste_bytes.to_string()),
            ("max_avatar_bytes", self.max_avatar_bytes.to_string()),
            ("min_expiry_secs", self.min_expiry_secs.to_string()),
            ("max_expiry_secs", self.max_expiry_secs.to_string()),
            ("default_expiry_secs", self.default_expiry_secs.to_string()),
            ("allow_anonymous", self.allow_anonymous.to_string()),
            ("allow_registration", self.allow_registration.to_string()),
            ("allow_local_login", self.allow_local_login.to_string()),
            ("allow_oidc", self.allow_oidc.to_string()),
            ("anonymous_max_bytes", self.anonymous_max_bytes.to_string()),
            ("registration_mode", self.registration_mode.clone()),
            ("scan_uploads", self.scan_uploads.to_string()),
            ("block_encrypted_archives", self.block_encrypted_archives.to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        InstanceConfig::default().validate().unwrap();
    }

    #[test]
    fn inequality_failures_name_the_pair() {
        let mut c = InstanceConfig::default();
        c.anonymous_max_bytes = c.max_file_bytes + 1;
        assert!(c
            .validate()
            .unwrap_err()
            .contains("anonymous_max_bytes <= max_file_bytes"));
        let mut c = InstanceConfig::default();
        c.default_expiry_secs = c.min_expiry_secs - 1;
        assert!(c
            .validate()
            .unwrap_err()
            .contains("min_expiry_secs <= default_expiry_secs"));
        let mut c = InstanceConfig::default();
        c.default_expiry_secs = c.max_expiry_secs + 1;
        assert!(c
            .validate()
            .unwrap_err()
            .contains("default_expiry_secs <= max_expiry_secs"));
    }
}
