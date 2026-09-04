//! Passwords (Argon2id), usernames, API/delete tokens, session helpers.
//!
//! Token hashes are peppered with `SESSION_SECRET`: a DB read alone never
//! suffices to forge a bearer token or delete token.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const SESSION_USER_ID: &str = "uid";
const TOKEN_ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Reserved at the auth layer (profile paths + support-looking names).
pub const USERNAME_RESERVED: &[&str] = &["admin", "root", "system", "api", "support"];

pub fn hash_password(pw: &str) -> Result<String, String> {
    if pw.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    if pw.len() > 72 {
        return Err("password must be at most 72 bytes".into());
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(hash: &str, pw: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(pw.as_bytes(), &parsed)
        .is_ok()
}

/// 3–24 chars `[a-z0-9_]`; lowercase enforced so profile URLs are canonical.
pub fn validate_username(name: &str) -> Result<String, &'static str> {
    if !(3..=24).contains(&name.len()) {
        return Err("username must be 3-24 characters");
    }
    if !name
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
    {
        return Err("username may only contain a-z, 0-9, _");
    }
    if USERNAME_RESERVED.contains(&name) {
        return Err("that username is reserved");
    }
    Ok(name.to_string())
}

/// Sanitize an OIDC `preferred_username` into a registrable base name.
pub fn oidc_base_username(preferred: &str) -> String {
    let mut s: String = preferred
        .to_lowercase()
        .chars()
        .map(|c| {
            if matches!(c, 'a'..='z' | '0'..='9' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.truncate(20);
    s = s.trim_matches('_').to_string();
    if s.len() < 3 {
        s = format!("user-{s}");
    }
    if USERNAME_RESERVED.contains(&s.as_str()) {
        s.push_str("_uwu");
    }
    s
}

fn random_alnum(n: usize) -> String {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| {
            let i: usize = rng.random_range(0..TOKEN_ALPHABET.len());
            TOKEN_ALPHABET[i] as char
        })
        .collect()
}

pub fn new_api_token() -> String {
    format!("uwu_{}", random_alnum(32))
}

pub fn new_delete_token() -> String {
    format!("uwu-del-{}", random_alnum(32))
}

pub fn new_reset_token() -> String {
    format!("uwu-rst-{}", random_alnum(32))
}

pub fn peppered_hash(domain: &str, secret: &[u8; 32], token: &str) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(secret);
    h.update([0u8]);
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub fn api_token_hash(secret: &[u8; 32], token: &str) -> String {
    peppered_hash("api-token-v1", secret, token)
}

pub fn delete_token_hash(secret: &[u8; 32], token: &str) -> String {
    peppered_hash("delete-token-v1", secret, token)
}

pub fn reset_token_hash(secret: &[u8; 32], token: &str) -> String {
    peppered_hash("reset-v1", secret, token)
}

pub fn tokens_equal(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub fn is_api_token_format(token: &str) -> bool {
    token.len() == 36
        && token.starts_with("uwu_")
        && token[4..]
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
}

pub fn new_user_id() -> Uuid {
    Uuid::now_v7()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip_and_policy() {
        let h = hash_password("correct horse 123").unwrap();
        assert!(verify_password(&h, "correct horse 123"));
        assert!(!verify_password(&h, "wrong"));
        assert!(hash_password("short").is_err());
        assert!(hash_password(&"x".repeat(73)).is_err());
    }

    #[test]
    fn username_matrix() {
        assert!(validate_username("ashley_01").is_ok());
        assert!(validate_username("ab").is_err());
        assert!(validate_username("Ashley").is_err());
        assert!(validate_username("has-dash").is_err());
        assert!(validate_username("admin").is_err());
    }

    #[test]
    fn oidc_first_login_derives_safe_name() {
        // OIDC link-on-first-login: weird IdP names collapse to a valid base.
        assert_eq!(oidc_base_username("Ashley Lee!"), "ashley_lee");
        assert_eq!(oidc_base_username("a"), "user-a");
        assert_eq!(oidc_base_username("admin"), "admin_uwu");
    }

    #[test]
    fn token_hash_is_peppered() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let t = new_api_token();
        assert!(is_api_token_format(&t));
        assert_ne!(api_token_hash(&s1, &t), api_token_hash(&s2, &t));
        assert!(tokens_equal(
            &api_token_hash(&s1, &t),
            &api_token_hash(&s1, &t)
        ));
        assert!(!tokens_equal(
            &api_token_hash(&s1, &t),
            &api_token_hash(&s2, &t)
        ));
    }

    #[test]
    fn reset_tokens_have_a_separate_domain() {
        let secret = [7u8; 32];
        let token = new_reset_token();
        assert_eq!(token.len(), 40);
        assert!(token.starts_with("uwu-rst-"));
        assert!(token[8..].bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_ne!(
            reset_token_hash(&secret, &token),
            api_token_hash(&secret, &token)
        );
    }
}
