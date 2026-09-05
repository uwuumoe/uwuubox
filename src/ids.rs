//! Content IDs, extension handling, reserved words, expiry clamping.
//!
//! `id_core` is 8 chars from an unambiguous 32-char alphabet (no `0/O/1/l`).
//! Lookup is exact-match on the core; any URL extension is ignored for lookup
//! and only the stored ext is used for the canonical link.

use rand::RngCore;

/// Single source of truth for core length; bump to 10 if retries ever spike.
pub const ID_LEN: usize = 8;
const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";

/// Router-level static segments that must never resolve as raw file cores.
pub const RESERVED: &[&str] = &[
    "f", "p", "u", "api", "admin", "login", "register", "logout", "oidc", "static", "health",
    "config",
];

pub fn generate_core() -> String {
    let mut buf = [0u8; ID_LEN];
    rand::rng().fill_bytes(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect()
}

/// Lowercase original extension incl. dot, max 10 chars, charset `[a-z0-9.]`.
/// Anything else (missing, too long, weird chars) → `""`.
pub fn normalize_ext(original_name: &str) -> String {
    let base = original_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(original_name);
    let dot = match base.rfind('.') {
        Some(i) if i > 0 => i,
        _ => return String::new(),
    };
    let ext: String = base[dot..].to_lowercase();
    if !(2..=10).contains(&ext.len()) {
        return String::new();
    }
    if ext
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '.'))
    {
        ext
    } else {
        String::new()
    }
}

/// Strip any URL suffix for lookup: cores never contain `.`.
pub fn strip_to_core(segment: &str) -> &str {
    match segment.find('.') {
        Some(i) => &segment[..i],
        None => segment,
    }
}

pub fn is_reserved(word: &str) -> bool {
    RESERVED.contains(&word)
}

/// What the caller wants for content lifetime. `Never` serializes to a NULL
/// `expires_at` (kept until deleted); everything else becomes a timestamp.
/// `Never` is authenticated-users-only: callers pass `allow_never =
/// user.is_some()` so anonymous uploads/pastes stay finite (no quota).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryRequest {
    Default,
    Never,
    InSecs(i64),
}

/// Parse an optional `expires_in_secs` form/multipart field; `Err` → 400.
/// Empty/absent → `Default`; `never` (any case) or `0` → `Never`.
pub fn parse_expiry_param(raw: Option<&str>) -> Result<ExpiryRequest, ()> {
    match raw {
        None => Ok(ExpiryRequest::Default),
        Some(s) if s.trim().is_empty() => Ok(ExpiryRequest::Default),
        Some(s) if s.trim().eq_ignore_ascii_case("never") || s.trim() == "0" => {
            Ok(ExpiryRequest::Never)
        }
        Some(s) => s.trim().parse::<i64>().map(ExpiryRequest::InSecs).map_err(|_| ()),
    }
}

/// JSON variant of [`parse_expiry_param`]: numbers stay seconds (`<= 0` →
/// `Never`), strings follow the form rules, null/absent → `Default`.
pub fn parse_expiry_json(value: Option<&serde_json::Value>) -> Result<ExpiryRequest, ()> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(ExpiryRequest::Default),
        Some(serde_json::Value::Number(n)) => n
            .as_i64()
            .map(|secs| {
                if secs <= 0 {
                    ExpiryRequest::Never
                } else {
                    ExpiryRequest::InSecs(secs)
                }
            })
            .ok_or(()),
        Some(serde_json::Value::String(s)) => parse_expiry_param(Some(s)),
        Some(_) => Err(()),
    }
}

/// Resolve `req` into a concrete lifetime: `None` = never expires.
/// Finite values clamp into `[min, max]`, defaulting when absent.
/// `Never` without `allow_never` → `Err` (caller sends 400).
pub fn clamp_expiry(
    requested: ExpiryRequest,
    min_secs: i64,
    default_secs: i64,
    max_secs: i64,
    allow_never: bool,
) -> Result<Option<i64>, ()> {
    match requested {
        ExpiryRequest::Default => Ok(Some(default_secs)),
        ExpiryRequest::Never if allow_never => Ok(None),
        ExpiryRequest::Never => Err(()),
        ExpiryRequest::InSecs(secs) => Ok(Some(secs.clamp(min_secs, max_secs))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cores_use_unambiguous_alphabet() {
        for _ in 0..200 {
            let c = generate_core();
            assert_eq!(c.len(), ID_LEN);
            assert!(c.bytes().all(|b| ALPHABET.contains(&b)));
            assert!(!c.bytes().any(|b| matches!(b, b'0' | b'O' | b'1' | b'l')));
        }
    }

    #[test]
    fn ext_matrix() {
        assert_eq!(normalize_ext("photo.PNG"), ".png");
        assert_eq!(normalize_ext("archive.tar.gz"), ".gz");
        assert_eq!(normalize_ext("noext"), "");
        assert_eq!(normalize_ext(".hidden"), "");
        assert_eq!(normalize_ext("evil.SH"), ".sh");
        assert_eq!(normalize_ext("a.0123456789x"), ""); // >10 chars
        assert_eq!(normalize_ext("we!rd.e$x"), "");
        assert_eq!(normalize_ext("UPPER.JPEG"), ".jpeg");
    }

    #[test]
    fn ext_stripped_for_lookup() {
        assert_eq!(strip_to_core("abcdefgh"), "abcdefgh");
        assert_eq!(strip_to_core("abcdefgh.png"), "abcdefgh");
        assert_eq!(strip_to_core("abcdefgh.PNG"), "abcdefgh");
        assert_eq!(strip_to_core("abcdefgh.tar.gz"), "abcdefgh");
    }

    #[test]
    fn reserved_words_never_reach_raw() {
        for w in RESERVED {
            assert!(is_reserved(w), "{w} must be reserved");
        }
        assert!(!is_reserved("abcdefgh"));
    }

    #[test]
    fn expiry_clamp_matrix() {
        use ExpiryRequest::{Default, InSecs, Never};
        // min 600 / default 86400 / max 2592000
        let allow = true;
        assert_eq!(clamp_expiry(Default, 600, 86_400, 2_592_000, allow), Ok(Some(86_400)));
        assert_eq!(
            clamp_expiry(InSecs(9), 600, 86_400, 2_592_000, allow),
            Ok(Some(600))
        );
        assert_eq!(
            clamp_expiry(InSecs(600), 600, 86_400, 2_592_000, allow),
            Ok(Some(600))
        );
        assert_eq!(
            clamp_expiry(InSecs(2_592_000), 600, 86_400, 2_592_000, allow),
            Ok(Some(2_592_000))
        );
        assert_eq!(
            clamp_expiry(InSecs(2_678_400), 600, 86_400, 2_592_000, allow),
            Ok(Some(2_592_000))
        );
        assert_eq!(clamp_expiry(Never, 600, 86_400, 2_592_000, true), Ok(None));
        assert_eq!(clamp_expiry(Never, 600, 86_400, 2_592_000, false), Err(()));
    }

    #[test]
    fn expiry_never_parsing() {
        use ExpiryRequest::{Default, InSecs, Never};
        assert_eq!(parse_expiry_param(None), Ok(Default));
        assert_eq!(parse_expiry_param(Some("")), Ok(Default));
        assert_eq!(parse_expiry_param(Some("never")), Ok(Never));
        assert_eq!(parse_expiry_param(Some("NEVER")), Ok(Never));
        assert_eq!(parse_expiry_param(Some("0")), Ok(Never));
        assert_eq!(parse_expiry_param(Some("3600")), Ok(InSecs(3600)));
        assert!(parse_expiry_param(Some("junk")).is_err());
        assert_eq!(
            parse_expiry_json(None),
            Ok(Default)
        );
        assert_eq!(
            parse_expiry_json(Some(&serde_json::Value::Null)),
            Ok(Default)
        );
        assert_eq!(
            parse_expiry_json(Some(&serde_json::json!("never"))),
            Ok(Never)
        );
        assert_eq!(parse_expiry_json(Some(&serde_json::json!(0))), Ok(Never));
        assert_eq!(
            parse_expiry_json(Some(&serde_json::json!(3600))),
            Ok(InSecs(3600))
        );
        assert!(parse_expiry_json(Some(&serde_json::json!(true))).is_err());
    }
}
