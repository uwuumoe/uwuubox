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

/// Clamp `expires_in_secs` into `[min, max]`, defaulting when absent.
pub fn clamp_expiry(
    requested: Option<i64>,
    min_secs: i64,
    default_secs: i64,
    max_secs: i64,
) -> i64 {
    requested.unwrap_or(default_secs).clamp(min_secs, max_secs)
}

/// Parse an optional `expires_in_secs` form/JSON field; `Err` → caller sends 400.
pub fn parse_expiry_param(raw: Option<&str>) -> Result<Option<i64>, ()> {
    match raw {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => s.trim().parse::<i64>().map(Some).map_err(|_| ()),
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
        // min 600 / default 86400 / max 2592000
        assert_eq!(clamp_expiry(None, 600, 86_400, 2_592_000), 86_400);
        assert_eq!(clamp_expiry(Some(9), 600, 86_400, 2_592_000), 600);
        assert_eq!(clamp_expiry(Some(600), 600, 86_400, 2_592_000), 600);
        assert_eq!(
            clamp_expiry(Some(2_592_000), 600, 86_400, 2_592_000),
            2_592_000
        );
        assert_eq!(
            clamp_expiry(Some(2_678_400), 600, 86_400, 2_592_000),
            2_592_000
        );
    }
}
