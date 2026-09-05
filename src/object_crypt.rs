//! Transparent per-object encryption for the object store.
//!
//! When `UWUU_STORAGE_ENCRYPTION_KEY` is set, [`Store`](crate::storage::Store)
//! seals every object with XChaCha20-Poly1305 before `put` and opens it after
//! `get`. Wire format: `MAGIC || 24-byte nonce || ciphertext+tag` (44 bytes
//! overhead). Objects without the magic prefix are legacy plaintext and read
//! back raw, so enabling the key never breaks pre-existing objects.

use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Magic prefix identifying a sealed object.
pub const MAGIC: &[u8; 4] = b"UWU1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// `MAGIC + nonce + AEAD tag` overhead per stored object.
pub const OVERHEAD: usize = 4 + NONCE_LEN + TAG_LEN;

pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC[..]
}

/// Parse the `UWUU_STORAGE_ENCRYPTION_KEY` value: 64 hex chars (32 bytes).
pub fn parse_key(raw: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(raw.trim()).map_err(|e| format!("want 64 hex chars (32 bytes): {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "want 64 hex chars (32 bytes), got {} bytes",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Bytes {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .expect("XChaCha20-Poly1305 seal cannot fail");
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Bytes::from(out)
}

/// Open a sealed object. Fails closed (no plaintext) on wrong key,
/// truncation, or tampering.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Bytes, String> {
    if !is_encrypted(sealed) || sealed.len() < OVERHEAD {
        return Err("object decrypt failed".into());
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&sealed[MAGIC.len()..MAGIC.len() + NONCE_LEN]),
            &sealed[MAGIC.len() + NONCE_LEN..],
        )
        .map(Bytes::from)
        .map_err(|_| "object decrypt failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn roundtrip() {
        let k = key(7);
        let pt = b"hello, uwuubox";
        let sealed = seal(&k, pt);
        assert!(is_encrypted(&sealed));
        assert_eq!(sealed.len(), OVERHEAD + pt.len());
        assert_ne!(&sealed[OVERHEAD..], &pt[..]);
        assert_eq!(&open(&k, &sealed).unwrap()[..], &pt[..]);
    }

    #[test]
    fn nonces_differ() {
        let k = key(1);
        assert_ne!(&seal(&k, b"same")[..], &seal(&k, b"same")[..]);
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = seal(&key(1), b"secret");
        assert!(open(&key(2), &sealed).is_err());
    }

    #[test]
    fn tamper_and_truncation_fail() {
        let k = key(3);
        let mut sealed = seal(&k, b"tamper me").to_vec();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&k, &sealed).is_err());
        let sealed = seal(&k, b"cut me");
        assert!(open(&k, &sealed[..sealed.len() - 1]).is_err());
        assert!(open(&k, b"UWU1short").is_err());
    }

    #[test]
    fn legacy_bytes_are_not_encrypted() {
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"UWU"));
        assert!(!is_encrypted(b"plain object bytes"));
        assert!(open(&key(9), b"plain object bytes").is_err());
    }

    #[test]
    fn key_parsing_matches_session_secret_convention() {
        let hex_key = "ab".repeat(32);
        assert_eq!(parse_key(&hex_key).unwrap(), [0xabu8; 32]);
        assert!(parse_key("xyz").is_err());
        assert!(parse_key(&"ab".repeat(31)).is_err());
    }
}
