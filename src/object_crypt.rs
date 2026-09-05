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

// ---- v2: chunked STREAM encryption for large objects ----
//
// The v1 format above needs the whole plaintext (and ciphertext) in RAM,
// which OOMs the pod on ~GB uploads. V2 splits the plaintext into
// independently-sealed chunks so both PUT and GET stream in bounded memory:
//
// ```text
// header: MAGIC_V2(4) || chunk_pt_len u32 BE(4) || base_nonce(16)
// chunk i: seal(key, base16 || i u64 BE, pt[i*chunk_pt .. (i+1)*chunk_pt])
// ```
//
// Nonce uniqueness holds per object (random 128-bit base, unique index);
// tamper/reorder fails the per-chunk Poly1305 tag; truncation is caught by
// checking the chunk count against the DB-authoritative plaintext length.

/// Magic prefix identifying a v2 stream-sealed object.
pub const MAGIC_V2: &[u8; 4] = b"UWU2";
/// Plaintext bytes per v2 chunk. Sealed chunks are this +16, keeping every
/// non-final S3 multipart part above the 5 MiB minimum.
pub const STREAM_CHUNK_PT: usize = 8 * 1024 * 1024;
/// `MAGIC_V2 + chunk_pt_len + base_nonce` header length.
pub const STREAM_HEADER_LEN: usize = 4 + 4 + 16;
const BASE_LEN: usize = 16;

pub fn is_stream_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC_V2.len() && bytes[..MAGIC_V2.len()] == MAGIC_V2[..]
}

/// Fresh random 128-bit base nonce for one object.
pub fn stream_base() -> [u8; BASE_LEN] {
    let mut base = [0u8; BASE_LEN];
    rand::rng().fill_bytes(&mut base);
    base
}

pub fn stream_header(chunk_pt: u32, base: &[u8; BASE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(STREAM_HEADER_LEN);
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&chunk_pt.to_be_bytes());
    out.extend_from_slice(base);
    out
}

/// Parse a v2 header: `(chunk_pt_bytes, base_nonce)`.
pub fn parse_stream_header(header: &[u8]) -> Result<(usize, [u8; BASE_LEN]), String> {
    if header.len() < STREAM_HEADER_LEN || !is_stream_sealed(header) {
        return Err("not a v2 stream object".into());
    }
    let chunk_pt = u32::from_be_bytes(header[4..8].try_into().map_err(|_| "bad v2 header")?);
    if chunk_pt == 0 || chunk_pt as usize > 64 * 1024 * 1024 {
        return Err("bad v2 chunk size".into());
    }
    let mut base = [0u8; BASE_LEN];
    base.copy_from_slice(&header[8..8 + BASE_LEN]);
    Ok((chunk_pt as usize, base))
}

fn stream_nonce(base: &[u8; BASE_LEN], index: u64) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(NONCE_LEN);
    nonce.extend_from_slice(base);
    nonce.extend_from_slice(&index.to_be_bytes());
    nonce
}

pub fn seal_chunk(
    key: &[u8; 32],
    base: &[u8; BASE_LEN],
    index: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(&stream_nonce(base, index)), plaintext)
        .expect("XChaCha20-Poly1305 seal cannot fail")
}

pub fn open_chunk(
    key: &[u8; 32],
    base: &[u8; BASE_LEN],
    index: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&stream_nonce(base, index)),
            sealed,
        )
        .map_err(|_| "stream chunk decrypt failed".into())
}

/// Number of v2 chunks covering `pt_len` plaintext bytes.
pub fn stream_chunk_count(pt_len: u64, chunk_pt: usize) -> u64 {
    let chunk_pt = chunk_pt as u64;
    pt_len.div_ceil(chunk_pt)
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

    fn seal_stream(k: &[u8; 32], chunks: &[Vec<u8>]) -> (Vec<u8>, [u8; BASE_LEN]) {
        let base = stream_base();
        let mut out = stream_header(STREAM_CHUNK_PT as u32, &base);
        for (i, chunk) in chunks.iter().enumerate() {
            out.extend_from_slice(&seal_chunk(k, &base, i as u64, chunk));
        }
        (out, base)
    }

    #[test]
    fn stream_roundtrip_multiple_chunks() {
        let k = key(11);
        let chunks = vec![vec![1u8; STREAM_CHUNK_PT], vec![2u8; 100], vec![]];
        let (sealed, base) = seal_stream(&k, &chunks);
        let (chunk_pt, parsed_base) = parse_stream_header(&sealed[..STREAM_HEADER_LEN]).unwrap();
        assert_eq!((chunk_pt, parsed_base), (STREAM_CHUNK_PT, base));
        assert!(is_stream_sealed(&sealed));
        assert!(!is_encrypted(&sealed));
        let mut off = STREAM_HEADER_LEN;
        for (i, want) in chunks.iter().enumerate() {
            let n = want.len() + TAG_LEN;
            let got = open_chunk(&k, &base, i as u64, &sealed[off..off + n]).unwrap();
            assert_eq!(&got, want);
            off += n;
        }
        assert_eq!(off, sealed.len());
    }

    #[test]
    fn stream_chunk_tamper_reorder_wrong_index_fail() {
        let k = key(12);
        let (sealed, base) = seal_stream(&k, &[vec![9u8; 50], vec![8u8; 50]]);
        let first = STREAM_HEADER_LEN;
        let second = first + 50 + TAG_LEN;
        // Flip a ciphertext byte in chunk 0.
        let mut tampered = sealed.clone();
        tampered[first] ^= 1;
        assert!(open_chunk(&k, &base, 0, &tampered[first..second]).is_err());
        // Correct bytes under the wrong index fail (binds position).
        assert!(open_chunk(&k, &base, 1, &sealed[first..second]).is_err());
        // Wrong key fails closed.
        assert!(open_chunk(&key(13), &base, 0, &sealed[first..second]).is_err());
        // Truncated chunk fails.
        assert!(open_chunk(&k, &base, 0, &sealed[first..second - 1]).is_err());
        // Bogus headers rejected.
        assert!(parse_stream_header(b"UWU2").is_err());
        assert!(parse_stream_header(b"plain object bytes....1234").is_err());
    }

    #[test]
    fn stream_chunk_count_covers_remainder() {
        assert_eq!(stream_chunk_count(0, STREAM_CHUNK_PT), 0);
        assert_eq!(stream_chunk_count(1, STREAM_CHUNK_PT), 1);
        assert_eq!(
            stream_chunk_count(STREAM_CHUNK_PT as u64, STREAM_CHUNK_PT),
            1
        );
        assert_eq!(
            stream_chunk_count(STREAM_CHUNK_PT as u64 + 1, STREAM_CHUNK_PT),
            2
        );
    }
}
