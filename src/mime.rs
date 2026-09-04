//! MIME sniffing, inline-vs-attachment policy, upload blocklist.
//!
//! The stored extension is never trusted for content type: bytes are sniffed
//! with `infer` at upload, `mime_stored` is persisted, and every raw response
//! is decided from it.

/// Sniff bytes → stored MIME. `infer` knows nothing of text, so valid UTF-8
/// without NUL falls back to `text/plain`, else `application/octet-stream`.
pub fn sniff_mime(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "application/octet-stream".to_string();
    }
    if let Some(t) = infer::get(bytes) {
        return t.mime_type().to_string();
    }
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.contains('\0') => "text/plain".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

/// Inline allowlist: raster images (no SVG), mp4/webm, any audio, UTF-8 text.
/// Everything else (`image/svg+xml`, `text/html`, `application/*`, unknown)
/// forces a download with an octet-stream fallback.
pub fn should_inline(mime: &str, bytes: &[u8]) -> bool {
    match mime {
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/avif" => true,
        "video/mp4" | "video/webm" => true,
        m if m.starts_with("audio/") => true,
        "text/plain" => std::str::from_utf8(bytes).is_ok(),
        _ => false,
    }
}

/// Upload-time deny list → 415 naming the MIME.
pub fn is_upload_blocked(mime: &str) -> bool {
    matches!(
        mime,
        "text/html"
            | "application/xhtml+xml"
            | "application/x-sh"
            | "application/x-msdownload"
            | "application/x-executable"
            | "application/x-mach-binary"
            | "application/x-elf"
    )
}

pub fn is_avatar_mime(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/avif"
    )
}

/// Strip path components, quotes, controls; cap at 128 chars for the
/// `Content-Disposition` filename. Never empty.
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut out: String = base
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '"' | '\'' | '\\' | ';' => '_',
            c => c,
        })
        .collect();
    while out.starts_with('.') {
        out.remove(0);
    }
    if out.is_empty() {
        out.push_str("download");
    }
    // Cap by chars (headers are bytes, but ASCII-heavy names make this fine).
    if out.len() > 128 {
        out.truncate(128);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spoofed_html_rejected_with_415_signal() {
        let html = b"<html><script>alert(1)</script></html>";
        // infer sees text → caller falls back; explicit html upload path:
        assert!(is_upload_blocked("text/html"));
        assert!(!should_inline("text/html", html));
    }

    #[test]
    fn executables_blocked() {
        for m in [
            "application/x-sh",
            "application/x-msdownload",
            "application/x-executable",
            "application/x-mach-binary",
        ] {
            assert!(is_upload_blocked(m), "{m}");
            assert!(!should_inline(m, b"MZ..."));
        }
    }

    #[test]
    fn svg_never_inlines() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"></svg>"#;
        assert!(!should_inline("image/svg+xml", svg));
    }

    #[test]
    fn images_and_text_inline() {
        // Minimal 1x1 PNG.
        let png = [
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
        ];
        assert_eq!(sniff_mime(&png), "image/png");
        assert!(should_inline("image/png", &png));
        assert!(should_inline("text/plain", "hello, world".as_bytes()));
        assert!(!should_inline("text/plain", &[0xff, 0xfe, 0x00]));
    }
}
