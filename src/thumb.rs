//! Video thumbnails for link embeds.
//!
//! Chat crawlers (notably Discord) download the whole `og:video` file before
//! embedding, so videos above [`EMBED_VIDEO_MAX_BYTES`] never embed — the
//! debugger just reports "timed out". For those, crawlers get a thumbnail
//! card instead: a real frame with a play-button overlay, extracted by
//! ffmpeg at upload time (and lazily, in the background, for older rows).
//!
//! Thumbnails are never made for burn-after-read or password-protected
//! videos: a public first frame would leak both protections.

use std::path::Path;
use std::time::Duration;

/// Above this, crawlers get a thumbnail card instead of `og:video`.
/// 25 MiB matches Discord's reliable remote-embed ceiling; humans always
/// get the full video regardless.
pub const EMBED_VIDEO_MAX_BYTES: i64 = 25 * 1024 * 1024;

/// Embeddable video types we thumbnail (ffmpeg-decodable, see
/// [`crate::mime::is_embeddable_video`]).
pub fn thumbnailed_mime(mime: &str) -> bool {
    crate::mime::is_embeddable_video(mime)
}

/// Link-preview crawlers that fetch embeds with tight size/time budgets.
pub fn embed_crawler(user_agent: Option<&str>) -> bool {
    const BOTS: &[&str] = &[
        "discordbot",
        "twitterbot",
        "facebookexternalhit",
        "slackbot",
        "telegrambot",
        "whatsapp",
        "linkedinbot",
    ];
    let ua = user_agent.unwrap_or_default().to_ascii_lowercase();
    BOTS.iter().any(|bot| ua.contains(bot))
}

#[derive(Debug, thiserror::Error)]
pub enum ThumbError {
    #[error("ffmpeg not available: {0}")]
    Unavailable(String),
    #[error("ffmpeg failed: {0}")]
    Failed(String),
    #[error("bad image: {0}")]
    Image(String),
}

/// Extract one frame with ffmpeg and overlay a play button. Returns JPEG
/// bytes. Missing/broken ffmpeg is a clean `Err`, never a panic: callers
/// treat it as "no thumbnail" and keep the old behavior.
pub async fn generate_video_thumb(src: &Path, ffmpeg: &str) -> Result<Vec<u8>, ThumbError> {
    let mut command = tokio::process::Command::new(ffmpeg);
    command
        .arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-ss")
        .arg("1")
        .arg("-i")
        .arg(src)
        .arg("-frames:v")
        .arg("1")
        .arg("-vf")
        .arg("scale=640:-2")
        .arg("-f")
        .arg("image2")
        .arg("-vcodec")
        .arg("mjpeg")
        .arg("pipe:1")
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .map_err(|_| ThumbError::Failed("timeout".into()))?
        .map_err(|error| ThumbError::Unavailable(error.to_string()))?;
    if !output.status.success() || output.stdout.is_empty() {
        let detail: String = String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(200)
            .collect();
        return Err(ThumbError::Failed(detail));
    }
    overlay_play_button(&output.stdout)
}

/// Center a translucent play button over decoded JPEG bytes, re-encode.
/// Pure pixel math so no extra imaging deps beyond jpeg decode/encode.
pub fn overlay_play_button(jpeg: &[u8]) -> Result<Vec<u8>, ThumbError> {
    use image::ExtendedColorType;
    let img = image::load_from_memory(jpeg).map_err(|error| ThumbError::Image(error.to_string()))?;
    let rgb = img.to_rgb8();
    let (width, height) = rgb.dimensions();
    if width == 0 || height == 0 {
        return Err(ThumbError::Image("empty frame".into()));
    }
    let mut buf = rgb.into_raw();
    let stride = width as usize * 3;
    let cx = width as f32 / 2.0;
    let cy = height as f32 / 2.0;
    let radius = width.min(height) as f32 / 6.0;
    // Right-pointing triangle: apex right, flat edge left.
    let (ax, ay) = (cx + 0.65 * radius, cy);
    let (bx, by) = (cx - 0.45 * radius, cy - 0.60 * radius);
    let (cx2, cy2) = (cx - 0.45 * radius, cy + 0.60 * radius);
    let sign = |x: f32, y: f32, ux: f32, uy: f32, vx: f32, vy: f32| {
        (x - vx) * (uy - vy) - (ux - vx) * (y - vy)
    };
    for y in 0..height {
        for x in 0..width {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let dx = fx - cx;
            let dy = fy - cy;
            if dx * dx + dy * dy > radius * radius {
                continue;
            }
            let d1 = sign(fx, fy, ax, ay, bx, by);
            let d2 = sign(fx, fy, bx, by, cx2, cy2);
            let d3 = sign(fx, fy, cx2, cy2, ax, ay);
            let in_triangle =
                (d1 < 0.0 && d2 < 0.0 && d3 < 0.0) || (d1 > 0.0 && d2 > 0.0 && d3 > 0.0);
            let idx = y as usize * stride + x as usize * 3;
            if in_triangle {
                buf[idx] = 255;
                buf[idx + 1] = 255;
                buf[idx + 2] = 255;
            } else {
                // Translucent black disc so the button reads on bright frames.
                for c in 0..3 {
                    let v = buf[idx + c] as u32;
                    buf[idx + c] = (v * 140 / 255) as u8;
                }
            }
        }
    }
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 82)
        .encode(&buf, width, height, ExtendedColorType::Rgb8)
        .map_err(|error| ThumbError::Image(error.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_jpeg(width: u32, height: u32, px: [u8; 3]) -> Vec<u8> {
        let buf = vec![px[0], px[1], px[2]]
            .into_iter()
            .cycle()
            .take(width as usize * height as usize * 3)
            .collect::<Vec<_>>();
        let mut out = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 90)
            .encode(&buf, width, height, image::ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    #[test]
    fn overlay_keeps_size_marks_center_spares_corners() {
        use image::GenericImageView;
        let before = solid_jpeg(640, 360, [200, 40, 40]);
        let after = overlay_play_button(&before).unwrap();
        let img = image::load_from_memory(&after).unwrap().to_rgb8();
        assert_eq!(img.dimensions(), (640, 360));
        // Center pixel is inside the white triangle.
        let center = img.get_pixel(320, 180);
        assert!(center.0.iter().all(|c| *c > 200), "{center:?}");
        // Corners keep the darkened-but-red frame, far from white.
        let corner = img.get_pixel(4, 4);
        assert!(corner.0[0] > corner.0[1] + 40, "{corner:?}");
    }

    #[test]
    fn overlay_rejects_garbage() {
        assert!(overlay_play_button(b"not a jpeg").is_err());
    }

    #[test]
    fn crawler_match_matrix() {
        assert!(embed_crawler(Some(
            "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
        )));
        assert!(embed_crawler(Some("TelegramBot (like TwitterBot)")));
        assert!(embed_crawler(Some("facebookexternalhit/1.1")));
        assert!(!embed_crawler(Some(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36"
        )));
        assert!(!embed_crawler(None));
    }

    #[tokio::test]
    async fn missing_ffmpeg_is_a_clean_skip() {
        let dir = std::env::temp_dir();
        let src = dir.join("uwuubox-thumb-test-missing-input");
        assert!(matches!(
            generate_video_thumb(&src, "/nonexistent/ffmpeg-bin").await,
            Err(ThumbError::Unavailable(_))
        ));
    }
}
