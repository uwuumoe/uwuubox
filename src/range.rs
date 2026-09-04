//! Single-range HTTP byte parsing and response construction.

use axum::{
    body::Body,
    http::{
        header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE},
        Response, StatusCode,
    },
};
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOutcome {
    Full,
    Satisfiable { start: u64, end: u64 },
    Invalid,
    Unsatisfiable,
}

fn decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

pub fn parse(header: Option<&str>, len: u64) -> RangeOutcome {
    let Some(header) = header else {
        return RangeOutcome::Full;
    };
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Invalid;
    };
    if spec.is_empty() || spec.contains(',') || spec.chars().any(char::is_whitespace) {
        return RangeOutcome::Invalid;
    }

    let Some((first, last)) = spec.split_once('-') else {
        return RangeOutcome::Invalid;
    };
    if first.is_empty() {
        let Some(suffix_len) = decimal(last) else {
            return RangeOutcome::Invalid;
        };
        if suffix_len == 0 || len == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        let start = len.saturating_sub(suffix_len);
        return RangeOutcome::Satisfiable {
            start,
            end: len - 1,
        };
    }

    let Some(start) = decimal(first) else {
        return RangeOutcome::Invalid;
    };
    let requested_end = if last.is_empty() {
        None
    } else {
        let Some(end) = decimal(last) else {
            return RangeOutcome::Invalid;
        };
        if end < start {
            return RangeOutcome::Invalid;
        }
        Some(end)
    };
    if len == 0 || start >= len {
        return RangeOutcome::Unsatisfiable;
    }
    let end = requested_end.unwrap_or(len - 1).min(len - 1);
    RangeOutcome::Satisfiable { start, end }
}

/// Build the status/body and range-specific headers. Callers may add content
/// type, disposition, caching, and security headers to the returned response.
pub fn response(outcome: RangeOutcome, full_len: u64, body: Bytes) -> Response<Body> {
    let builder = Response::builder().header(ACCEPT_RANGES, "bytes");
    match outcome {
        RangeOutcome::Full => builder
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, body.len())
            .body(Body::from(body)),
        RangeOutcome::Satisfiable { start, end } => builder
            .status(StatusCode::PARTIAL_CONTENT)
            .header(CONTENT_RANGE, format!("bytes {start}-{end}/{full_len}"))
            .header(CONTENT_LENGTH, body.len())
            .body(Body::from(body)),
        RangeOutcome::Invalid => builder
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_LENGTH, 0)
            .body(Body::empty()),
        RangeOutcome::Unsatisfiable => builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(CONTENT_RANGE, format!("bytes */{full_len}"))
            .header(CONTENT_LENGTH, 0)
            .body(Body::empty()),
    }
    .expect("static range response headers are valid")
}

#[cfg(test)]
mod tests {
    use super::{parse, RangeOutcome};

    #[test]
    fn parses_supported_single_ranges() {
        assert_eq!(parse(None, 10), RangeOutcome::Full);
        assert_eq!(
            parse(Some("bytes=3-"), 10),
            RangeOutcome::Satisfiable { start: 3, end: 9 }
        );
        assert_eq!(
            parse(Some("bytes=3-6"), 10),
            RangeOutcome::Satisfiable { start: 3, end: 6 }
        );
        assert_eq!(
            parse(Some("bytes=3-99"), 10),
            RangeOutcome::Satisfiable { start: 3, end: 9 }
        );
        assert_eq!(
            parse(Some("bytes=-4"), 10),
            RangeOutcome::Satisfiable { start: 6, end: 9 }
        );
        assert_eq!(
            parse(Some("bytes=-99"), 10),
            RangeOutcome::Satisfiable { start: 0, end: 9 }
        );
    }

    #[test]
    fn distinguishes_invalid_from_unsatisfiable() {
        for header in [
            "items=0-1",
            "bytes=",
            "bytes=1",
            "bytes=1-0",
            "bytes=99-1",
            "bytes=1-2,4-5",
            "bytes= 1-2",
            "bytes=a-b",
            "bytes=+1-2",
        ] {
            assert_eq!(parse(Some(header), 10), RangeOutcome::Invalid, "{header}");
        }
        for header in ["bytes=10-", "bytes=99-100", "bytes=-0"] {
            assert_eq!(
                parse(Some(header), 10),
                RangeOutcome::Unsatisfiable,
                "{header}"
            );
        }
        assert_eq!(
            parse(Some("bytes=0-"), 0),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(parse(Some("bytes=-1"), 0), RangeOutcome::Unsatisfiable);
    }
}
