//! Prometheus metrics: uploads, bytes, sweeper runs, HTTP status classes.
//!
//! Handlers bump counters; `GET /metrics` renders the registry. Labels stay
//! low-cardinality on purpose (no per-user/per-file labels).

use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    /// `status`: ok | too_large | rejected | rate_limited | error
    pub uploads: IntCounterVec,
    pub upload_bytes: IntCounter,
    /// `status`: ok | too_large | rejected | error
    pub pastes: IntCounterVec,
    pub sweeper_runs: IntCounter,
    pub files_swept: IntCounter,
    pub pastes_swept: IntCounter,
    /// `class`: 2xx | 4xx | 5xx
    pub http: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let mk_vec = |name: &str, help: &str, labels: &[&str]| {
            let v = IntCounterVec::new(Opts::new(name, help), labels)?;
            registry.register(Box::new(v.clone()))?;
            Ok::<_, prometheus::Error>(v)
        };
        let mk = |name: &str, help: &str| {
            let c = IntCounter::new(name, help)?;
            registry.register(Box::new(c.clone()))?;
            Ok::<_, prometheus::Error>(c)
        };
        Ok(Self {
            uploads: mk_vec("uwuubox_uploads_total", "file uploads by outcome", &["status"])?,
            upload_bytes: mk("uwuubox_upload_bytes_total", "uploaded file bytes accepted")?,
            pastes: mk_vec("uwuubox_pastes_total", "paste creates by outcome", &["status"])?,
            sweeper_runs: mk("uwuubox_sweeper_runs_total", "expiry sweeper passes")?,
            files_swept: mk("uwuubox_files_swept_total", "expired files removed")?,
            pastes_swept: mk("uwuubox_pastes_swept_total", "expired pastes removed")?,
            http: mk_vec(
                "uwuubox_http_responses_total",
                "responses by status class",
                &["class"],
            )?,
            registry,
        })
    }

    pub fn render(&self) -> String {
        let families = self.registry.gather();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&families, &mut buf).unwrap_or(());
        String::from_utf8(buf).unwrap_or_default()
    }
}
