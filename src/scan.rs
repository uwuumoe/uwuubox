//! Optional external malware/secret scanning hook for uploads.
//!
//! When `scan_uploads` is on and `UWUU_SCAN_COMMAND` is set, each uploaded
//! file is written to a temp file and the command is executed as
//! `{cmd} {temp_path} {mime}` with `UWUU_SCAN_TIMEOUT_SECS` timeout:
//! exit 0 = clean, exit 3 = infected (rejected with 422), anything else =
//! error (fail-open allows, fail-closed rejects, per `UWUU_SCAN_FAIL_OPEN`).
//! `Skipped` (toggle off or no command) stores `scan_status = 'skipped'`.
//!
//! The temp file is removed before this returns, whatever the outcome.

use crate::config::Env;

pub enum Verdict {
    Clean,
    Infected(String),
    Skipped,
}

// Placeholder until the scanning-hooks slice lands the implementation.
pub async fn verdict(_env: &Env, _filename: &str, _bytes: &[u8], _mime: &str) -> Verdict {
    Verdict::Skipped
}
