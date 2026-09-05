//! Optional external malware/secret scanning hook for uploads.
//!
//! When `scan_uploads` is on and `UWUU_SCAN_COMMAND` is set, the spooled
//! upload file is scanned in place as `{cmd} {path} {mime}` with
//! `UWUU_SCAN_TIMEOUT_SECS` timeout: exit 0 = clean, exit 3 = infected
//! (rejected with 422), anything else = error (fail-open allows, fail-closed
//! rejects, per `UWUU_SCAN_FAIL_OPEN`). `Skipped` (toggle off or no command)
//! stores `scan_status = 'skipped'`.

use std::time::Duration;

use tokio::{process::Command, time::timeout};

use crate::config::Env;

pub enum Verdict {
    Clean,
    Infected(String),
    Skipped,
}

fn scanner_error(env: &Env, filename: &str, reason: String) -> Verdict {
    tracing::warn!(
        %filename,
        error = %reason,
        fail_open = env.scan_fail_open,
        "upload scanner failed"
    );
    if env.scan_fail_open {
        Verdict::Clean
    } else {
        Verdict::Infected(format!("scanner error: {reason}"))
    }
}

fn infected_reason(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .trim()
        .chars()
        .take(200)
        .collect()
}

fn status_error(status: std::process::ExitStatus) -> String {
    status.to_string()
}

/// Scan an already-spooled file without copying it again. The caller owns
/// `path` and removes it; this only runs the scanner command.
pub async fn verdict_path(
    env: &Env,
    filename: &str,
    path: &std::path::Path,
    mime: &str,
) -> Verdict {
    if env.scan_command.is_none() {
        return Verdict::Skipped;
    }
    verdict_path_inner(env, filename, path, mime).await
}

async fn verdict_path_inner(
    env: &Env,
    filename: &str,
    path: &std::path::Path,
    mime: &str,
) -> Verdict {
    let Some(command_name) = env.scan_command.as_deref() else {
        return Verdict::Skipped;
    };
    let mut command = Command::new(command_name);
    command.arg(path).arg(mime).kill_on_drop(true);
    let outcome = timeout(Duration::from_secs(env.scan_timeout_secs), command.output()).await;
    match outcome {
        Ok(Ok(output)) if output.status.success() => Verdict::Clean,
        Ok(Ok(output)) if output.status.code() == Some(3) => {
            Verdict::Infected(infected_reason(&output.stdout))
        }
        Ok(Ok(output)) => scanner_error(env, filename, status_error(output.status)),
        Ok(Err(error)) => scanner_error(env, filename, error.to_string()),
        Err(_) => scanner_error(env, filename, "timeout".into()),
    }
}
