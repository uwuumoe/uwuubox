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

use std::{path::PathBuf, process::ExitStatus, time::Duration};

use tokio::{fs, io::AsyncWriteExt, process::Command, time::timeout};
use uuid::Uuid;

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

async fn remove_temp(path: &PathBuf) {
    if let Err(error) = fs::remove_file(path).await {
        tracing::warn!(path = %path.display(), %error, "could not remove scanner temp file");
    }
}

fn status_error(status: ExitStatus) -> String {
    status.to_string()
}

async fn write_temp(path: &PathBuf, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    file.write_all(bytes).await
}

pub async fn verdict(env: &Env, filename: &str, bytes: &[u8], mime: &str) -> Verdict {
    let Some(command_name) = env.scan_command.as_deref() else {
        return Verdict::Skipped;
    };

    let temp_path =
        std::env::temp_dir().join(format!("uwuubox-scan-{}", Uuid::new_v4().as_simple()));
    if let Err(error) = write_temp(&temp_path, bytes).await {
        // A partial file may exist even when write returns an error.
        remove_temp(&temp_path).await;
        return scanner_error(env, filename, error.to_string());
    }

    let mut command = Command::new(command_name);
    command.arg(&temp_path).arg(mime).kill_on_drop(true);
    let outcome = timeout(Duration::from_secs(env.scan_timeout_secs), command.output()).await;
    let verdict = match outcome {
        Ok(Ok(output)) if output.status.success() => Verdict::Clean,
        Ok(Ok(output)) if output.status.code() == Some(3) => {
            Verdict::Infected(infected_reason(&output.stdout))
        }
        Ok(Ok(output)) => scanner_error(env, filename, status_error(output.status)),
        Ok(Err(error)) => scanner_error(env, filename, error.to_string()),
        Err(_) => scanner_error(env, filename, "timeout".into()),
    };
    remove_temp(&temp_path).await;
    verdict
}
