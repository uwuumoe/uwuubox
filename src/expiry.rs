//! Expiry sweeper: every 300s, atomically delete expired rows and release
//! their shared backing objects in 500-row batches.

use sqlx::PgPool;

use crate::{db, routes::files::remove_file, storage::Store};

pub async fn run_once(
    pool: &PgPool,
    store: &Store,
    metrics: &std::sync::Arc<crate::metrics::Metrics>,
) -> (usize, usize) {
    let mut files = 0usize;
    let mut pastes = 0usize;

    match db::expired_files(pool, 500).await {
        Ok(rows) => {
            for file in rows {
                match remove_file(&(pool, store), &file).await {
                    Ok(true) => files += 1,
                    Ok(false) => {}
                    Err(e) => {
                        tracing::error!(core = %file.id_core, error = %e, "expiry: file removal failed")
                    }
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "expiry: file scan failed"),
    }

    match db::expired_pastes(pool, 500).await {
        Ok(rows) => {
            for p in rows {
                match sqlx::query("DELETE FROM pastes WHERE id_core = $1")
                    .bind(&p.id_core)
                    .execute(pool)
                    .await
                {
                    Ok(_) => pastes += 1,
                    Err(e) => {
                        tracing::error!(core = %p.id_core, error = %e, "expiry: paste delete failed")
                    }
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "expiry: paste scan failed"),
    }
    if files + pastes > 0 {
        tracing::info!(files, pastes, "expiry sweep removed expired items");
    }
    metrics.sweeper_runs.inc();
    metrics.files_swept.inc_by(files as u64);
    metrics.pastes_swept.inc_by(pastes as u64);
    (files, pastes)
}

pub fn spawn(pool: PgPool, store: Store, metrics: std::sync::Arc<crate::metrics::Metrics>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            run_once(&pool, &store, &metrics).await;
        }
    });
}
