//! Expiry sweeper: every 300s, delete objects then rows for expired
//! files/pastes in 500-row batches. Object-delete failure keeps the row for
//! retry; row delete only follows a successful object delete.

use sqlx::PgPool;

use crate::{db, storage::Store};

pub async fn run_once(pool: &PgPool, store: &Store) -> (usize, usize) {
    let mut files = 0usize;
    let mut pastes = 0usize;

    match db::expired_files(pool, 500).await {
        Ok(rows) => {
            for f in rows {
                match store.delete(&f.storage_key).await {
                    Ok(()) => {
                        match sqlx::query("DELETE FROM files WHERE id_core = $1")
                            .bind(&f.id_core)
                            .execute(pool)
                            .await
                        {
                            Ok(_) => files += 1,
                            Err(e) => {
                                tracing::error!(core = %f.id_core, error = %e, "expiry: row delete failed")
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(core = %f.id_core, error = %e, "expiry: object delete failed; row kept")
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
    (files, pastes)
}

pub fn spawn(pool: PgPool, store: Store) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            run_once(&pool, &store).await;
        }
    });
}
