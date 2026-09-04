//! Boot: env → pool → migrations → session store → storage → OIDC → router.

mod auth;
mod config;
mod db;
mod error;
mod expiry;
mod identity;
mod ids;
mod mime;
mod oidc;
mod ratelimit;
mod routes;
mod state;
mod storage;
mod views;

use std::{net::SocketAddr, time::Duration};

use tower_sessions::{
    cookie::{time::Duration as CookieDuration, SameSite},
    Expiry, SessionManagerLayer,
};
use tower_sessions_sqlx_store::PostgresStore;
use tracing_subscriber::EnvFilter;

use crate::{config::Env, ratelimit::AnonLimiter, state::AppState, storage::Store};

fn fatal(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("uwuubox: {context}: {err}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("uwuubox=info,tower_http=info")),
        )
        .init();

    let env = Env::load().unwrap_or_else(|e| fatal("bad config", e));

    let pool = db::connect(&env.database_url)
        .await
        .unwrap_or_else(|e| fatal("database unreachable", e));
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap_or_else(|e| fatal("migration failed", e));

    let session_store = PostgresStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .unwrap_or_else(|e| fatal("session store migrate failed", e));
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("__Host-uwuubox")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(CookieDuration::days(30)));

    let store = Store::from_env(&env)
        .await
        .unwrap_or_else(|e| fatal("storage init failed", e));
    let http = reqwest::Client::new();
    let oidc = oidc::build(&env, &http).await;

    let boot_cfg = db::instance_config(&pool)
        .await
        .unwrap_or_else(|e| fatal("instance config unreadable", e));
    let boot_body_limit = (boot_cfg.max_file_bytes + 2 * 1024 * 1024).max(1) as usize;

    if db::user_count(&pool).await.unwrap_or(1) == 0 {
        tracing::warn!("no users yet: the first registration (local or OIDC) becomes admin");
    }

    let state = AppState {
        pool: pool.clone(),
        store: store.clone(),
        env: env.clone(),
        anon_limiter: AnonLimiter::new(10, Duration::from_secs(3600)),
        oidc,
    };
    expiry::spawn(pool, store);

    let app = routes::build_router(state, session_layer, boot_body_limit);
    let addr = SocketAddr::from(([0, 0, 0, 0], env.port));
    tracing::info!(%addr, base = %env.base_url, "uwuubox listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| fatal("bind failed", e));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap_or_else(|e| fatal("serve failed", e));
}
