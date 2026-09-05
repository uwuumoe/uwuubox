//! Boot: env → pool → migrations → session store → storage → OIDC → router.

mod auth;
mod config;
mod db;
mod error;
mod expiry;
mod identity;
mod ids;
mod mail;
mod metrics;
mod mime;
mod oidc;
mod range;
mod ratelimit;
mod routes;
mod scan;
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

/// WebAuthn RP derived from the canonical base URL. `None` when the origin
/// does not parse; passkeys stay disabled but boot continues.
fn build_webauthn(env: &crate::config::Env) -> Option<std::sync::Arc<webauthn_rs::Webauthn>> {
    let origin = url::Url::parse(&env.base_url).ok()?;
    // webauthn-rs checks rp_id against origin.domain(), which is None for
    // bare IPs: passkeys need a hostname BASE_URL (`localhost` works).
    let domain = origin.domain()?;
    if origin.host_str() != Some(domain) {
        tracing::warn!("passkeys disabled: BASE_URL host must be a bare domain for WebAuthn");
        return None;
    }
    let wan = webauthn_rs::WebauthnBuilder::new(domain, &origin)
        .ok()?
        .rp_name("uwuubox")
        .build()
        .ok()?;
    Some(std::sync::Arc::new(wan))
}

#[tokio::main]
async fn main() {
    let env = Env::load().unwrap_or_else(|e| fatal("bad config", e));

    // OTLP trace export, composed with fmt logging before init. `_otel`
    // owns the provider for the life of the process (dropping it would shut
    // down the batch exporter); without an endpoint this stays `None` and
    // boot continues on local logging only.
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    let _otel = env.otel_endpoint.clone().and_then(|endpoint| {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| eprintln!("uwuubox: otel exporter build failed ({e})"))
            .ok()?;
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .build();
        let tracer = provider.tracer("uwuubox");
        let _ = opentelemetry::global::set_tracer_provider(provider.clone());
        Some((provider, tracing_opentelemetry::layer().with_tracer(tracer)))
    });
    let (_otel_provider, otlp) = match _otel {
        Some((p, l)) => (Some(p), Some(l)),
        None => (None, None),
    };
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("uwuubox=info,tower_http=info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(otlp)
        .init();
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

    let metrics = std::sync::Arc::new(crate::metrics::Metrics::new().unwrap_or_else(|e| {
        fatal("metrics registry failed", e);
    }));
    let mailer = crate::mail::Mailer::from_env(&env);
    if mailer.is_none() {
        tracing::info!("smtp not configured: password-reset mail disabled");
    }
    let webauthn = build_webauthn(&env);

    let state = AppState {
        pool: pool.clone(),
        store: store.clone(),
        env: env.clone(),
        anon_limiter: AnonLimiter::new(10, Duration::from_secs(3600)),
        oidc,
        metrics: metrics.clone(),
        mailer,
        webauthn,
    };
    expiry::spawn(pool, store, metrics);
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
