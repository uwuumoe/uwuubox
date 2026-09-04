//! Route table. Explicit routes first, root-raw `/{core}` last; static
//! segments always beat the dynamic capture, and the raw handler additionally
//! 404s every reserved word (unit-tested).

pub mod accounts;
pub mod admin;
pub mod common;
pub mod files;
pub mod pages;
pub mod pastes;
pub mod upload;

use std::{sync::Arc, time::Duration};

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post},
    Router,
};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tower_sessions::SessionManagerLayer;
use tower_sessions_sqlx_store::PostgresStore;

use crate::state::AppState;

pub fn build_router(
    state: AppState,
    session_layer: SessionManagerLayer<PostgresStore>,
    boot_body_limit: usize,
) -> Router {
    // 60 uploads/hr/IP ceiling; anonymous 10/hr additionally enforced in-handler
    // (authed-vs-anon can't split at the routing layer).
    let upload_governor = {
        let config: Arc<_> = Arc::new(
            GovernorConfigBuilder::default()
                .period(Duration::from_secs(3600))
                .burst_size(60)
                .finish()
                .expect("governor config"),
        );
        GovernorLayer::new(config)
    };
    // 5 auth attempts/min/IP.
    let auth_governor = {
        let config: Arc<_> = Arc::new(
            GovernorConfigBuilder::default()
                .period(Duration::from_secs(60))
                .burst_size(5)
                .finish()
                .expect("governor config"),
        );
        GovernorLayer::new(config)
    };

    let throttled_uploads = Router::new()
        .route("/api/upload", post(upload::upload))
        .route("/api/pastes", post(pastes::create_paste))
        .layer(upload_governor);

    let throttled_auth = Router::new()
        .route("/login", post(accounts::login_post))
        .route("/register", post(accounts::register_post))
        .layer(auth_governor);

    Router::new()
        .route("/", get(pages::index))
        .route("/health", get(pages::health))
        .route("/paste", get(pages::new_paste))
        // files
        .route("/f/{core}", get(files::preview))
        .route("/api/files/{core}", delete(files::delete_file))
        .route("/api/files/{core}", patch(files::toggle_file))
        // pastes
        .route("/p/{core}", get(pastes::view_paste))
        .route("/p/{core}/raw", get(pastes::raw_paste))
        .route("/api/pastes/{core}", delete(pastes::delete_paste))
        .route("/api/pastes/{core}", patch(pastes::toggle_paste))
        // accounts
        .route("/register", get(accounts::register_form))
        .route("/login", get(accounts::login_form))
        .route("/logout", post(accounts::logout))
        .route("/account", get(accounts::dashboard))
        .route("/account/profile", post(accounts::update_profile))
        .route("/account/avatar", post(accounts::upload_avatar))
        .route("/account/tokens", post(accounts::create_token))
        .route("/account/tokens/{id}/revoke", post(accounts::revoke_token))
        .route(
            "/account/files/{core}/delete",
            post(accounts::dashboard_delete_file),
        )
        .route(
            "/account/files/{core}/visibility",
            post(accounts::dashboard_file_visibility),
        )
        .route(
            "/account/pastes/{core}/delete",
            post(accounts::dashboard_delete_paste),
        )
        .route(
            "/account/pastes/{core}/visibility",
            post(accounts::dashboard_paste_visibility),
        )
        .route("/account/oidc/link", post(crate::oidc::link_start))
        .route("/u/{username}", get(accounts::profile))
        .route("/a/{name}", get(accounts::serve_avatar))
        // oidc
        .route("/oidc/login", get(crate::oidc::login))
        .route("/oidc/callback", get(crate::oidc::callback))
        // admin
        .route("/admin", get(admin::admin_page))
        .route("/admin/config", post(admin::update_config))
        .route("/admin/users/{id}/grant", post(admin::grant))
        .merge(throttled_uploads)
        .merge(throttled_auth)
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // root-raw byte serving: registered last, reserved words guarded.
        .route("/{core}", get(files::raw))
        .layer(RequestBodyLimitLayer::new(boot_body_limit))
        // Axum's own 2MB default would shadow the boot limit + per-role caps.
        .layer(DefaultBodyLimit::disable())
        .layer(TraceLayer::new_for_http())
        .layer(session_layer)
        .with_state(state)
}
