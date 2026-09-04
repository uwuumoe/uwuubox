//! Route table. Explicit routes first, root-raw `/{core}` last; static
//! segments always beat the dynamic capture, and the raw handler additionally
//! 404s every reserved word (unit-tested).

pub mod accounts;
pub mod admin;
pub mod common;
pub mod files;
pub mod invites;
pub mod pages;
pub mod pastes;
pub mod passkeys;
pub mod reset;
pub mod roles;
pub mod upload;
pub mod zip;

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
        .route("/forgot", post(reset::forgot_post))
        .route(
            "/passkeys/auth/start",
            post(passkeys::authentication_start),
        )
        .route(
            "/passkeys/auth/finish",
            post(passkeys::authentication_finish),
        )
        .layer(auth_governor);

    Router::new()
        .route("/", get(pages::index))
        .route("/health", get(pages::health))
        .route("/paste", get(pages::new_paste))
        // files
        .route("/f/{core}", get(files::preview))
        .route("/f/{core}/unlock", post(files::unlock))
        .route("/api/files/{core}", delete(files::delete_file))
        .route("/api/files/{core}", patch(files::toggle_file))
        .route("/api/zip", post(zip::create))
        // pastes
        .route("/p/{core}", get(pastes::view_paste))
        .route("/p/{core}/raw", get(pastes::raw_paste))
        .route("/api/pastes/{core}", delete(pastes::delete_paste))
        .route("/api/pastes/{core}", patch(pastes::toggle_paste))
        // accounts
        .route("/register", get(accounts::register_form))
        .route("/login", get(accounts::login_form))
        .route("/forgot", get(reset::forgot_form))
        .route(
            "/reset/{token}",
            get(reset::reset_form).post(reset::reset_post),
        )
        .route("/logout", post(accounts::logout))
        .route("/account", get(accounts::dashboard))
        .route("/account/profile", post(accounts::update_profile))
        .route("/account/avatar", post(accounts::upload_avatar))
        .route("/account/tokens", post(accounts::create_token))
        .route("/account/tokens/{id}/revoke", post(accounts::revoke_token))
        .route(
            "/account/passkeys/start",
            post(passkeys::registration_start),
        )
        .route(
            "/account/passkeys/finish",
            post(passkeys::registration_finish),
        )
        .route(
            "/account/passkeys/{id}/delete",
            post(passkeys::delete_passkey),
        )
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
        .route("/admin/roles", post(roles::create_role))
        .route("/admin/roles/{id}", post(roles::update_role))
        .route("/admin/roles/{id}/delete", post(roles::delete_role))
        .route(
            "/admin/roles/{id}/oidc-groups",
            post(roles::add_oidc_mapping),
        )
        .route(
            "/admin/roles/{id}/oidc-groups/remove",
            post(roles::remove_oidc_mapping),
        )
        .route(
            "/admin/users/{id}/role",
            post(roles::update_user_role),
        )
        .route("/admin/invites", post(invites::create_invite))
        .route(
            "/admin/invites/{code}/revoke",
            post(invites::revoke_invite),
        )
        .merge(throttled_uploads)
        .merge(throttled_auth)
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // root-raw byte serving: registered last, reserved words guarded.
        .route("/{core}", get(files::raw))
        .layer(RequestBodyLimitLayer::new(boot_body_limit))
        // Axum's own 2MB default would shadow the boot limit + per-role caps.
        .layer(DefaultBodyLimit::disable())
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::extract::Request| {
                // Path only: DefaultMakeSpan would log request.uri including
                // `?password=` unlock secrets.
                tracing::debug_span!(
                    "request",
                    method = %request.method(),
                    path = %request.uri().path()
                )
            },
        ))
        .layer(session_layer)
        .with_state(state)
}
