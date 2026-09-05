//! Shared request state.

use std::sync::{atomic::AtomicUsize, Arc};

use sqlx::PgPool;

use crate::{
    config::Env, mail::Mailer, metrics::Metrics, oidc::OidcState, ratelimit::AnonLimiter,
    storage::Store,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub store: Store,
    pub env: Env,
    pub anon_limiter: AnonLimiter,
    pub oidc: Option<OidcState>,
    pub metrics: Arc<Metrics>,
    pub mailer: Option<Mailer>,
    pub webauthn: Option<Arc<webauthn_rs::Webauthn>>,
    /// Live request-body cap (see [`InstanceConfig::body_limit`]). Refreshed
    /// instantly on admin save plus a periodic safety net; read per request,
    /// so limit changes never need a restart.
    pub body_limit: Arc<AtomicUsize>,
}
