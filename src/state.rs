//! Shared request state.

use sqlx::PgPool;

use crate::{config::Env, oidc::OidcState, ratelimit::AnonLimiter, storage::Store};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub store: Store,
    pub env: Env,
    pub anon_limiter: AnonLimiter,
    pub oidc: Option<OidcState>,
}
