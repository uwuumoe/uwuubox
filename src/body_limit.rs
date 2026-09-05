//! Request-body backstop with a live limit.
//!
//! tower-http's [`RequestBodyLimitLayer`] snapshots its limit at construction,
//! so admin changes to `max_file_bytes` needed a restart to take effect. This
//! layer reads the current cap from shared state on every request and otherwise
//! behaves identically: immediate 413 on `Content-Length` overflow, mid-stream
//! 413 for chunked bodies.
//!
//! The cap refreshes instantly when the admin UI saves (see
//! [`crate::routes::admin::update_config`]) and every [`REFRESH_INTERVAL`] as
//! a safety net for out-of-band database edits, so limit changes never need a
//! restart.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::http::{Request, Response};
use http_body::Body;
use tower::{Layer, Service};
use tower_http::{
    body::Limited,
    limit::{RequestBodyLimit, ResponseBody, ResponseFuture},
};

/// Poll interval for the out-of-band-edit safety net (admin saves refresh instantly).
const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// [`Layer`] enforcing the shared live body cap. Clone the [`Arc`] from
/// [`crate::state::AppState::body_limit`].
#[derive(Clone, Debug)]
pub struct DynamicBodyLimitLayer {
    limit: Arc<AtomicUsize>,
}

impl DynamicBodyLimitLayer {
    pub fn new(limit: Arc<AtomicUsize>) -> Self {
        Self { limit }
    }
}

impl<S> Layer<S> for DynamicBodyLimitLayer {
    type Service = DynamicBodyLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DynamicBodyLimit {
            inner,
            limit: self.limit.clone(),
        }
    }
}

/// [`Service`] delegating to a per-request fixed-limit tower-http service, so
/// the 413 mapping stays exactly theirs.
#[derive(Clone, Debug)]
pub struct DynamicBodyLimit<S> {
    inner: S,
    limit: Arc<AtomicUsize>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for DynamicBodyLimit<S>
where
    S: Service<Request<Limited<ReqBody>>, Response = Response<ResBody>> + Clone,
    ReqBody: Body,
    ResBody: Body,
{
    type Response = Response<ResponseBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Inner is ready (our `poll_ready` passthrough upholds the tower
        // contract); the clone only carries the call to a fixed-limit service
        // built from the current cap.
        let limit = self.limit.load(Ordering::Relaxed);
        RequestBodyLimit::new(self.inner.clone(), limit).call(req)
    }
}
/// restart. Fire-and-forget for the life of the process (like `expiry::spawn`).
pub fn spawn_refresher(pool: sqlx::PgPool, limit: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REFRESH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            match crate::db::instance_config(&pool).await {
                Ok(cfg) => {
                    let next = cfg.body_limit();
                    if limit.swap(next, Ordering::Relaxed) != next {
                        tracing::info!(next, "request body limit refreshed");
                    }
                }
                Err(error) => tracing::warn!(%error, "body limit refresh failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::post, Router};
    use bytes::Bytes;
    use tower::ServiceExt;

    async fn app_with(limit: Arc<AtomicUsize>) -> Router {
        Router::new()
            .route(
                "/",
                post(|body: Bytes| async move { body.len().to_string() }),
            )
            .layer(DynamicBodyLimitLayer::new(limit))
    }

    fn post_req(body: &'static str) -> Request<Body> {
        Request::builder()
            .uri("/")
            .method("POST")
            .body(Body::from(body))
            .expect("test request builds")
    }

    #[tokio::test]
    async fn limit_reloads_without_rebuild() {
        let limit = Arc::new(AtomicUsize::new(8));
        let app = app_with(limit.clone()).await;
        let res = app.clone().oneshot(post_req("12345678")).await.unwrap();
        assert_eq!(res.status(), 200);

        // Tighten live: the same router must now reject what it just accepted.
        limit.store(4, Ordering::Relaxed);
        let res = app.clone().oneshot(post_req("12345678")).await.unwrap();
        assert_eq!(res.status(), 413);

        // And loosening re-admits without touching the router.
        limit.store(8, Ordering::Relaxed);
        let res = app.oneshot(post_req("12345678")).await.unwrap();
        assert_eq!(res.status(), 200);
    }
}
