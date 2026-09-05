//! Prometheus exposition endpoint and HTTP response-class accounting.

use std::sync::Arc;

use axum::{
    extract::State,
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
};

use crate::{metrics::Metrics, state::AppState};

/// Intentionally unauthenticated for Prometheus scraping. Production installs
/// should restrict this path at the reverse proxy when metrics are not public.
pub async fn render(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

pub async fn count_status(State(metrics): State<Arc<Metrics>>, response: Response) -> Response {
    let class = match response.status().as_u16() / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => return response,
    };
    metrics.http.with_label_values(&[class]).inc();
    response
}
