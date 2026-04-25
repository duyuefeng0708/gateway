pub mod format;
pub mod handler;
pub mod metrics;
pub mod privacy_api;
pub mod readiness;
pub mod receipts;
pub mod routing;
pub mod sse_buffer;
pub mod state;
pub mod transparency;
pub mod warmup;

pub use handler::handle_proxy_request;
pub use metrics::metrics_handler;
pub use privacy_api::{anonymize, deanonymize};
pub use readiness::ready_handler;
pub use receipts::receipts_handler;
pub use routing::Router;
pub use state::AppState;
pub use transparency::head_handler as transparency_head_handler;

use axum::routing::{get, post};

/// Build the axum Router with all routes and the given shared state.
///
/// Exposed so both `main.rs` and integration tests construct the server the
/// same way. Keeps the wiring assertion-checkable from tests.
pub fn build_server(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/v1/anonymize", post(anonymize))
        .route("/v1/deanonymize", post(deanonymize))
        .route("/v1/receipts/{id}", get(receipts_handler))
        .route("/v1/transparency/head", get(transparency_head_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ready", get(ready_handler))
        .fallback(handle_proxy_request)
        .with_state(state)
}
