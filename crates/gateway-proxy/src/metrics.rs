use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Global Prometheus handle
// ---------------------------------------------------------------------------

static PROM_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the Prometheus metrics recorder. Call once before the server starts.
/// Returns `Err` if a recorder is already installed (e.g. in tests that run
/// multiple times in one process).
pub fn init_metrics() -> Result<(), String> {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .map_err(|e| format!("failed to install Prometheus recorder: {e}"))?;
    PROM_HANDLE
        .set(handle)
        .map_err(|_| "Prometheus recorder already initialised".to_string())
}

/// Try to initialise metrics; silently succeed if already initialised.
/// Useful in test code where multiple tests share the same process.
pub fn try_init_metrics() {
    let _ = init_metrics();
}

// ---------------------------------------------------------------------------
// Metric recording helpers
// ---------------------------------------------------------------------------

/// Record a completed request, labelled by HTTP status code.
pub fn record_request_total(status: u16) {
    counter!("gateway_requests_total", "status" => status.to_string()).increment(1);
}

/// Record PII entities detected, labelled by PII type name.
pub fn record_pii_detected(pii_type: &str, count: u64) {
    counter!("gateway_pii_detected_total", "pii_type" => pii_type.to_string()).increment(count);
}

/// Record model inference duration for the PII detection step.
pub fn record_model_inference_duration(start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    histogram!("gateway_model_inference_duration_seconds").record(elapsed);
}

/// Record total request duration (client-visible latency).
pub fn record_request_duration(start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    histogram!("gateway_request_duration_seconds").record(elapsed);
}

/// Record upstream round-trip duration.
pub fn record_upstream_duration(start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    histogram!("gateway_upstream_duration_seconds").record(elapsed);
}

/// Increment the error counter, labelled by error kind.
pub fn record_error(kind: &str) {
    counter!("gateway_errors_total", "kind" => kind.to_string()).increment(1);
}

/// Set the current number of active sessions (gauge).
pub fn set_active_sessions(count: f64) {
    gauge!("gateway_active_sessions").set(count);
}

// ---------------------------------------------------------------------------
// GET /metrics handler
// ---------------------------------------------------------------------------

/// Axum handler for `GET /metrics`.  Returns the Prometheus text exposition
/// format with content-type `text/plain; version=0.0.4`.
pub async fn metrics_handler() -> Response {
    let body = match PROM_HANDLE.get() {
        Some(handle) => handle.render(),
        None => String::from("# Prometheus recorder not initialised\n"),
    };

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}
