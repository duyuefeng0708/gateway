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

/// Custom histogram buckets for deep-tier latency. Default Prometheus buckets
/// top out around 10 seconds which is useless for a 86-second laptop Gemma-26B
/// run. These cover 100ms through 5 minutes honestly.
const DEEP_TIER_LATENCY_BUCKETS: &[f64] =
    &[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 90.0, 120.0, 180.0, 300.0];

/// Install the Prometheus metrics recorder. Call once before the server starts.
/// Returns `Err` if a recorder is already installed (e.g. in tests that run
/// multiple times in one process).
pub fn init_metrics() -> Result<(), String> {
    let builder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(
                "gateway_deep_tier_latency_seconds".to_string(),
            ),
            DEEP_TIER_LATENCY_BUCKETS,
        )
        .map_err(|e| format!("failed to set deep_tier_latency buckets: {e}"))?;
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
// Tier-visibility metrics (from DetectionResult populated in handler.rs).
//
// These distinguish "deep tier was not requested" from "deep tier ran and
// succeeded" from "deep tier ran and silently fell back." Without them,
// silent-fallback is unobservable and the privacy claim is unverifiable.
// Operators should alert on
//   gateway_deep_tier_attempted_total - gateway_deep_tier_succeeded_total
// to catch sustained failures.
// ---------------------------------------------------------------------------

/// Record which tier produced the final spans for this request.
/// `tier` must be one of the literals "regex", "fast", or "deep" — callers
/// construct it from the DetectionResult flags, never from user input, so
/// label cardinality stays bounded.
pub fn record_tier_used(tier: &'static str) {
    counter!("gateway_detector_tier_used", "tier" => tier).increment(1);
}

/// Record that the deep tier was invoked (Deep mode or Auto-escalated).
/// Does not tell you whether it succeeded — pair with `record_deep_tier_succeeded`
/// and the delta is the silent-fallback count.
pub fn record_deep_tier_attempted() {
    counter!("gateway_deep_tier_attempted_total").increment(1);
}

/// Record that the deep tier returned Ok and its spans were merged.
pub fn record_deep_tier_succeeded() {
    counter!("gateway_deep_tier_succeeded_total").increment(1);
}

/// Record a deep-tier failure by error kind. `kind` is a fixed set from
/// DetectionError variants (timeout, server_error, parse_error, empty,
/// connection_refused, other).
pub fn record_deep_tier_failed(kind: &'static str) {
    counter!("gateway_deep_tier_failed_total", "kind" => kind).increment(1);
}

/// Record the wall-clock time spent in the deep tier. Custom buckets span
/// 100ms to 5 minutes to cover both GPU-backed inference and laptop runs.
pub fn record_deep_tier_latency(start: Instant) {
    histogram!("gateway_deep_tier_latency_seconds").record(start.elapsed().as_secs_f64());
}

/// Record a failure to connect to the Ollama HTTP endpoint (distinct from
/// ollama returning 5xx once connected). Useful as a first signal when the
/// Ollama process is down or misbinding.
pub fn record_ollama_connection_error() {
    counter!("gateway_ollama_connection_errors_total").increment(1);
}

/// Record how long the startup warm-up probe took (seconds, may span several
/// retries). Emitted once per process start on success.
pub fn record_warmup_duration_secs(seconds: f64) {
    gauge!("gateway_readiness_warmup_duration_seconds").set(seconds);
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
