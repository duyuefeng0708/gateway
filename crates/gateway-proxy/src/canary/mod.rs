//! Statistical model-fingerprint canary probe (PR-B from the 2026-04-25
//! verifiability plan).
//!
//! Periodically sends a small prompt suite at the configured upstream and
//! compares the responses against a baseline captured from a known-good
//! Anthropic session. Drift in any of four feasible signals (output
//! similarity, length bucket, stop reason, latency bucket) collapses the
//! aggregate confidence score. If confidence drops below a threshold,
//! `/v1/canary/status` reports `degraded` and operators get a 5-minute
//! detection window for upstream model swaps. Codex F18.
//!
//! Public surface:
//! - [`CanaryState`] — the cloneable handle on `AppState`.
//! - [`CanaryStatus`] — coarse state returned by `GET /v1/canary/status`.
//! - [`Baseline`] — the JSON shape checked into `eval/canary_baseline.json`.
//! - [`features`] — per-feature scoring functions exposed for testing.

pub mod features;
pub mod state;

// Re-export the baseline types from gateway-common so existing
// `gateway_proxy::canary::Baseline` and `ProbeFingerprint` paths keep
// working. The types live in common because the CLI also serialises
// them; the runtime state stays here.
pub use gateway_common::canary_baseline::{Baseline, ProbeFingerprint};
pub use state::{CanaryState, CanaryStatus};

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::state::AppState;

/// `GET /v1/canary/status` — coarse upstream-identity confidence.
///
/// Returns one of `healthy | degraded | unknown` plus the most recent
/// confidence score and last probe time. The endpoint deliberately does
/// NOT expose per-feature scores or raw probe output — they would let
/// an attacker tune a spoof against the canary. Codex F17.
pub async fn status_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.canary.status_snapshot().await)
}
