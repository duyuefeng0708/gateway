use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// GET /ready — liveness + readiness signal for orchestrators.
///
/// Returns 200 with body "ok" iff the warm-up probe has succeeded at least
/// once. Returns 503 with body "warming" before the first success.
///
/// `/ready` only reflects warm-up state. It does NOT indicate that the deep
/// tier is currently responsive — operators should watch the
/// `deep_tier_attempted_total` vs `deep_tier_succeeded_total` metric ratio
/// for that signal. The silent-fallback posture means `/ready` can be 200
/// while deep detection is degraded.
pub async fn ready_handler(State(state): State<AppState>) -> Response {
    if state.warm.load(Ordering::Acquire) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "warming").into_response()
    }
}
