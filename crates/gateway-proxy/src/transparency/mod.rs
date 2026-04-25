//! Rekor transparency-log anchor publisher.
//!
//! This module batches the gateway's hash-chained audit log heads and
//! periodically anchors a Merkle root over them in Sigstore's Rekor
//! public-good service. Anchoring is best-effort — receipts always
//! verify offline first, and the `anchor_status` field on each receipt
//! tells clients whether their entry has made it to a public log yet.
//!
//! The batched design (Merkle root over many chain heads, NOT one Rekor
//! entry per audit entry) drops Rekor load from ~1440/day to ~96/day at
//! the default 15-minute interval. Per the eng-review plan, this is
//! mandatory: Sigstore's instance has a 99.5% SLO and is not designed
//! for per-request traffic.
//!
//! Public surface:
//! - [`TransparencyState`] — the cloneable handle the wiring PR will
//!   stick on `AppState`.
//! - [`HeadSnapshot`] — JSON shape returned by `GET /v1/transparency/head`.
//! - [`TransparencyError`] — construction errors from `from_env`.

pub mod rekor;
pub mod state;

pub use state::{HeadSnapshot, TransparencyError, TransparencyState};

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::state::AppState;

/// `GET /v1/transparency/head` — return the current chain head + last
/// anchored hash + how stale the anchor is. Operators alert on
/// `last_publish_age_seconds` outgrowing the configured anchor interval
/// by a wide margin.
pub async fn head_handler(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state.transparency.current_head().await;
    Json(snapshot)
}
