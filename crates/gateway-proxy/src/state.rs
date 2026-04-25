use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use gateway_anonymizer::audit::AuditHandle;
use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::hmac_digest::HmacContext;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use tokio::sync::Semaphore;

use crate::receipts::ReceiptCache;
use crate::routing::Router;

/// Shared application state passed to every Axum handler via `State(...)`.
///
/// `warm` starts `false` and flips to `true` after the startup warm-up probe
/// succeeds. `/ready` reads it; handlers serve traffic regardless (silent
/// fallback on deep tier is the accepted posture).
///
/// `detection_semaphore` bounds the number of concurrent `detect()` calls
/// per multi-message request — see `handler::handle_proxy_request` for the
/// bounded-parallelism loop.
#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    pub detector: Arc<dyn PiiDetector>,
    pub session_store: Arc<SessionStore>,
    pub http_client: reqwest::Client,
    pub router: Router,
    pub warm: Arc<AtomicBool>,
    pub detection_semaphore: Arc<Semaphore>,
    /// Async handle to the dedicated audit writer thread. Cheap to clone
    /// (mpsc Sender). Handlers submit via `audit.write_entry_v2` per
    /// request; backpressure surfaces as `AuditError::Backpressured`
    /// (mapped to HTTP 503). PR-A1.
    pub audit: AuditHandle,
    /// Per-instance HMAC key used to compute receipt prompt/response
    /// digests. Codex F12 — bare hashes leak via confirmation attacks.
    pub hmac: Arc<HmacContext>,
    /// Receipt LRU cache. Hot path on `GET /v1/receipts/{id}`. Cache
    /// miss falls back to scanning today's then yesterday's audit jsonl.
    pub receipts: Arc<ReceiptCache>,
}
