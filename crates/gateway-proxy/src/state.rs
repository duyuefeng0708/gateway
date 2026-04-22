use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use tokio::sync::Semaphore;

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
}
