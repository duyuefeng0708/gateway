use std::sync::Arc;

use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;

/// Shared application state passed to every Axum handler via `State(...)`.
#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    pub detector: Arc<dyn PiiDetector>,
    pub session_store: Arc<SessionStore>,
    pub http_client: reqwest::Client,
}
