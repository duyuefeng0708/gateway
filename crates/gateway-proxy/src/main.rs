use std::sync::Arc;

use axum::Router;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use gateway_proxy::state::AppState;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse configuration from environment.
    let config = GatewayConfig::from_env()
        .map_err(|e| format!("configuration error: {e}"))?;

    // Initialize session store (SQLite).
    let session_store = SessionStore::new(&config.db_path).await
        .map_err(|e| format!("session store initialization failed: {e}"))?;

    // Initialize the PII detector (regex for now; TieredDetector in Unit 6).
    let detector = RegexDetector::new();

    // Build the HTTP client for upstream forwarding.
    let http_client = reqwest::Client::builder()
        .timeout(config.model_timeout)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let listen_addr = config.listen_addr.clone();

    let app_state = AppState {
        config,
        detector: Arc::new(detector),
        session_store: Arc::new(session_store),
        http_client,
    };

    // Build the router -- all methods on all paths go to the proxy handler.
    let app = Router::new()
        .fallback(gateway_proxy::handle_proxy_request)
        .with_state(app_state);

    info!("Gateway starting...");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}
