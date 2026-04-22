use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use gateway_proxy::metrics;
use gateway_proxy::routing::Router as SmartRouter;
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

    // Initialize Prometheus metrics recorder.
    metrics::init_metrics()
        .map_err(|e| format!("metrics initialization failed: {e}"))?;

    // Parse configuration from environment.
    let config = GatewayConfig::from_env()
        .map_err(|e| format!("configuration error: {e}"))?;

    // Initialize session store (SQLite).
    let session_store = SessionStore::new(&config.db_path).await
        .map_err(|e| format!("session store initialization failed: {e}"))?;

    // Initialize the PII detector (regex for now; TieredDetector in Unit 6).
    let detector = RegexDetector::new();

    // Build the HTTP client for upstream forwarding with connection pooling.
    let http_client = reqwest::Client::builder()
        .timeout(config.upstream_timeout)
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    // Load smart routing config (optional).
    let router = match &config.routing_config_path {
        Some(path) => SmartRouter::load_or_default(path),
        None => SmartRouter::default_router(),
    };
    if router.has_routes() {
        info!("smart model routing enabled");
    }

    let listen_addr = config.listen_addr.clone();

    let app_state = AppState {
        config,
        detector: Arc::new(detector),
        session_store: Arc::new(session_store),
        http_client,
        router,
    };

    // Build the router -- privacy API and /metrics are dedicated routes;
    // everything else falls through to the proxy handler.
    let app = Router::new()
        .route("/v1/anonymize", post(gateway_proxy::anonymize))
        .route("/v1/deanonymize", post(gateway_proxy::deanonymize))
        .route("/metrics", get(metrics::metrics_handler))
        .fallback(gateway_proxy::handle_proxy_request)
        .with_state(app_state);

    info!("Gateway starting...");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}
