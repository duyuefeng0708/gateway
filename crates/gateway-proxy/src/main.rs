use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use gateway_anonymizer::session::SessionStore;
use gateway_anonymizer::tiered::TieredDetector;
use gateway_common::config::GatewayConfig;
use gateway_proxy::metrics;
use gateway_proxy::routing::Router as SmartRouter;
use gateway_proxy::state::AppState;
use tokio::sync::Semaphore;
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
    let session_store = SessionStore::new(&config.db_path)
        .await
        .map_err(|e| format!("session store initialization failed: {e}"))?;

    // Build the tiered detector from config. Replaces the regex-only shim
    // that shipped while the wire-up was deferred. With scan_mode=fast,
    // the Ollama deep detector is not constructed; with auto/deep, an
    // Ollama client points at the deep model.
    let detector = TieredDetector::from_config(&config);
    info!(
        mode = ?config.scan_mode,
        fast = %config.fast_model,
        deep = %config.deep_model,
        "tiered detector built"
    );

    // Build the HTTP client for upstream forwarding with connection pooling.
    let http_client = reqwest::Client::builder()
        .timeout(config.upstream_timeout)
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    // Load smart routing config (optional, dormant until multi-upstream used).
    let router = match &config.routing_config_path {
        Some(path) => SmartRouter::load_or_default(path),
        None => SmartRouter::default_router(),
    };
    if router.has_routes() {
        info!("smart model routing enabled");
    }

    let listen_addr = config.listen_addr.clone();
    let detection_concurrency = config.detection_concurrency;

    let app_state = AppState {
        config,
        detector: Arc::new(detector),
        session_store: Arc::new(session_store),
        http_client,
        router,
        warm: Arc::new(AtomicBool::new(false)),
        detection_semaphore: Arc::new(Semaphore::new(detection_concurrency)),
    };

    let app = gateway_proxy::build_server(app_state.clone());

    info!("Gateway starting...");

    // Warm-up probe runs before the listener binds. See gateway_proxy::warmup.
    gateway_proxy::warmup::run_with_retry(&app_state).await;

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}
