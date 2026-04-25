use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use gateway_anonymizer::audit::AuditHandle;
use gateway_anonymizer::hmac_digest::HmacContext;
use gateway_anonymizer::session::SessionStore;
use gateway_anonymizer::tiered::TieredDetector;
use gateway_common::config::GatewayConfig;
use gateway_proxy::metrics;
use gateway_proxy::receipts::ReceiptCache;
use gateway_proxy::routing::Router as SmartRouter;
use gateway_proxy::state::AppState;
use gateway_proxy::canary::CanaryState;
use gateway_proxy::transparency::TransparencyState;
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

    // HMAC context for receipt prompt/response digests. Codex F12 — keyed
    // hashes defeat confirmation attacks. Key is loaded from env at boot;
    // missing or malformed key fails loud.
    let hmac = load_hmac_context()?;

    // Async audit writer. Spawns its own thread + bounded mpsc; cheap to
    // clone via the inner Sender. Fails loud at boot if the audit dir
    // is already locked by a sibling writer.
    let audit = AuditHandle::spawn(std::path::PathBuf::from(&config.audit_path))
        .map_err(|e| format!("audit handle initialization failed: {e}"))?;

    // Receipt LRU cache. Disk fallback scans config.audit_path.
    let receipts = Arc::new(ReceiptCache::with_default_capacity(
        std::path::PathBuf::from(&config.audit_path),
    ));

    // Transparency state: holds Ed25519 signing key + Rekor anchor queue.
    // Constructed before main loop so a missing/malformed signing key
    // fails the boot sequence loud, alongside HMAC validation. Codex F13.
    let transparency = TransparencyState::from_env()
        .map_err(|e| format!("transparency state initialization failed: {e}"))?;

    // Spawn the periodic Rekor anchor publisher. Detached for the
    // lifetime of the proxy; it sleeps `GATEWAY_REKOR_ANCHOR_INTERVAL`
    // (default 15m) between cycles and POSTs a Merkle-rooted batch
    // when there are pending heads. Failures surface via metrics; the
    // proxy keeps serving traffic regardless. Codex F14, F15.
    let _publisher_handle = transparency.spawn_publisher();
    info!(
        rekor_url = %std::env::var("GATEWAY_REKOR_URL").unwrap_or_else(|_| "https://rekor.sigstore.dev".to_string()),
        "transparency anchor publisher started"
    );

    // Canary fingerprint state. Loaded from GATEWAY_CANARY_BASELINE if
    // set, else `eval/canary_baseline.json`, else a stub baseline that
    // makes the canary report `unknown` forever (intentional — no
    // baseline means no comparison, and we don't want to gate boot on
    // a file the operator hasn't generated yet).
    let canary = load_canary_state();
    let _canary_probe_handle = canary.clone().spawn_probe();

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
        audit,
        hmac: Arc::new(hmac),
        receipts,
        transparency,
        canary,
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

/// Load the HMAC key for receipt digests from env.
///
/// Two routes accepted:
/// * `GATEWAY_HMAC_KEY` — hex-encoded key (>= 64 hex chars / 32 bytes).
/// * `GATEWAY_HMAC_KEY_FILE` — path to a file containing hex-encoded key.
///
/// `GATEWAY_HMAC_KEY_ID` (default "primary") is the stable identifier
/// embedded in receipts so verifiers can locate the matching key in
/// their trust store across rotations.
///
/// Missing/malformed key returns a fail-loud Err so the proxy refuses
/// to start without the receipt-digest dependency satisfied. Codex F12.
fn load_hmac_context() -> Result<HmacContext, Box<dyn std::error::Error>> {
    let key_hex = match std::env::var("GATEWAY_HMAC_KEY") {
        Ok(v) => v,
        Err(_) => {
            let path = std::env::var("GATEWAY_HMAC_KEY_FILE").map_err(|_| {
                "missing receipt-digest key: set GATEWAY_HMAC_KEY (hex) or GATEWAY_HMAC_KEY_FILE"
            })?;
            std::fs::read_to_string(&path).map_err(|e| {
                format!("failed to read GATEWAY_HMAC_KEY_FILE {path}: {e}")
            })?
        }
    };
    let key_id = std::env::var("GATEWAY_HMAC_KEY_ID").unwrap_or_else(|_| "primary".to_string());
    HmacContext::from_hex(key_hex.trim(), key_id).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Load canary state from a baseline file or fall back to a stub.
///
/// The stub keeps the canary surface alive (status endpoint returns
/// `unknown`, probe loop logs every interval) without forcing operators
/// to generate a baseline before first boot. Run `gateway-cli canary
/// bootstrap` against a known-good upstream to produce the real file.
fn load_canary_state() -> CanaryState {
    let custom = std::env::var("GATEWAY_CANARY_BASELINE").ok();
    let path = custom
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("eval/canary_baseline.json"));

    match CanaryState::from_baseline_path(path.clone()) {
        Ok(state) => {
            info!(
                baseline = %path.display(),
                model = %state.baseline().model_label,
                interval_secs = state.interval_secs(),
                "canary baseline loaded"
            );
            state
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "canary baseline not loaded; running with empty baseline (status will be 'unknown'). Generate one via 'gateway-cli canary bootstrap'."
            );
            CanaryState::stub()
        }
    }
}
