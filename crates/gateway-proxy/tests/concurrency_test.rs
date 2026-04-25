//! Verifies the handler's per-message bounded parallelism (Codex T4).
//!
//! Group E of the wire-up PR refactored the per-message detection loop
//! from sequential to bounded-parallel via `Arc<tokio::sync::Semaphore>`.
//! The semaphore is sized from `GatewayConfig::detection_concurrency`.
//! This test proves the bound is real: with N permits and M > N messages,
//! the observed max in-flight is exactly N, never higher.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use gateway_common::errors::DetectionError;
use gateway_common::types::PiiSpan;
use serde_json::json;
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// Detector that records concurrent in-flight calls via shared atomics.
/// Each call increments `in_flight`, tracks the max via `max_observed`,
/// sleeps briefly, then decrements. If the handler semaphore is correct,
/// `max_observed` never exceeds `expected_max`.
struct ConcurrencyProbeDetector {
    in_flight: Arc<AtomicUsize>,
    max_observed: Arc<AtomicUsize>,
    work_ms: u64,
}

impl ConcurrencyProbeDetector {
    fn new(in_flight: Arc<AtomicUsize>, max_observed: Arc<AtomicUsize>, work_ms: u64) -> Self {
        Self {
            in_flight,
            max_observed,
            work_ms,
        }
    }
}

#[async_trait]
impl PiiDetector for ConcurrencyProbeDetector {
    async fn detect(&self, _text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        // Enter the critical section: bump in_flight, record max.
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        // `fetch_max` returns the previous value; update max_observed atomically.
        self.max_observed.fetch_max(now, Ordering::SeqCst);

        // Hold the "work" window long enough that the scheduler can pile
        // other tasks up behind the permit. Without this sleep the tasks
        // may serialize purely through the async runtime's own scheduling
        // and we'd miss the concurrency signal we're trying to measure.
        tokio::time::sleep(Duration::from_millis(self.work_ms)).await;

        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(Vec::new())
    }

    fn name(&self) -> &str {
        "concurrency-probe"
    }
}

async fn echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::response::IntoResponse;

    async fn handler(req: axum::extract::Request) -> impl IntoResponse {
        let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        (StatusCode::OK, body)
    }

    let app: Router<()> = Router::new().fallback(handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (url, handle)
}

fn build_state(
    detector: Arc<dyn PiiDetector>,
    upstream_url: String,
    concurrency: usize,
) -> gateway_proxy::AppState {
    let config = GatewayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: upstream_url.clone(),
        upstream_url_openai: upstream_url,
        fast_model: "probe".to_string(),
        deep_model: "probe".to_string(),
        ollama_url: "http://localhost:11434".to_string(),
        scan_mode: gateway_common::types::ScanMode::Fast,
        db_path: ":memory:".to_string(),
        session_ttl: Duration::from_secs(3600),
        audit_retention_days: 30,
        audit_path: "/tmp/audit".to_string(),
        log_level: "debug".to_string(),
        show_score: false,
        max_request_size: 128 * 1024,
        detection_timeout: Duration::from_secs(5),
        upstream_timeout: Duration::from_secs(5),
        detection_concurrency: concurrency,
        escalation_confidence_threshold: 0.7,
        escalation_min_prompt_tokens: 200,
        rules_path: None,
        routing_config_path: None,
        streaming_enabled: false,
    };
    gateway_proxy::AppState {
        config,
        detector,
        session_store: Arc::new(futures_block_on(SessionStore::in_memory()).unwrap()),
        http_client: reqwest::Client::new(),
        router: gateway_proxy::Router::default_router(),
        warm: Arc::new(AtomicBool::new(true)),
        detection_semaphore: Arc::new(Semaphore::new(concurrency)),
        audit: gateway_anonymizer::audit::AuditHandle::spawn(tempfile::tempdir().unwrap().keep()).unwrap(),
        hmac: Arc::new(gateway_anonymizer::hmac_digest::HmacContext::from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "test").unwrap()),
        receipts: Arc::new(gateway_proxy::receipts::ReceiptCache::with_default_capacity(tempfile::tempdir().unwrap().keep())),
        transparency: gateway_proxy::transparency::TransparencyState::from_parts(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]), "test".to_string(), "http://unused".to_string(), std::time::Duration::from_secs(900)),
        canary: gateway_proxy::canary::CanaryState::stub(),
    }
}

fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
    // Only used for the session-store factory which is async. The outer
    // test is #[tokio::test] so we don't need a separate runtime; this
    // helper is a thin wrapper so `build_state` stays synchronous.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(fut)
    })
}

fn many_message_body(n: usize) -> String {
    // Anthropic-style body with N plain-text messages. The content has no
    // PII so regex-only tier returns zero spans, but the detector is still
    // invoked per-message — which is what we want for the concurrency
    // probe.
    let messages: Vec<_> = (0..n)
        .map(|i| {
            json!({
                "role": "user",
                "content": format!("message number {}", i)
            })
        })
        .collect();
    json!({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 16,
        "messages": messages,
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn semaphore_caps_in_flight_detections_to_configured_value() {
    let (upstream, _upstream_handle) = echo_upstream().await;

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_observed = Arc::new(AtomicUsize::new(0));
    let detector = Arc::new(ConcurrencyProbeDetector::new(
        Arc::clone(&in_flight),
        Arc::clone(&max_observed),
        50, // each detect holds the permit ~50ms
    ));

    const CONCURRENCY: usize = 2;
    const MESSAGES: usize = 10;

    let state = build_state(detector, upstream, CONCURRENCY);
    let router = gateway_proxy::build_server(state);

    let body = many_message_body(MESSAGES);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .header("x-api-key", "test-key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let max = max_observed.load(Ordering::SeqCst);
    assert!(
        max <= CONCURRENCY,
        "semaphore breach: max in-flight was {max}, expected <= {CONCURRENCY}"
    );
    // Also assert we actually DID parallelize — otherwise this test is
    // trivially passing because everything ran sequentially. With 10
    // messages at 50ms each, permits=2, a correctly-bounded parallel
    // implementation reaches max=2 (not 1).
    assert!(
        max >= CONCURRENCY,
        "expected max in-flight to reach CONCURRENCY={CONCURRENCY}, got {max}. \
         If max=1 the handler may have regressed to sequential execution."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn semaphore_of_one_serializes_detections() {
    // Regression guard: if a user sets GATEWAY_DETECTION_CONCURRENCY=1
    // the behaviour must match the pre-wire-up sequential loop exactly.
    let (upstream, _upstream_handle) = echo_upstream().await;

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_observed = Arc::new(AtomicUsize::new(0));
    let detector = Arc::new(ConcurrencyProbeDetector::new(
        Arc::clone(&in_flight),
        Arc::clone(&max_observed),
        20,
    ));

    let state = build_state(detector, upstream, 1);
    let router = gateway_proxy::build_server(state);

    let body = many_message_body(5);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .header("x-api-key", "test-key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let max = max_observed.load(Ordering::SeqCst);
    assert_eq!(
        max, 1,
        "concurrency=1 must produce strictly sequential detection, got max={max}"
    );
}
