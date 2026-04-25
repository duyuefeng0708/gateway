//! Integration tests for the /ready endpoint.
//!
//! Scope: verify that /ready reflects the `warm` AtomicBool flag honestly,
//! using `build_server` to construct the router exactly as main.rs does.
//! No Ollama or upstream dependencies — pure state-machine test.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use tokio::sync::Semaphore;
use tower::ServiceExt;

async fn make_state(warm: bool) -> gateway_proxy::AppState {
    let session_store = SessionStore::in_memory()
        .await
        .expect("in-memory session store");
    let detector = RegexDetector::new();
    let http_client = reqwest::Client::new();
    let config = GatewayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: "http://upstream".to_string(),
        upstream_url_openai: "http://upstream-openai".to_string(),
        fast_model: "gemma4:e4b".to_string(),
        deep_model: "gemma4:26b".to_string(),
        ollama_url: "http://localhost:11434".to_string(),
        scan_mode: gateway_common::types::ScanMode::Fast,
        db_path: ":memory:".to_string(),
        session_ttl: std::time::Duration::from_secs(3600),
        audit_retention_days: 30,
        audit_path: "/tmp/audit".to_string(),
        log_level: "debug".to_string(),
        show_score: true,
        max_request_size: 128 * 1024,
        detection_timeout: std::time::Duration::from_secs(5),
        upstream_timeout: std::time::Duration::from_secs(5),
        detection_concurrency: 2,
        escalation_confidence_threshold: 0.7,
        escalation_min_prompt_tokens: 200,
        rules_path: None,
        routing_config_path: None,
        streaming_enabled: false,
    };

    gateway_proxy::AppState {
        config,
        detector: Arc::new(detector),
        session_store: Arc::new(session_store),
        http_client,
        router: gateway_proxy::Router::default_router(),
        warm: Arc::new(AtomicBool::new(warm)),
        detection_semaphore: Arc::new(Semaphore::new(2)),
        audit: gateway_anonymizer::audit::AuditHandle::spawn(tempfile::tempdir().unwrap().keep())
            .unwrap(),
        hmac: Arc::new(
            gateway_anonymizer::hmac_digest::HmacContext::from_hex(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                "test",
            )
            .unwrap(),
        ),
        receipts: Arc::new(
            gateway_proxy::receipts::ReceiptCache::with_default_capacity(
                tempfile::tempdir().unwrap().keep(),
            ),
        ),
        transparency: gateway_proxy::transparency::TransparencyState::from_parts(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            "test".to_string(),
            "http://unused".to_string(),
            std::time::Duration::from_secs(900),
        ),
        canary: gateway_proxy::canary::CanaryState::stub(),
    }
}

#[tokio::test]
async fn ready_returns_503_when_warm_is_false() {
    let state = make_state(false).await;
    let router = gateway_proxy::build_server(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"warming");
}

#[tokio::test]
async fn ready_returns_200_when_warm_is_true() {
    let state = make_state(true).await;
    let router = gateway_proxy::build_server(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn ready_reflects_runtime_warm_transition() {
    // Make state initially NOT warm, then flip warm mid-request cycle. The
    // state is shared via Arc, so /ready should see the updated value on
    // the next request. This models the real warm-up flow: the listener
    // binds early-ish (in this test we just construct the router), the
    // warm-up probe runs, then flips the flag.
    let state = make_state(false).await;
    let router = gateway_proxy::build_server(state.clone());

    // Pre-warm: 503
    let pre = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pre.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Flip the flag as warm-up would.
    state.warm.store(true, Ordering::Release);

    // Post-warm: 200
    let post = router
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::OK);
}
