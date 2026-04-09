use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use gateway_proxy::metrics;
use serde_json::json;
use tower::ServiceExt;

/// Build a test AppState with an in-memory session store and a mock upstream.
async fn test_state(upstream_url: &str) -> gateway_proxy::AppState {
    let session_store = SessionStore::in_memory()
        .await
        .expect("in-memory session store");

    let detector = RegexDetector::new();
    let http_client = reqwest::Client::new();

    let config = GatewayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: upstream_url.to_string(),
        upstream_url_openai: upstream_url.to_string(),
        fast_model: "test".to_string(),
        deep_model: "test".to_string(),
        ollama_url: "http://localhost:11434".to_string(),
        scan_mode: gateway_common::types::ScanMode::Fast,
        db_path: ":memory:".to_string(),
        session_ttl: std::time::Duration::from_secs(3600),
        audit_retention_days: 30,
        audit_path: "/tmp/audit".to_string(),
        log_level: "debug".to_string(),
        show_score: true,
        max_request_size: 128 * 1024,
        model_timeout: std::time::Duration::from_secs(5),
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
    }
}

/// Build a test router that includes the /metrics endpoint and the fallback
/// proxy handler, mirroring main.rs.
fn test_router(state: gateway_proxy::AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .fallback(gateway_proxy::handle_proxy_request)
        .with_state(state)
}

/// Start a mock upstream that echoes back the request body unchanged.
async fn start_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn echo_handler(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        (StatusCode::OK, body_bytes)
    }

    let app = Router::new().fallback(echo_handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (url, handle)
}

/// Helper: read the full response body as string.
async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).to_string()
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn metrics_endpoint_returns_200_with_prometheus_content_type() {
    // Ensure the Prometheus recorder is installed (idempotent across tests).
    metrics::try_init_metrics();

    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .expect("content-type header should be present")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/plain"),
        "expected text/plain content type, got: {content_type}"
    );
}

#[tokio::test]
async fn metrics_endpoint_contains_expected_metric_names_after_request() {
    metrics::try_init_metrics();

    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    // First, send a proxy request with PII so counters get incremented.
    let proxy_body = json!({
        "messages": [
            {"role": "user", "content": "Email alice@example.com about SSN 123-45-6789."}
        ]
    });

    let proxy_req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&proxy_body).unwrap()))
        .unwrap();

    let proxy_resp = app.clone().oneshot(proxy_req).await.unwrap();
    assert_eq!(proxy_resp.status(), StatusCode::OK);

    // Now fetch /metrics and check for expected metric names.
    let metrics_req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let metrics_resp = app.oneshot(metrics_req).await.unwrap();
    assert_eq!(metrics_resp.status(), StatusCode::OK);

    let metrics_body = body_string(metrics_resp).await;

    // Check that key metric families are present.
    assert!(
        metrics_body.contains("gateway_requests_total"),
        "expected gateway_requests_total in metrics output:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("gateway_pii_detected_total"),
        "expected gateway_pii_detected_total in metrics output:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("gateway_request_duration_seconds"),
        "expected gateway_request_duration_seconds in metrics output:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("gateway_upstream_duration_seconds"),
        "expected gateway_upstream_duration_seconds in metrics output:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("gateway_model_inference_duration_seconds"),
        "expected gateway_model_inference_duration_seconds in metrics output:\n{metrics_body}"
    );
}

#[tokio::test]
async fn metrics_counters_increment_after_proxy_request() {
    metrics::try_init_metrics();

    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    // Send a proxy request with an email.
    let proxy_body = json!({
        "messages": [
            {"role": "user", "content": "Please contact bob@test.com."}
        ]
    });

    let proxy_req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&proxy_body).unwrap()))
        .unwrap();

    let proxy_resp = app.clone().oneshot(proxy_req).await.unwrap();
    assert_eq!(proxy_resp.status(), StatusCode::OK);

    // Fetch metrics.
    let metrics_req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let metrics_resp = app.oneshot(metrics_req).await.unwrap();
    let metrics_body = body_string(metrics_resp).await;

    // The request counter for status=200 should have a non-zero value.
    assert!(
        metrics_body.contains("gateway_requests_total"),
        "expected gateway_requests_total in output"
    );

    // The PII detected counter for EMAIL type should be present.
    assert!(
        metrics_body.contains("gateway_pii_detected_total"),
        "expected gateway_pii_detected_total in output"
    );
}
