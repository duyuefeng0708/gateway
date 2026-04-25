use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use serde_json::{json, Value};
use tokio::sync::Mutex;
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
        warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        detection_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
        audit: gateway_anonymizer::audit::AuditHandle::spawn(tempfile::tempdir().unwrap().keep()).unwrap(),
        hmac: Arc::new(gateway_anonymizer::hmac_digest::HmacContext::from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "test").unwrap()),
        receipts: Arc::new(gateway_proxy::receipts::ReceiptCache::with_default_capacity(tempfile::tempdir().unwrap().keep())),
    }
}

/// Build the test router (mirrors main.rs).
fn test_router(state: gateway_proxy::AppState) -> Router {
    Router::new()
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

/// Start a recording upstream that captures what was forwarded and returns a
/// fixed response. This lets tests inspect the anonymized request body
/// independently from the (deanonymized) response.
async fn start_recording_upstream(
    fixed_response: Value,
) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    use axum::extract::{Request as AxumRequest, State as AxumState};
    use axum::response::IntoResponse;

    #[derive(Clone)]
    struct RecState {
        captured: Arc<Mutex<Vec<String>>>,
        response: Value,
    }

    async fn recording_handler(
        AxumState(st): AxumState<RecState>,
        req: AxumRequest,
    ) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body_bytes).to_string();
        st.captured.lock().await.push(body_str);
        (StatusCode::OK, axum::Json(st.response.clone()))
    }

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let rec_state = RecState {
        captured: Arc::clone(&captured),
        response: fixed_response,
    };

    let app = Router::new()
        .fallback(recording_handler)
        .with_state(rec_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording server");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (url, captured, handle)
}

/// Helper: read the full response body as JSON.
async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
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
async fn no_pii_passes_through_unchanged() {
    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "What is the weather today?"}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Privacy score should be present.
    assert!(resp.headers().contains_key("x-gateway-privacy-score"));

    // Session header should be present.
    assert!(resp.headers().contains_key("x-gateway-session"));

    // Privacy score should be 100 (no PII).
    let score_header = resp
        .headers()
        .get("x-gateway-privacy-score")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        score_header.starts_with("100"),
        "expected 100, got: {score_header}"
    );

    // The echoed body should contain the original content unchanged.
    let echoed = body_json(resp).await;
    let content = echoed["messages"][0]["content"].as_str().unwrap();
    assert_eq!(content, "What is the weather today?");
}

#[tokio::test]
async fn pii_email_is_anonymized_in_forwarded_body() {
    // Use a recording upstream so we can inspect what was actually forwarded.
    let fixed_resp = json!({"reply": "ok"});
    let (upstream_url, captured, _handle) = start_recording_upstream(fixed_resp).await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "Please email alice@example.com about the project."}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Privacy score should be less than 100.
    let score_header = resp
        .headers()
        .get("x-gateway-privacy-score")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        !score_header.starts_with("100"),
        "expected < 100, got: {score_header}"
    );

    // Inspect what was actually sent to the upstream.
    let bodies = captured.lock().await;
    assert_eq!(bodies.len(), 1, "expected exactly one forwarded request");

    let forwarded: Value = serde_json::from_str(&bodies[0]).unwrap();
    let forwarded_content = forwarded["messages"][0]["content"]
        .as_str()
        .unwrap();

    assert!(
        !forwarded_content.contains("alice@example.com"),
        "email should have been anonymized in forwarded body, got: {forwarded_content}"
    );
    assert!(
        forwarded_content.contains("[EMAIL_"),
        "expected EMAIL placeholder in forwarded body: {forwarded_content}"
    );
}

#[tokio::test]
async fn empty_body_returns_400() {
    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_string(resp).await;
    assert!(body.contains("error"), "expected error body, got: {body}");
}

#[tokio::test]
async fn non_json_body_returns_400() {
    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from("this is not json"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_string(resp).await;
    assert!(body.contains("error"), "expected error body, got: {body}");
}

#[tokio::test]
async fn session_header_is_returned() {
    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "Hello, world!"}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-gateway-session"));

    let session_id = resp
        .headers()
        .get("x-gateway-session")
        .unwrap()
        .to_str()
        .unwrap();
    // Should be a valid UUID.
    assert_eq!(
        session_id.len(),
        36,
        "session id should be a UUID: {session_id}"
    );
}

#[tokio::test]
async fn provided_session_header_is_preserved() {
    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "Hello!"}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .header("x-gateway-session", "my-custom-session-42")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let session_id = resp
        .headers()
        .get("x-gateway-session")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(session_id, "my-custom-session-42");
}

#[tokio::test]
async fn privacy_score_header_present() {
    let (upstream_url, _handle) = start_echo_upstream().await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "My SSN is 123-45-6789."}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let score_header = resp
        .headers()
        .get("x-gateway-privacy-score")
        .unwrap()
        .to_str()
        .unwrap();
    // Should be formatted as "NN (CLASSIFICATION)".
    assert!(
        score_header.contains('(') && score_header.contains(')'),
        "expected formatted score, got: {score_header}"
    );
    // SSN has weight 12 => score = 100 - 12 = 88 => MEDIUM
    assert!(
        score_header.contains("MEDIUM") || score_header.contains("HIGH"),
        "expected MEDIUM or HIGH, got: {score_header}"
    );
}

#[tokio::test]
async fn code_blocks_are_preserved() {
    // Use a recording upstream so we can inspect the forwarded body directly.
    let fixed_resp = json!({"reply": "ok"});
    let (upstream_url, captured, _handle) = start_recording_upstream(fixed_resp).await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    // The email inside the code block should NOT be anonymized.
    // The email outside the code block SHOULD be anonymized.
    let body = json!({
        "messages": [
            {"role": "user", "content": "Email bob@test.com. Code: ```config email=alice@example.com``` done."}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Inspect the forwarded body.
    let bodies = captured.lock().await;
    assert_eq!(bodies.len(), 1);

    let forwarded: Value = serde_json::from_str(&bodies[0]).unwrap();
    let content = forwarded["messages"][0]["content"].as_str().unwrap();

    // The code block email should be preserved.
    assert!(
        content.contains("alice@example.com"),
        "code block email should be preserved, got: {content}"
    );
    // The non-code-block email should be anonymized.
    assert!(
        !content.contains("bob@test.com"),
        "non-code-block email should be anonymized, got: {content}"
    );
}

#[tokio::test]
async fn response_deanonymization_works() {
    // Build a mock upstream that returns a response containing a placeholder
    // from the forwarded request.
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn placeholder_echo(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&body_bytes).unwrap();
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap_or("");

        // The upstream "uses" the placeholder in its response text.
        let response = json!({
            "content": [{"type": "text", "text": format!("I will email {content}")}]
        });
        (StatusCode::OK, axum::Json(response))
    }

    let app = Router::new().fallback(placeholder_echo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let upstream_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "Contact alice@example.com please."}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp_body = body_string(resp).await;

    // The response should contain the ORIGINAL email, not the placeholder.
    assert!(
        resp_body.contains("alice@example.com"),
        "response should be deanonymized, got: {resp_body}"
    );
    assert!(
        !resp_body.contains("[EMAIL_"),
        "placeholder should have been restored, got: {resp_body}"
    );
}
