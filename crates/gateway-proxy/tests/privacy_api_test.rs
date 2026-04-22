use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Build a test AppState with an in-memory session store.
async fn test_state() -> gateway_proxy::AppState {
    let session_store = SessionStore::in_memory()
        .await
        .expect("in-memory session store");

    let detector = RegexDetector::new();
    let http_client = reqwest::Client::new();

    let config = GatewayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: "http://localhost:1".to_string(),
        upstream_url_openai: "http://localhost:1".to_string(),
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
    }
}

/// Build a router with the privacy API routes.
fn test_router(state: gateway_proxy::AppState) -> Router {
    Router::new()
        .route("/v1/anonymize", post(gateway_proxy::anonymize))
        .route("/v1/deanonymize", post(gateway_proxy::deanonymize))
        .with_state(state)
}

/// Helper: read the full response body as JSON.
async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn anonymize_text_with_pii_returns_anonymized_text_and_spans() {
    let state = test_state().await;
    let app = test_router(state);

    let body = json!({
        "text": "Please email alice@example.com about the project."
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/anonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;

    // anonymized text should not contain original email
    let anonymized = json["anonymized"].as_str().unwrap();
    assert!(
        !anonymized.contains("alice@example.com"),
        "email should be anonymized, got: {anonymized}"
    );
    assert!(
        anonymized.contains("[EMAIL_"),
        "expected EMAIL placeholder, got: {anonymized}"
    );

    // session_id should be present (auto-generated)
    let session_id = json["session_id"].as_str().unwrap();
    assert!(!session_id.is_empty());

    // score should be less than 100
    let score = json["score"].as_u64().unwrap();
    assert!(score < 100, "expected score < 100, got: {score}");

    // classification should be present
    let classification = json["classification"].as_str().unwrap();
    assert!(
        ["LOW", "MEDIUM", "HIGH"].contains(&classification),
        "unexpected classification: {classification}"
    );

    // spans should be non-empty
    let spans = json["spans"].as_array().unwrap();
    assert!(!spans.is_empty(), "expected at least one span");

    let span = &spans[0];
    assert_eq!(span["type"].as_str().unwrap(), "EMAIL");
    assert!(span["confidence"].as_f64().unwrap() > 0.0);
    assert!(span.get("start").is_some());
    assert!(span.get("end").is_some());
    assert!(span.get("text").is_some());
    assert!(span.get("implicit").is_some());
}

#[tokio::test]
async fn deanonymize_with_valid_session_restores_text() {
    let state = test_state().await;

    // First, anonymize some text.
    let app = test_router(state.clone());
    let body = json!({
        "text": "Contact alice@example.com please."
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/anonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let anon_json = body_json(resp).await;
    let anonymized = anon_json["anonymized"].as_str().unwrap();
    let session_id = anon_json["session_id"].as_str().unwrap();

    // Now deanonymize.
    let app = test_router(state);
    let body = json!({
        "text": anonymized,
        "session_id": session_id
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/deanonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let de_json = body_json(resp).await;
    let restored = de_json["restored"].as_str().unwrap();
    assert_eq!(restored, "Contact alice@example.com please.");

    let replaced = de_json["placeholders_replaced"].as_u64().unwrap();
    assert!(replaced >= 1, "expected at least 1 placeholder replaced, got: {replaced}");
}

#[tokio::test]
async fn round_trip_anonymize_then_deanonymize() {
    let state = test_state().await;
    let original = "My SSN is 123-45-6789 and email is bob@test.com.";

    // Anonymize.
    let app = test_router(state.clone());
    let body = json!({
        "text": original,
        "session_id": "round-trip-session"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/anonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let anon_json = body_json(resp).await;
    let anonymized = anon_json["anonymized"].as_str().unwrap();
    assert_eq!(anon_json["session_id"].as_str().unwrap(), "round-trip-session");

    // The anonymized text should not contain original PII.
    assert!(!anonymized.contains("123-45-6789"));
    assert!(!anonymized.contains("bob@test.com"));

    // Deanonymize.
    let app = test_router(state);
    let body = json!({
        "text": anonymized,
        "session_id": "round-trip-session"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/deanonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let de_json = body_json(resp).await;
    let restored = de_json["restored"].as_str().unwrap();
    assert_eq!(restored, original);
}

#[tokio::test]
async fn anonymize_with_no_pii_returns_score_100_and_original_text() {
    let state = test_state().await;
    let app = test_router(state);

    let body = json!({
        "text": "The weather is nice today."
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/anonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["anonymized"].as_str().unwrap(), "The weather is nice today.");
    assert_eq!(json["score"].as_u64().unwrap(), 100);
    assert_eq!(json["classification"].as_str().unwrap(), "LOW");
    assert!(json["spans"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn deanonymize_with_unknown_session_returns_404() {
    let state = test_state().await;
    let app = test_router(state);

    let body = json!({
        "text": "some text with [EMAIL_deadbeef]",
        "session_id": "nonexistent-session-id"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/deanonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = body_json(resp).await;
    assert!(
        json["error"].as_str().unwrap().contains("session not found"),
        "expected session not found error, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn anonymize_missing_text_field_returns_400() {
    let state = test_state().await;
    let app = test_router(state);

    // Send a body without "text" field.
    let body = json!({
        "session_id": "some-session"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/anonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert!(
        json["error"].as_str().unwrap().contains("text"),
        "expected error about text field, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn deanonymize_missing_session_id_returns_400() {
    let state = test_state().await;
    let app = test_router(state);

    // Send a body with text but no session_id.
    let body = json!({
        "text": "some text"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/deanonymize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert!(
        json["error"].as_str().unwrap().contains("session_id"),
        "expected error about session_id field, got: {}",
        json["error"]
    );
}
