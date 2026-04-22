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

// ---------------------------------------------------------------------------
// Helpers (shared with handler_test.rs but duplicated to keep tests self-contained)
// ---------------------------------------------------------------------------

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
    }
}

fn test_router(state: gateway_proxy::AppState) -> Router {
    Router::new()
        .fallback(gateway_proxy::handle_proxy_request)
        .with_state(state)
}

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

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).to_string()
}

// ===========================================================================
// Unit-level tests for the format module (public API)
// ===========================================================================

#[test]
fn detect_format_openai_path() {
    use gateway_proxy::format::{detect_format, ApiFormat};
    assert_eq!(detect_format("/v1/chat/completions"), ApiFormat::OpenAi);
}

#[test]
fn detect_format_anthropic_path() {
    use gateway_proxy::format::{detect_format, ApiFormat};
    assert_eq!(detect_format("/v1/messages"), ApiFormat::Anthropic);
}

#[test]
fn detect_format_unknown_defaults_to_anthropic() {
    use gateway_proxy::format::{detect_format, ApiFormat};
    assert_eq!(detect_format("/unknown"), ApiFormat::Anthropic);
    assert_eq!(detect_format("/"), ApiFormat::Anthropic);
}

#[test]
fn extract_anthropic_messages_from_body() {
    use gateway_proxy::format::{extract_messages, ApiFormat};
    let body = json!({
        "messages": [
            {"role": "user", "content": "Hello Alice"},
            {"role": "assistant", "content": "Hi!"}
        ]
    });
    let result = extract_messages(&body, ApiFormat::Anthropic).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].1, "Hello Alice");
    assert_eq!(result[1].1, "Hi!");
}

#[test]
fn extract_openai_messages_from_body() {
    use gateway_proxy::format::{extract_messages, ApiFormat};
    let body = json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "Be helpful."},
            {"role": "user", "content": "Hello Bob"}
        ]
    });
    let result = extract_messages(&body, ApiFormat::OpenAi).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].1, "Be helpful.");
    assert_eq!(result[1].1, "Hello Bob");
}

#[test]
fn rebuild_anthropic_body_replaces_content() {
    use gateway_proxy::format::{rebuild_body, ApiFormat};
    let mut body = json!({
        "messages": [
            {"role": "user", "content": "original"}
        ]
    });
    rebuild_body(&mut body, &[(0, "replaced".to_string())], ApiFormat::Anthropic).unwrap();
    assert_eq!(body["messages"][0]["content"].as_str().unwrap(), "replaced");
}

#[test]
fn rebuild_openai_body_replaces_content() {
    use gateway_proxy::format::{rebuild_body, ApiFormat};
    let mut body = json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "system msg"},
            {"role": "user", "content": "original"}
        ]
    });
    rebuild_body(&mut body, &[(1, "replaced".to_string())], ApiFormat::OpenAi).unwrap();
    assert_eq!(body["messages"][1]["content"].as_str().unwrap(), "replaced");
    // system message unchanged
    assert_eq!(
        body["messages"][0]["content"].as_str().unwrap(),
        "system msg"
    );
}

#[test]
fn extract_anthropic_response_content() {
    use gateway_proxy::format::{extract_response_content, ApiFormat};
    let body = r#"{"content":[{"type":"text","text":"Hello from Claude"}]}"#;
    assert_eq!(
        extract_response_content(body, ApiFormat::Anthropic).unwrap(),
        "Hello from Claude"
    );
}

#[test]
fn extract_openai_response_content() {
    use gateway_proxy::format::{extract_response_content, ApiFormat};
    let body =
        r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"Hello from GPT"}}]}"#;
    assert_eq!(
        extract_response_content(body, ApiFormat::OpenAi).unwrap(),
        "Hello from GPT"
    );
}

#[test]
fn rebuild_anthropic_response() {
    use gateway_proxy::format::{rebuild_response, ApiFormat};
    let body = r#"{"content":[{"type":"text","text":"placeholder"}]}"#;
    let result = rebuild_response(body, "real text", ApiFormat::Anthropic);
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["content"][0]["text"].as_str().unwrap(), "real text");
}

#[test]
fn rebuild_openai_response() {
    use gateway_proxy::format::{rebuild_response, ApiFormat};
    let body = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"placeholder"}}]}"#;
    let result = rebuild_response(body, "real text", ApiFormat::OpenAi);
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(
        parsed["choices"][0]["message"]["content"].as_str().unwrap(),
        "real text"
    );
}

// ===========================================================================
// Integration tests: OpenAI-format request through the full proxy handler
// ===========================================================================

#[tokio::test]
async fn openai_format_no_pii_passes_through() {
    let fixed_resp = json!({
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "The weather is sunny."}
        }]
    });
    let (upstream_url, captured, _handle) = start_recording_upstream(fixed_resp).await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "What is the weather today?"}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

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

    // Forwarded body should contain original content.
    let bodies = captured.lock().await;
    assert_eq!(bodies.len(), 1);
    let forwarded: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(
        forwarded["messages"][1]["content"].as_str().unwrap(),
        "What is the weather today?"
    );
}

#[tokio::test]
async fn openai_format_pii_is_anonymized() {
    let fixed_resp = json!({
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "I will send the email."}
        }]
    });
    let (upstream_url, captured, _handle) = start_recording_upstream(fixed_resp).await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Please email alice@example.com about the project."}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
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

    // The forwarded body should have the email anonymized.
    let bodies = captured.lock().await;
    assert_eq!(bodies.len(), 1);
    let forwarded: Value = serde_json::from_str(&bodies[0]).unwrap();
    let forwarded_content = forwarded["messages"][0]["content"].as_str().unwrap();
    assert!(
        !forwarded_content.contains("alice@example.com"),
        "email should be anonymized: {forwarded_content}"
    );
    assert!(
        forwarded_content.contains("[EMAIL_"),
        "expected EMAIL placeholder: {forwarded_content}"
    );
}

#[tokio::test]
async fn openai_format_response_deanonymization() {
    // Build a mock that echoes back a response containing whatever placeholder
    // the gateway sent, wrapped in OpenAI response format.
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn openai_echo(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&body_bytes).unwrap();
        let content = body["messages"][0]["content"].as_str().unwrap_or("");

        let response = json!({
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": format!("I will contact {content}")
                }
            }]
        });
        (StatusCode::OK, axum::Json(response))
    }

    let app = Router::new().fallback(openai_echo);
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
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Contact alice@example.com please."}
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp_body = body_string(resp).await;

    // The response should contain the original email, not the placeholder.
    assert!(
        resp_body.contains("alice@example.com"),
        "response should be deanonymized, got: {resp_body}"
    );
    assert!(
        !resp_body.contains("[EMAIL_"),
        "placeholder should have been restored, got: {resp_body}"
    );
}

#[tokio::test]
async fn anthropic_format_still_works_after_refactor() {
    // Regression test: the original Anthropic path must still work.
    let fixed_resp = json!({"content": [{"type": "text", "text": "Hello!"}]});
    let (upstream_url, captured, _handle) = start_recording_upstream(fixed_resp).await;
    let state = test_state(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "messages": [
            {"role": "user", "content": "Please email bob@test.com about the project."}
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

    let bodies = captured.lock().await;
    assert_eq!(bodies.len(), 1);
    let forwarded: Value = serde_json::from_str(&bodies[0]).unwrap();
    let forwarded_content = forwarded["messages"][0]["content"].as_str().unwrap();
    assert!(
        !forwarded_content.contains("bob@test.com"),
        "email should be anonymized: {forwarded_content}"
    );
    assert!(
        forwarded_content.contains("[EMAIL_"),
        "expected EMAIL placeholder: {forwarded_content}"
    );
}
