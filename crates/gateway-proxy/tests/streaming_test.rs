use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::session::SessionStore;
use gateway_common::config::GatewayConfig;
use serde_json::{json, Value};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a test AppState with streaming enabled.
async fn test_state_streaming(upstream_url: &str) -> gateway_proxy::AppState {
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
        streaming_enabled: true,
    };

    gateway_proxy::AppState {
        config,
        detector: Arc::new(detector),
        session_store: Arc::new(session_store),
        http_client,
        router: gateway_proxy::Router::default_router(),
    }
}

/// Build a test AppState with streaming disabled (for backward compat test).
async fn test_state_no_streaming(upstream_url: &str) -> gateway_proxy::AppState {
    let mut state = test_state_streaming(upstream_url).await;
    state.config.streaming_enabled = false;
    state
}

fn test_router(state: gateway_proxy::AppState) -> Router {
    Router::new()
        .fallback(gateway_proxy::handle_proxy_request)
        .with_state(state)
}

/// Helper: read the full response body as string.
async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).to_string()
}

/// Start a mock upstream that returns SSE events with Anthropic format.
/// The `tokens` are sent as individual `content_block_delta` events.
async fn start_sse_upstream_anthropic(
    tokens: Vec<String>,
) -> (String, tokio::task::JoinHandle<()>) {
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    let tokens = Arc::new(tokens);

    let handler = {
        let tokens = Arc::clone(&tokens);
        move |_req: AxumRequest| {
            let tokens = Arc::clone(&tokens);
            async move {
                let mut body = String::new();

                // Start event.
                body.push_str("data: {\"type\":\"content_block_start\"}\n\n");

                // Text delta events.
                for token in tokens.iter() {
                    let event = json!({
                        "type": "content_block_delta",
                        "delta": {
                            "type": "text_delta",
                            "text": token,
                        }
                    });
                    body.push_str(&format!("data: {}\n\n", serde_json::to_string(&event).unwrap()));
                }

                // End events.
                body.push_str("data: {\"type\":\"content_block_stop\"}\n\n");
                body.push_str("data: [DONE]\n\n");

                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    body,
                )
                    .into_response()
            }
        }
    };

    let app = Router::new().fallback(handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind SSE upstream");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (url, handle)
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn streaming_anthropic_deanonymizes_sse_events() {
    // The upstream mock returns SSE tokens that include a placeholder.
    // Since we don't know the exact placeholder ID until anonymization runs,
    // we use a mock that echoes placeholders from the request.
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn sse_echo(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&body_bytes).unwrap();
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap_or("nothing")
            .to_string();

        // Split the content to create multiple SSE events.
        let mut sse_body = String::new();
        let event = json!({
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": format!("Hello {content}!")}
        });
        sse_body.push_str(&format!("data: {}\n\n", serde_json::to_string(&event).unwrap()));
        sse_body.push_str("data: [DONE]\n\n");

        (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            sse_body,
        )
            .into_response()
    }

    let app = Router::new().fallback(sse_echo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let upstream_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let state = test_state_streaming(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "stream": true,
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

    // Verify streaming headers.
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert_eq!(ct, "text/event-stream");

    assert!(resp.headers().contains_key("x-gateway-session"));
    assert!(resp.headers().contains_key("x-gateway-privacy-score"));

    let resp_body = body_string(resp).await;

    // The response should contain the original email (deanonymized).
    assert!(
        resp_body.contains("alice@example.com"),
        "SSE response should be deanonymized, got: {resp_body}"
    );
    // The response should not contain the placeholder.
    assert!(
        !resp_body.contains("[EMAIL_"),
        "placeholder should have been restored in SSE, got: {resp_body}"
    );
    // Should end with [DONE].
    assert!(
        resp_body.contains("[DONE]"),
        "SSE stream should end with [DONE], got: {resp_body}"
    );
}

#[tokio::test]
async fn streaming_openai_deanonymizes_sse_events() {
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn sse_echo_openai(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&body_bytes).unwrap();
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap_or("nothing")
            .to_string();

        let mut sse_body = String::new();
        let event = json!({
            "choices": [{"delta": {"content": format!("Reply to {content}")}}]
        });
        sse_body.push_str(&format!("data: {}\n\n", serde_json::to_string(&event).unwrap()));
        sse_body.push_str("data: [DONE]\n\n");

        (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            sse_body,
        )
            .into_response()
    }

    let app = Router::new().fallback(sse_echo_openai);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let upstream_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let state = test_state_streaming(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "stream": true,
        "messages": [
            {"role": "user", "content": "Email bob@test.com about this."}
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

    assert!(
        resp_body.contains("bob@test.com"),
        "OpenAI SSE response should be deanonymized, got: {resp_body}"
    );
    assert!(
        !resp_body.contains("[EMAIL_"),
        "placeholder should have been restored, got: {resp_body}"
    );
}

#[tokio::test]
async fn non_streaming_request_still_uses_buffered_path() {
    // This test ensures that when stream:false (or not set), the existing
    // buffered path is used even when streaming is enabled in config.
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn json_echo(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&body_bytes).unwrap();
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let response = json!({
            "content": [{"type": "text", "text": format!("I will email {content}")}]
        });
        (StatusCode::OK, axum::Json(response))
    }

    let app = Router::new().fallback(json_echo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let upstream_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let state = test_state_streaming(&upstream_url).await;
    let app = test_router(state);

    // Request WITHOUT stream:true.
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

    // Buffered path should deanonymize the response.
    assert!(
        resp_body.contains("alice@example.com"),
        "buffered response should be deanonymized, got: {resp_body}"
    );
    assert!(
        !resp_body.contains("[EMAIL_"),
        "placeholder should have been restored, got: {resp_body}"
    );
}

#[tokio::test]
async fn streaming_disabled_config_falls_back_to_buffered() {
    // When GATEWAY_STREAMING is false, even stream:true requests use buffered path.
    use axum::extract::Request as AxumRequest;
    use axum::response::IntoResponse;

    async fn json_echo(req: AxumRequest) -> impl IntoResponse {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        (StatusCode::OK, body_bytes)
    }

    let app = Router::new().fallback(json_echo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let upstream_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let state = test_state_no_streaming(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "stream": true,
        "messages": [
            {"role": "user", "content": "Hello world"}
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

    // Should NOT have SSE content-type (buffered path used).
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !ct.contains("text/event-stream"),
        "should use buffered path when streaming disabled, content-type: {ct}"
    );
}

#[tokio::test]
async fn streaming_no_pii_passes_through_sse_unchanged() {
    // When there is no PII, the SSE tokens should pass through unmodified.
    let tokens = vec![
        "Hello ".to_string(),
        "world!".to_string(),
    ];
    let (upstream_url, _handle) = start_sse_upstream_anthropic(tokens).await;

    let state = test_state_streaming(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "stream": true,
        "messages": [
            {"role": "user", "content": "What is the weather?"}
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
    assert!(resp_body.contains("Hello "), "got: {resp_body}");
    assert!(resp_body.contains("world!"), "got: {resp_body}");
    assert!(resp_body.contains("[DONE]"), "got: {resp_body}");
}

#[tokio::test]
async fn streaming_response_has_gateway_headers() {
    let tokens = vec!["test".to_string()];
    let (upstream_url, _handle) = start_sse_upstream_anthropic(tokens).await;

    let state = test_state_streaming(&upstream_url).await;
    let app = test_router(state);

    let body = json!({
        "stream": true,
        "messages": [
            {"role": "user", "content": "Hello"}
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

    // Gateway headers should be present on streaming responses.
    assert!(
        resp.headers().contains_key("x-gateway-session"),
        "streaming response missing x-gateway-session header"
    );
    assert!(
        resp.headers().contains_key("x-gateway-privacy-score"),
        "streaming response missing x-gateway-privacy-score header"
    );
    assert_eq!(
        resp.headers().get("cache-control").unwrap().to_str().unwrap(),
        "no-cache"
    );
}
