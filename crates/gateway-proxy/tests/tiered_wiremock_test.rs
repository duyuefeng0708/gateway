//! Integration tests for the tiered detector against a wiremock-driven
//! fake Ollama HTTP server. Exercises the full OllamaDetector → HTTP →
//! JSON parse path that a mock-trait bypass cannot reach.
//!
//! Focus: silent-fallback correctness — deep failure must populate the
//! DetectionResult error field AND produce fast-only spans. This is the
//! signal the proxy metrics rely on per Codex T7.

use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::ollama::OllamaDetector;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_anonymizer::tiered::TieredDetector;
use gateway_common::types::ScanMode;
use ollama_rs::Ollama;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A well-formed Ollama /api/chat response wrapping an assistant message
/// whose content is a JSON array of PII spans. `content_json` is the
/// string payload we want the "model" to return.
fn chat_response_with_json(content_json: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "model": "gemma4:26b",
        "created_at": "2026-04-22T00:00:00Z",
        "message": {
            "role": "assistant",
            "content": content_json,
        },
        "done": true,
        "done_reason": "stop",
        "total_duration": 100_000_000u64,
        "load_duration": 0u64,
        "prompt_eval_count": 10u64,
        "prompt_eval_duration": 0u64,
        "eval_count": 10u64,
        "eval_duration": 0u64,
    }))
}

fn ollama_for(server: &MockServer) -> Ollama {
    let uri = server.uri();
    let without_scheme = uri
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (host, port_str) = without_scheme.split_once(':').expect("host:port");
    let port: u16 = port_str.parse().unwrap();
    Ollama::new(format!("http://{host}"), port)
}

#[tokio::test]
async fn deep_tier_500_falls_back_silently_with_error_captured() {
    let server = MockServer::start().await;

    // Fast tier: returns a well-formed empty span list for any chat call
    // until we override it. But we want deep to fail, so we layer a "for
    // the fast model name" matcher to return success and deep-model-name
    // to return 500.

    // wiremock does not let us filter on request JSON body by default in
    // a clean way; we just return success for the first call and failure
    // for subsequent calls by priority. Simpler: let all /api/chat return
    // 500, and we'll assert the fast tier itself failed — but that's not
    // the silent-fallback scenario. Instead: return success with empty
    // spans always, and separately make deep fail. We do this by
    // registering the fast-success mock with priority and the deep-fail
    // mock with a higher priority on a specific matcher.
    //
    // Simpler still: for this test, skip the two-model setup. Build
    // TieredDetector::new directly with a plain RegexDetector as the fast
    // tier (offline, succeeds every time) and the wiremock'd Ollama
    // detector as deep. When wiremock returns 500, deep should fail
    // silently and only regex spans should remain.

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(500).set_body_string("ollama broken"))
        .mount(&server)
        .await;

    let deep = OllamaDetector::new(ollama_for(&server), "gemma4:26b")
        .with_timeout(std::time::Duration::from_secs(3));

    let tiered = TieredDetector::new(
        Box::new(RegexDetector::new()),
        Box::new(RegexDetector::new()),
        Some(Box::new(deep)),
        ScanMode::Deep,
    );

    // Prompt with a detectable email span via regex; deep tier will error.
    let result = tiered
        .detect_with_metadata("please email alice@example.com about the thing")
        .await
        .expect("detect_with_metadata should succeed with silent fallback");

    // Deep was configured, attempted, and failed — the honest 4-state enum.
    assert!(result.deep_scan_available, "deep detector configured");
    assert!(result.deep_attempted, "deep was invoked");
    assert!(!result.deep_scan_used, "deep call failed, spans not merged");
    assert!(
        result.deep_error.is_some(),
        "deep_error must be captured for metric emission"
    );

    // Regex fast tier still produced a span for the email.
    assert!(
        !result.spans.is_empty(),
        "regex span should survive fallback"
    );
    assert!(
        result
            .spans
            .iter()
            .any(|s| s.pii_type == gateway_common::types::PiiType::Email),
        "email span should be in the fallback result"
    );
}

#[tokio::test]
async fn deep_tier_malformed_json_triggers_retry_then_fallback() {
    let server = MockServer::start().await;

    // Return non-JSON content twice (OllamaDetector retries once on parse
    // failure). After both tries fail to parse, deep_error is populated.
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(chat_response_with_json("not valid JSON at all"))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    let deep = OllamaDetector::new(ollama_for(&server), "gemma4:26b")
        .with_timeout(std::time::Duration::from_secs(3));

    let tiered = TieredDetector::new(
        Box::new(RegexDetector::new()),
        Box::new(RegexDetector::new()),
        Some(Box::new(deep)),
        ScanMode::Deep,
    );

    let result = tiered
        .detect_with_metadata("alice@example.com")
        .await
        .expect("detect_with_metadata should fall back silently");

    assert!(result.deep_attempted);
    assert!(!result.deep_scan_used);
    assert!(
        result.deep_error.is_some(),
        "parse failures should surface as deep_error"
    );
}

#[tokio::test]
async fn deep_tier_success_merges_spans() {
    let server = MockServer::start().await;

    // Return a valid JSON array with one span from the "deep" model.
    let deep_span_json =
        r#"[{"type":"PERSON","start":0,"end":4,"text":"John","confidence":0.9,"implicit":false}]"#;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(chat_response_with_json(deep_span_json))
        .mount(&server)
        .await;

    let deep = OllamaDetector::new(ollama_for(&server), "gemma4:26b")
        .with_timeout(std::time::Duration::from_secs(3));

    let tiered = TieredDetector::new(
        Box::new(RegexDetector::new()),
        Box::new(RegexDetector::new()),
        Some(Box::new(deep)),
        ScanMode::Deep,
    );

    let result = tiered
        .detect_with_metadata("John emailed alice@example.com")
        .await
        .expect("detect succeeds when deep returns valid JSON");

    assert!(result.deep_scan_available);
    assert!(result.deep_attempted);
    assert!(result.deep_scan_used, "deep succeeded, spans merged");
    assert!(result.deep_error.is_none());

    // Must have both the regex email span and the deep PERSON span.
    let has_email = result
        .spans
        .iter()
        .any(|s| s.pii_type == gateway_common::types::PiiType::Email);
    let has_person = result
        .spans
        .iter()
        .any(|s| s.pii_type == gateway_common::types::PiiType::Person);
    assert!(has_email, "regex email span");
    assert!(has_person, "deep person span");
}
