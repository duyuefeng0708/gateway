use std::path::Path;

use async_trait::async_trait;
use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::eval::{self, BenchmarkEntry, LabeledSpan, Metrics};
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, PiiType};

// -----------------------------------------------------------------------
// RegexDetector tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn regex_detects_email() {
    let det = RegexDetector::new();
    let spans = det
        .detect("Send to alice@example.com please")
        .await
        .unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].pii_type, PiiType::Email);
    assert_eq!(spans[0].text, "alice@example.com");
    assert_eq!(spans[0].confidence, 1.0);
    assert!(!spans[0].implicit);
}

#[tokio::test]
async fn regex_detects_ssn() {
    let det = RegexDetector::new();
    let spans = det.detect("SSN: 123-45-6789").await.unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].pii_type, PiiType::Ssn);
    assert_eq!(spans[0].text, "123-45-6789");
}

#[tokio::test]
async fn regex_detects_phone() {
    let det = RegexDetector::new();
    let spans = det.detect("Phone: (555) 123-4567").await.unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].pii_type, PiiType::Phone);
}

#[tokio::test]
async fn regex_clean_text_empty() {
    let det = RegexDetector::new();
    let spans = det
        .detect("Just a regular sentence about nothing sensitive.")
        .await
        .unwrap();
    assert!(spans.is_empty());
}

// -----------------------------------------------------------------------
// OllamaDetector parse tests (no network needed -- mock via custom detector)
// -----------------------------------------------------------------------

/// Mock detector that returns a canned Ollama-style JSON response.
struct MockOllamaDetector {
    response: String,
}

#[async_trait]
impl PiiDetector for MockOllamaDetector {
    async fn detect(&self, _text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        // Reuse OllamaDetector's parse logic indirectly by simulating what
        // the real detector does: parse JSON from the model response.
        let trimmed = self.response.trim();
        if trimmed.is_empty() {
            return Err(DetectionError::EmptyModelResponse);
        }

        let json_str = if trimmed.starts_with("```") {
            trimmed
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim()
        } else {
            trimmed
        };

        #[derive(serde::Deserialize)]
        struct RawSpan {
            #[serde(rename = "type")]
            pii_type: String,
            start: usize,
            end: usize,
            text: String,
            confidence: f64,
            #[serde(default)]
            implicit: bool,
        }

        let raw_spans: Vec<RawSpan> = serde_json::from_str(json_str)
            .map_err(|e| DetectionError::ModelOutputParseError(e.to_string()))?;

        let spans = raw_spans
            .into_iter()
            .filter_map(|s| {
                let pii_type = match s.pii_type.as_str() {
                    "PERSON" => PiiType::Person,
                    "EMAIL" => PiiType::Email,
                    "PHONE" => PiiType::Phone,
                    "SSN" => PiiType::Ssn,
                    "CREDENTIAL" => PiiType::Credential,
                    "ORGANIZATION" => PiiType::Organization,
                    "LOCATION" => PiiType::Location,
                    _ => return None,
                };
                Some(PiiSpan {
                    pii_type,
                    start: s.start,
                    end: s.end,
                    text: s.text,
                    confidence: s.confidence,
                    implicit: s.implicit,
                })
            })
            .collect();

        Ok(spans)
    }

    fn name(&self) -> &str {
        "mock-ollama"
    }
}

#[tokio::test]
async fn mock_ollama_returns_correct_spans() {
    let json = r#"[
        {"type":"PERSON","start":0,"end":10,"text":"John Smith","confidence":0.95,"implicit":false},
        {"type":"EMAIL","start":22,"end":41,"text":"john@example.com","confidence":1.0,"implicit":false}
    ]"#;
    let det = MockOllamaDetector {
        response: json.to_string(),
    };
    let spans = det.detect("ignored").await.unwrap();
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].pii_type, PiiType::Person);
    assert_eq!(spans[0].text, "John Smith");
    assert_eq!(spans[1].pii_type, PiiType::Email);
}

#[tokio::test]
async fn mock_ollama_malformed_json_returns_error() {
    let det = MockOllamaDetector {
        response: "this is not valid json".to_string(),
    };
    let result = det.detect("anything").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        DetectionError::ModelOutputParseError(_) => {}
        other => panic!("expected ModelOutputParseError, got: {other:?}"),
    }
}

#[tokio::test]
async fn mock_ollama_empty_response_returns_error() {
    let det = MockOllamaDetector {
        response: "".to_string(),
    };
    let result = det.detect("anything").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        DetectionError::EmptyModelResponse => {}
        other => panic!("expected EmptyModelResponse, got: {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Eval harness tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn eval_computes_correct_metrics() {
    let det = RegexDetector::new();

    let entries = vec![
        BenchmarkEntry {
            prompt: "Contact alice@example.com now.".to_string(),
            spans: vec![LabeledSpan {
                pii_type: "EMAIL".to_string(),
                start: 8,
                end: 25,
                text: "alice@example.com".to_string(),
                confidence: 1.0,
                implicit: false,
            }],
        },
        BenchmarkEntry {
            prompt: "No PII here at all.".to_string(),
            spans: vec![],
        },
    ];

    let report = eval::run_eval(&det, &entries).await.unwrap();

    // First entry: regex should find the email => TP=1.
    // Second entry: no PII expected and none detected => perfect.
    assert_eq!(report.total_entries, 2);
    assert!(
        report.overall.recall >= 0.99,
        "recall should be ~1.0: {}",
        report.overall.recall
    );
    assert!(
        report.overall.precision >= 0.99,
        "precision should be ~1.0: {}",
        report.overall.precision
    );
}

#[tokio::test]
async fn eval_loads_sample_benchmark() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("eval")
        .join("sample_benchmark.jsonl");

    let entries = eval::load_benchmark(&path).unwrap();
    assert_eq!(entries.len(), 5, "sample benchmark should have 5 entries");

    // Verify the clean prompt has no spans.
    let clean = entries.iter().find(|e| e.spans.is_empty()).unwrap();
    assert!(clean.prompt.contains("weather"));
}

#[test]
fn eval_metrics_computation() {
    // 2 TP, 1 FP, 1 FN => precision=2/3, recall=2/3
    let m = Metrics::compute(2, 1, 1);
    assert!((m.precision - 2.0 / 3.0).abs() < 1e-9);
    assert!((m.recall - 2.0 / 3.0).abs() < 1e-9);
    let expected_f1 = 2.0 * (2.0 / 3.0) * (2.0 / 3.0) / (2.0 / 3.0 + 2.0 / 3.0);
    assert!((m.f1 - expected_f1).abs() < 1e-9);
}
