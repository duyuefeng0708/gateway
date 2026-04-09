use async_trait::async_trait;
use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, PiiType};
use ollama_rs::generation::chat::request::ChatMessageRequest;
use ollama_rs::generation::chat::ChatMessage;
use ollama_rs::Ollama;
use serde::Deserialize;
use std::time::Duration;

use crate::detector::PiiDetector;

/// System prompt instructing the model to return PII spans as a JSON array.
///
/// Uses PROMPT-BASED JSON rather than Ollama's `format` parameter due to
/// upstream bug (issue #15260).
const SYSTEM_PROMPT: &str = r#"You are a PII detection engine. Given user text, identify all personally identifiable information (PII).

Return ONLY a JSON array (no markdown, no explanation). Each element must be:
{"type": "<TYPE>", "start": <int>, "end": <int>, "text": "<matched text>", "confidence": <0.0-1.0>, "implicit": <bool>}

Valid TYPE values: PERSON, ORGANIZATION, LOCATION, EMAIL, PHONE, SSN, CREDENTIAL

"implicit" should be true when the PII is inferred from context rather than explicitly stated (e.g. "the CEO of Tesla" implies Elon Musk).

If no PII is found, return an empty array: []

Return ONLY valid JSON. No other text."#;

/// A single span returned by the model in its JSON response.
#[derive(Debug, Deserialize)]
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

impl RawSpan {
    fn into_pii_span(self) -> Option<PiiSpan> {
        let pii_type = match self.pii_type.to_uppercase().as_str() {
            "PERSON" => PiiType::Person,
            "ORGANIZATION" => PiiType::Organization,
            "LOCATION" => PiiType::Location,
            "EMAIL" => PiiType::Email,
            "PHONE" => PiiType::Phone,
            "SSN" => PiiType::Ssn,
            "CREDENTIAL" => PiiType::Credential,
            _ => return None,
        };
        Some(PiiSpan {
            pii_type,
            start: self.start,
            end: self.end,
            text: self.text,
            confidence: self.confidence,
            implicit: self.implicit,
        })
    }
}

/// PII detector backed by an Ollama LLM.
///
/// Generic over model name -- instantiate with a fast 4B model for the
/// pre-scan tier or a deep 27B model for the thorough tier.
pub struct OllamaDetector {
    client: Ollama,
    model: String,
    timeout: Duration,
}

impl OllamaDetector {
    /// Create a new detector targeting `model` on the given Ollama instance.
    pub fn new(client: Ollama, model: impl Into<String>) -> Self {
        Self {
            client,
            model: model.into(),
            timeout: Duration::from_secs(8),
        }
    }

    /// Override the default 8-second timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the chat request for a user prompt.
    fn build_request(&self, text: &str) -> ChatMessageRequest {
        ChatMessageRequest::new(
            self.model.clone(),
            vec![
                ChatMessage::system(SYSTEM_PROMPT.to_string()),
                ChatMessage::user(text.to_string()),
            ],
        )
    }

    /// Parse the model's raw text response into PII spans.
    fn parse_response(raw: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DetectionError::EmptyModelResponse);
        }

        // Strip markdown code fences if the model wraps its output.
        let json_str = if trimmed.starts_with("```") {
            let inner = trimmed
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim();
            inner
        } else {
            trimmed
        };

        let raw_spans: Vec<RawSpan> = serde_json::from_str(json_str)
            .map_err(|e| DetectionError::ModelOutputParseError(e.to_string()))?;

        Ok(raw_spans.into_iter().filter_map(|s| s.into_pii_span()).collect())
    }

    /// Send a chat request with timeout, returning the assistant content.
    async fn send(&self, request: ChatMessageRequest) -> Result<String, DetectionError> {
        let resp = tokio::time::timeout(self.timeout, self.client.send_chat_messages(request))
            .await
            .map_err(|_| DetectionError::InferenceTimeout(self.timeout.as_secs()))?
            .map_err(|e| DetectionError::OllamaServerError(e.to_string()))?;

        Ok(resp.message.content)
    }
}

#[async_trait]
impl PiiDetector for OllamaDetector {
    async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        let request = self.build_request(text);
        let content = self.send(request).await?;

        // First attempt to parse.
        match Self::parse_response(&content) {
            Ok(spans) => return Ok(spans),
            Err(_first_err) => {
                // Retry once: re-send the request.
                let retry_request = self.build_request(text);
                let retry_content = self.send(retry_request).await?;
                Self::parse_response(&retry_content)
            }
        }
    }

    fn name(&self) -> &str {
        "ollama"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_json() {
        let json = r#"[
            {"type": "PERSON", "start": 0, "end": 10, "text": "John Smith", "confidence": 0.95, "implicit": false},
            {"type": "EMAIL", "start": 22, "end": 41, "text": "john@example.com", "confidence": 1.0, "implicit": false}
        ]"#;
        let spans = OllamaDetector::parse_response(json).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].pii_type, PiiType::Person);
        assert_eq!(spans[1].pii_type, PiiType::Email);
    }

    #[test]
    fn parse_empty_array() {
        let spans = OllamaDetector::parse_response("[]").unwrap();
        assert!(spans.is_empty());
    }

    #[test]
    fn parse_empty_string_is_error() {
        let err = OllamaDetector::parse_response("").unwrap_err();
        assert!(matches!(err, DetectionError::EmptyModelResponse));
    }

    #[test]
    fn parse_malformed_json_is_error() {
        let err = OllamaDetector::parse_response("not json at all").unwrap_err();
        assert!(matches!(err, DetectionError::ModelOutputParseError(_)));
    }

    #[test]
    fn parse_strips_markdown_fences() {
        let json = "```json\n[{\"type\": \"SSN\", \"start\": 0, \"end\": 11, \"text\": \"123-45-6789\", \"confidence\": 0.9, \"implicit\": false}]\n```";
        let spans = OllamaDetector::parse_response(json).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Ssn);
    }

    #[test]
    fn parse_skips_unknown_types() {
        let json = r#"[
            {"type": "UNKNOWN_TYPE", "start": 0, "end": 5, "text": "hello", "confidence": 0.5, "implicit": false},
            {"type": "PERSON", "start": 10, "end": 15, "text": "Alice", "confidence": 0.9, "implicit": false}
        ]"#;
        let spans = OllamaDetector::parse_response(json).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Person);
    }
}
