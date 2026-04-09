use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use gateway_anonymizer::placeholder;
use gateway_common::errors::GatewayError;
use gateway_common::types::PrivacyScore;
use serde_json::Value;
use tracing::debug;

use crate::format::{self, ApiFormat};
use crate::metrics;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Code-block extraction
// ---------------------------------------------------------------------------

/// A code block extracted from text, with its byte range and a unique marker.
struct CodeBlock {
    start: usize,
    end: usize,
    marker: String,
    content: String,
}

/// Find markdown fenced code blocks (``` ... ```) and replace them with
/// unique markers. Returns the modified text and the extracted blocks so
/// they can be restored later.
fn extract_code_blocks(text: &str) -> (String, Vec<CodeBlock>) {
    let mut blocks = Vec::new();
    let mut search_from = 0;
    let fence = "```";

    loop {
        let open = match text[search_from..].find(fence) {
            Some(pos) => search_from + pos,
            None => break,
        };
        // The closing fence starts after the opening fence.
        let after_open = open + fence.len();
        let close = match text[after_open..].find(fence) {
            Some(pos) => after_open + pos + fence.len(),
            None => break, // Unmatched fence — stop looking.
        };

        let marker = format!("__CODEBLOCK_{}_", blocks.len());
        blocks.push(CodeBlock {
            start: open,
            end: close,
            marker,
            content: text[open..close].to_string(),
        });

        search_from = close;
    }

    // Replace in reverse order so byte offsets stay valid.
    let mut result = text.to_string();
    for block in blocks.iter().rev() {
        result.replace_range(block.start..block.end, &block.marker);
    }

    (result, blocks)
}

/// Re-insert code blocks by replacing their markers with the original content.
fn restore_code_blocks(text: &str, blocks: &[CodeBlock]) -> String {
    let mut result = text.to_string();
    for block in blocks {
        result = result.replace(&block.marker, &block.content);
    }
    result
}

// ---------------------------------------------------------------------------
// Privacy score header formatting
// ---------------------------------------------------------------------------

fn format_privacy_header(score: &PrivacyScore) -> String {
    format!("{} ({})", score.value(), score.classification())
}

// ---------------------------------------------------------------------------
// Error → Response conversion
// ---------------------------------------------------------------------------

fn error_kind(err: &GatewayError) -> &'static str {
    match err {
        GatewayError::BadRequest(_) => "bad_request",
        GatewayError::PayloadTooLarge => "payload_too_large",
        GatewayError::UnsupportedMediaType => "unsupported_media_type",
        GatewayError::ModelUnavailable(_) => "model_unavailable",
        GatewayError::SessionStore(_) => "session_store",
        GatewayError::AuditTrail(_) => "audit_trail",
        GatewayError::UpstreamUnavailable(_) => "upstream_unavailable",
        GatewayError::UpstreamError { .. } => "upstream_error",
        GatewayError::UpstreamTimeout => "upstream_timeout",
        GatewayError::Internal(_) => "internal",
    }
}

fn error_response(err: GatewayError) -> Response {
    let status = err.status_code();
    metrics::record_error(error_kind(&err));
    metrics::record_request_total(status);
    let body = serde_json::json!({ "error": err.to_string() });
    let mut resp = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body),
    )
        .into_response();
    // Ensure content-type is set.
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/json"),
    );
    resp
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

pub async fn handle_proxy_request(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    handle_inner(state, uri, headers, body)
        .await
        .map_err(error_response)
}

async fn handle_inner(
    state: AppState,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, GatewayError> {
    let request_start = Instant::now();

    // 0. Detect API format from the request path.
    let api_format = format::detect_format(uri.path());

    // 1. Parse JSON body.
    if body.is_empty() {
        return Err(GatewayError::BadRequest("empty body".into()));
    }
    let parsed_body: Value = serde_json::from_slice(&body)
        .map_err(|e| GatewayError::BadRequest(format!("invalid JSON: {e}")))?;

    // 2. Extract content strings from messages.
    let contents = format::extract_messages(&parsed_body, api_format)?;

    // 3-5. Detect PII, substitute, and store session data.
    let session_id = headers
        .get("x-gateway-session")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut all_spans = Vec::new();
    let mut anonymized_contents: Vec<(usize, String)> = Vec::new();

    let inference_start = Instant::now();

    for (idx, content) in &contents {
        // 2a. Extract code blocks before PII detection.
        let (stripped, code_blocks) = extract_code_blocks(content);

        // 3. Run PII detection on the text with code blocks removed.
        let spans = state
            .detector
            .detect(&stripped)
            .await
            .map_err(GatewayError::ModelUnavailable)?;

        if spans.is_empty() {
            // No PII — keep original content.
            anonymized_contents.push((*idx, content.clone()));
            continue;
        }

        // 4. Substitute PII with placeholders.
        let (substituted, placeholders) = placeholder::substitute(&stripped, &spans);

        // 4a. Restore code blocks around the substituted text.
        let final_text = restore_code_blocks(&substituted, &code_blocks);

        // 5. Store placeholder mappings.
        state
            .session_store
            .store(&session_id, &placeholders)
            .await
            .map_err(GatewayError::SessionStore)?;

        all_spans.extend(spans);
        anonymized_contents.push((*idx, final_text));
    }

    // Record model inference duration.
    metrics::record_model_inference_duration(inference_start);

    // Record PII detection counts by type.
    {
        use std::collections::HashMap;
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for span in &all_spans {
            *counts.entry(span.pii_type.placeholder_prefix()).or_insert(0) += 1;
        }
        for (pii_type, count) in counts {
            metrics::record_pii_detected(pii_type, count);
        }
    }

    // 6. Compute privacy score.
    let privacy_score = PrivacyScore::compute(&all_spans);

    // 7. Rebuild the JSON body.
    let mut new_body = parsed_body;
    format::rebuild_body(&mut new_body, &anonymized_contents, api_format)?;
    let new_body_bytes = serde_json::to_vec(&new_body)
        .map_err(|e| GatewayError::Internal(format!("JSON serialization failed: {e}")))?;

    // 8. Forward to upstream.
    let upstream_url = match api_format {
        ApiFormat::OpenAi => format!(
            "{}/v1/chat/completions",
            state.config.upstream_url_openai.trim_end_matches('/')
        ),
        ApiFormat::Anthropic => state.config.upstream_url.clone(),
    };
    debug!(upstream = %upstream_url, format = ?api_format, "forwarding request");

    let mut req_builder = state.http_client.post(&upstream_url);

    // Copy original headers, skipping hop-by-hop and host.
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if matches!(
            name_str.as_str(),
            "host" | "transfer-encoding" | "connection" | "content-length"
                | "x-gateway-session"
        ) {
            continue;
        }
        req_builder = req_builder.header(name, value);
    }

    // Add authorization header appropriate for the API format.
    match api_format {
        ApiFormat::OpenAi => {
            if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
                req_builder =
                    req_builder.header("authorization", format!("Bearer {api_key}"));
            }
        }
        ApiFormat::Anthropic => {
            if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
                req_builder = req_builder.header("x-api-key", api_key);
            }
        }
    }
    req_builder = req_builder.header("content-type", "application/json");
    req_builder = req_builder.body(new_body_bytes);

    let upstream_start = Instant::now();

    let upstream_resp = req_builder.send().await.map_err(|e| {
        if e.is_timeout() {
            GatewayError::UpstreamTimeout
        } else {
            GatewayError::UpstreamUnavailable(e.to_string())
        }
    })?;

    // 9. Buffer full response.
    let upstream_status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();
    let upstream_body_bytes = upstream_resp.bytes().await.map_err(|e| {
        GatewayError::UpstreamUnavailable(format!("failed to read upstream body: {e}"))
    })?;

    // Record upstream round-trip duration.
    metrics::record_upstream_duration(upstream_start);

    // 10. Deanonymize response body.
    let response_text = String::from_utf8_lossy(&upstream_body_bytes);
    let all_placeholders = state
        .session_store
        .lookup_all(&session_id)
        .await
        .map_err(GatewayError::SessionStore)?;
    let deanonymized = placeholder::restore(&response_text, &all_placeholders);

    // 11. Build final response.
    let mut builder = Response::builder().status(upstream_status.as_u16());

    // Copy upstream response headers.
    for (name, value) in upstream_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if matches!(
            name_str.as_str(),
            "transfer-encoding" | "content-length" | "connection"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }

    // Add gateway headers.
    builder = builder.header("x-gateway-session", &session_id);
    builder = builder.header(
        "x-gateway-privacy-score",
        format_privacy_header(&privacy_score),
    );

    let response = builder
        .body(axum::body::Body::from(deanonymized.into_bytes()))
        .map_err(|e| GatewayError::Internal(format!("response build failed: {e}")))?;

    // Record total request duration and success status.
    metrics::record_request_duration(request_start);
    metrics::record_request_total(upstream_status.as_u16());

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_code_blocks_none() {
        let (result, blocks) = extract_code_blocks("no code here");
        assert_eq!(result, "no code here");
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_extract_code_blocks_single() {
        let text = "before ```code``` after";
        let (result, blocks) = extract_code_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert!(!result.contains("```"));
        assert!(result.contains("__CODEBLOCK_0_"));
        let restored = restore_code_blocks(&result, &blocks);
        assert_eq!(restored, text);
    }

    #[test]
    fn test_extract_code_blocks_multiple() {
        let text = "a ```x``` b ```y``` c";
        let (result, blocks) = extract_code_blocks(text);
        assert_eq!(blocks.len(), 2);
        assert!(!result.contains("```"));
        let restored = restore_code_blocks(&result, &blocks);
        assert_eq!(restored, text);
    }

    #[test]
    fn test_extract_code_blocks_unmatched() {
        let text = "before ``` no closing";
        let (result, blocks) = extract_code_blocks(text);
        assert_eq!(result, text);
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_format_privacy_header() {
        let score = PrivacyScore(100);
        assert_eq!(format_privacy_header(&score), "100 (LOW)");
        let score = PrivacyScore(75);
        assert_eq!(format_privacy_header(&score), "75 (MEDIUM)");
        let score = PrivacyScore(20);
        assert_eq!(format_privacy_header(&score), "20 (HIGH)");
    }
}
