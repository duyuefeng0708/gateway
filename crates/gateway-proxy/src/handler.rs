use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::future::join_all;
use futures_util::StreamExt;
use gateway_anonymizer::detector::DetectionResult;
use gateway_anonymizer::placeholder;
use gateway_anonymizer::streaming::StreamingDeanonymizer;
use gateway_common::errors::{DetectionError, GatewayError};
use gateway_common::types::PrivacyScore;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::format::{self, ApiFormat};
use crate::metrics;
use crate::state::AppState;

/// Emit tier-visibility metrics from a DetectionResult. The tier label is
/// derived purely from the DetectionResult flags, so the Prometheus label
/// cardinality is bounded to {regex, fast, deep} — no user input ever
/// reaches a label value.
fn record_tier_metrics(meta: &DetectionResult, deep_start: Instant) {
    // Tier label: if deep spans were merged, call it deep. Otherwise the
    // call went through fast (regex + fast-model). Even zero-span cases
    // are labelled "fast" because the fast pipeline still ran.
    let tier = if meta.deep_scan_used { "deep" } else { "fast" };
    metrics::record_tier_used(tier);

    if meta.deep_attempted {
        metrics::record_deep_tier_attempted();
        if meta.deep_scan_used {
            metrics::record_deep_tier_succeeded();
            metrics::record_deep_tier_latency(deep_start);
        } else if let Some(err) = &meta.deep_error {
            let kind = match err {
                DetectionError::InferenceTimeout(_) => "timeout",
                DetectionError::OllamaServerError(_) => "server_error",
                DetectionError::ConnectionRefused(_) => "connection_refused",
                DetectionError::ModelOutputParseError(_) => "parse_error",
                DetectionError::EmptyModelResponse => "empty_response",
                DetectionError::Other(_) => "other",
            };
            metrics::record_deep_tier_failed(kind);
            if matches!(err, DetectionError::ConnectionRefused(_)) {
                metrics::record_ollama_connection_error();
            }
        }
    }
}

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

    while let Some(pos) = text[search_from..].find(fence) {
        let open = search_from + pos;
        // The closing fence starts after the opening fence.
        let after_open = open + fence.len();
        let Some(close_pos) = text[after_open..].find(fence) else {
            break; // Unmatched fence — stop looking.
        };
        let close = after_open + close_pos + fence.len();

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
    resp.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
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

    let inference_start = Instant::now();

    // Stage 1: parallel per-message detection, bounded by detection_semaphore.
    // Each task owns its own permit via acquire_owned so the Future stays
    // 'static for join_all; the permit drops with the task, returning the slot.
    //
    // Prior to 2026-04-22 this loop was strictly sequential, which meant a
    // 10-message request at 3s/detection paid ~30s before upstream ever saw
    // the body. With bounded parallelism (default 2) that drops to ~15s on
    // the same shape, while capping Ollama pressure. Codex T4 from
    // plan-eng-review.
    let detection_tasks = contents.iter().map(|(idx, content)| {
        let idx = *idx;
        let content = content.clone();
        let detector = Arc::clone(&state.detector);
        let sem = Arc::clone(&state.detection_semaphore);
        async move {
            let _permit = sem.acquire_owned().await.expect("semaphore never closed");
            let (stripped, code_blocks) = extract_code_blocks(&content);
            let deep_start = Instant::now();
            let result = detector.detect_with_metadata(&stripped).await;
            (idx, content, stripped, code_blocks, result, deep_start)
        }
    });
    let detection_results = join_all(detection_tasks).await;

    // Stage 2: emit tier-visibility metrics and substitute placeholders. We
    // collect placeholders per message and batch the session store writes in
    // Stage 3 because SQLite performs better with grouped inserts than with
    // concurrent writers scattered across parallel futures.
    let mut all_spans = Vec::new();
    let mut anonymized_contents: Vec<(usize, String)> = Vec::new();
    let mut pending_placeholder_batches = Vec::new();

    for (idx, content, stripped, code_blocks, result, deep_start) in detection_results {
        let meta: DetectionResult = result.map_err(GatewayError::ModelUnavailable)?;
        record_tier_metrics(&meta, deep_start);

        if meta.spans.is_empty() {
            anonymized_contents.push((idx, content));
            continue;
        }

        let (substituted, placeholders) = placeholder::substitute(&stripped, &meta.spans);
        let final_text = restore_code_blocks(&substituted, &code_blocks);

        pending_placeholder_batches.push(placeholders);
        all_spans.extend(meta.spans);
        anonymized_contents.push((idx, final_text));
    }

    // Stage 3: batch the session-store writes sequentially. Placeholder IDs
    // are UUIDs so ordering within the request doesn't matter for
    // correctness — this just keeps the SQLite write pattern simple.
    for batch in &pending_placeholder_batches {
        state
            .session_store
            .store(&session_id, batch)
            .await
            .map_err(GatewayError::SessionStore)?;
    }

    // Record aggregate model inference duration (wall-clock across all
    // messages in this request, whether they ran in parallel or not).
    metrics::record_model_inference_duration(inference_start);

    // Record PII detection counts by type.
    {
        use std::collections::HashMap;
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for span in &all_spans {
            *counts
                .entry(span.pii_type.placeholder_prefix())
                .or_insert(0) += 1;
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

    // 8. Forward to upstream — use smart routing if configured.
    let route_target = state.router.select(privacy_score.value());

    let (upstream_url, effective_format, api_key_env) = if let Some(ref target) = route_target {
        // Smart routing: use the route target's upstream and credentials.
        let url = match target.api_format {
            ApiFormat::OpenAi => format!(
                "{}/v1/chat/completions",
                target.upstream_url.trim_end_matches('/')
            ),
            ApiFormat::Anthropic => target.upstream_url.clone(),
        };
        debug!(
            upstream = %url,
            route = %target.route_name,
            format = ?target.api_format,
            score = privacy_score.value(),
            "smart routing request"
        );
        (url, target.api_format, target.api_key_env.clone())
    } else {
        // Default behavior: use config upstream based on request format.
        let url = match api_format {
            ApiFormat::OpenAi => format!(
                "{}/v1/chat/completions",
                state.config.upstream_url_openai.trim_end_matches('/')
            ),
            ApiFormat::Anthropic => state.config.upstream_url.clone(),
        };
        let key_env = match api_format {
            ApiFormat::OpenAi => "OPENAI_API_KEY".to_string(),
            ApiFormat::Anthropic => "ANTHROPIC_API_KEY".to_string(),
        };
        debug!(upstream = %url, format = ?api_format, "forwarding request (default)");
        (url, api_format, key_env)
    };

    // -- Receipt write (PR-A1) ----------------------------------------------
    //
    // Write the audit entry now: we know the routing decision, the
    // post-redaction prompt body, and the placeholder-bearing rebuild.
    // We do NOT yet know the upstream-reported model or the response
    // body — those land via a follow-up audit update once the response
    // is received (currently P2 since the audit log is append-only and
    // the audit subsystem doesn't support entry-update yet).
    //
    // The receipt is emitted via the x-gateway-receipt header on the
    // forwarded response. response_hash_status starts as Pending and
    // stays that way for both streaming and non-streaming requests in
    // PR-A1; finalising it lands in PR-A2.
    let prompt_hmac = state.hmac.digest(&new_body_bytes);
    let client_requested_model = new_body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let gateway_selected_route = route_target
        .as_ref()
        .map(|t| t.route_name.clone())
        .unwrap_or_default();

    let audit_request = gateway_anonymizer::audit::AuditEntryRequest {
        session_id: session_id.clone(),
        spans: all_spans.clone(),
        score: privacy_score,
        request_id: String::new(), // assigned by AuditWriter
        client_requested_model: client_requested_model.clone(),
        gateway_selected_route,
        upstream_requested_model: client_requested_model,
        upstream_reported_model: String::new(), // P2: filled on response
        detector_fast_model: state.config.fast_model.clone(),
        detector_deep_model: state.config.deep_model.clone(),
        prompt_hmac,
        response_hmac: String::new(), // P2: rolling HMAC over response stream
        hmac_key_id: state.hmac.key_id.clone(),
        response_hash_status: gateway_common::types::ResponseHashStatus::Pending,
        signing_key_id: state.transparency.signing_key_id(),
        signature_alg: state.transparency.signature_alg().to_string(),
    };

    let receipt_id = match state.audit.write_entry_v2(audit_request).await {
        Ok(outcome) => {
            // Queue the new chain head for the next Rekor anchor cycle.
            // Best-effort: a slow Rekor doesn't block the proxy. Codex F14.
            state.transparency.record_head(outcome.hash.clone()).await;
            outcome.request_id
        }
        Err(e) => {
            warn!(error = %e, "audit write failed; continuing without receipt");
            String::new()
        }
    };

    let mut req_builder = state.http_client.post(&upstream_url);

    // Copy original headers, skipping hop-by-hop and host.
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if matches!(
            name_str.as_str(),
            "host"
                | "transfer-encoding"
                | "connection"
                | "content-length"
                | "x-gateway-session"
                | "authorization"
                | "x-api-key"
        ) {
            continue;
        }
        req_builder = req_builder.header(name, value);
    }

    // Add authorization header appropriate for the effective API format.
    match effective_format {
        ApiFormat::OpenAi => {
            if let Ok(api_key) = std::env::var(&api_key_env) {
                req_builder = req_builder.header("authorization", format!("Bearer {api_key}"));
            }
        }
        ApiFormat::Anthropic => {
            if let Ok(api_key) = std::env::var(&api_key_env) {
                req_builder = req_builder.header("x-api-key", api_key);
            }
        }
    }
    req_builder = req_builder.header("content-type", "application/json");
    req_builder = req_builder.body(new_body_bytes);

    // Detect whether the client requested streaming.
    let is_streaming = new_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && state.config.streaming_enabled;

    let upstream_start = Instant::now();

    let upstream_resp = req_builder.send().await.map_err(|e| {
        if e.is_timeout() {
            GatewayError::UpstreamTimeout
        } else {
            GatewayError::UpstreamUnavailable(e.to_string())
        }
    })?;

    let upstream_status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    if is_streaming {
        // ---------------------------------------------------------------
        // Streaming path: deanonymize SSE chunks in real time
        // ---------------------------------------------------------------

        // Load all placeholders for this session up-front.
        let all_placeholders = state
            .session_store
            .lookup_all(&session_id)
            .await
            .map_err(GatewayError::SessionStore)?;

        let deanonymizer = Arc::new(Mutex::new(StreamingDeanonymizer::new(all_placeholders)));

        let byte_stream = upstream_resp.bytes_stream();

        // Shared state for the stream processing closure.
        let deanonymizer_clone = Arc::clone(&deanonymizer);
        let sse_format = effective_format;
        let sse_buf = Arc::new(Mutex::new(crate::sse_buffer::SseLineBuffer::new()));

        let body_stream = byte_stream.then(move |chunk_result| {
            let deano = Arc::clone(&deanonymizer_clone);
            let buf = Arc::clone(&sse_buf);
            async move {
                match chunk_result {
                    Ok(chunk) => {
                        // Buffer raw bytes until complete SSE events (\n\n) are available.
                        // This prevents partial JSON lines from being parsed when TCP
                        // delivers chunks at arbitrary byte boundaries.
                        let mut buf_guard = buf.lock().await;
                        let complete_events = buf_guard.push_bytes(&chunk);
                        drop(buf_guard);

                        let mut output_lines = Vec::new();

                        for event in &complete_events {
                            for line in event.split('\n') {
                                if let Some(data) = line.strip_prefix("data: ") {
                                    let trimmed = data.trim();
                                    if trimmed == "[DONE]" {
                                        let mut guard = deano.lock().await;
                                        if let Some(remaining) = guard.flush() {
                                            let synth = build_sse_delta(&remaining, sse_format);
                                            output_lines.push(format!("data: {synth}\n\n"));
                                        }
                                        output_lines.push("data: [DONE]\n\n".to_string());
                                        continue;
                                    }

                                    if let Ok(mut json) = serde_json::from_str::<Value>(trimmed) {
                                        let delta_text = extract_sse_delta(&json, sse_format);

                                        if let Some(token) = delta_text {
                                            let mut guard = deano.lock().await;
                                            let deanonymized_chunks = guard.process_token(&token);
                                            let deanonymized = deanonymized_chunks.join("");

                                            set_sse_delta(&mut json, &deanonymized, sse_format);
                                            let json_str = serde_json::to_string(&json)
                                                .unwrap_or_else(|_| trimmed.to_string());
                                            output_lines.push(format!("data: {json_str}\n\n"));
                                        } else {
                                            output_lines.push(format!("data: {trimmed}\n\n"));
                                        }
                                    } else {
                                        output_lines.push(format!("data: {trimmed}\n\n"));
                                    }
                                } else if !line.is_empty() {
                                    output_lines.push(format!("{line}\n"));
                                }
                            }
                        }

                        Ok::<_, std::io::Error>(Bytes::from(output_lines.join("")))
                    }
                    Err(e) => {
                        warn!("upstream stream error: {e}");
                        Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            e.to_string(),
                        ))
                    }
                }
            }
        });

        // Build streaming response.
        let stream_body = axum::body::Body::from_stream(body_stream);

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

        builder = builder.header("content-type", "text/event-stream");
        builder = builder.header("cache-control", "no-cache");
        builder = builder.header("x-gateway-session", &session_id);
        builder = builder.header(
            "x-gateway-privacy-score",
            format_privacy_header(&privacy_score),
        );
        if !receipt_id.is_empty() {
            builder = builder.header("x-gateway-receipt", &receipt_id);
        }

        let response = builder
            .body(stream_body)
            .map_err(|e| GatewayError::Internal(format!("response build failed: {e}")))?;

        // Record metrics (upstream duration is approximate for streaming).
        metrics::record_upstream_duration(upstream_start);
        metrics::record_request_duration(request_start);
        metrics::record_request_total(upstream_status.as_u16());

        Ok(response)
    } else {
        // ---------------------------------------------------------------
        // Buffered path: existing behavior (backward compatible)
        // ---------------------------------------------------------------

        // 9. Buffer full response.
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
        if !receipt_id.is_empty() {
            builder = builder.header("x-gateway-receipt", &receipt_id);
        }

        let response = builder
            .body(axum::body::Body::from(deanonymized.into_bytes()))
            .map_err(|e| GatewayError::Internal(format!("response build failed: {e}")))?;

        // Record total request duration and success status.
        metrics::record_request_duration(request_start);
        metrics::record_request_total(upstream_status.as_u16());

        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// SSE delta extraction and rebuilding helpers
// ---------------------------------------------------------------------------

/// Extract the text delta from a parsed SSE JSON event.
///
/// - Anthropic: `{"delta":{"type":"text_delta","text":"token"}}`
/// - OpenAI: `{"choices":[{"delta":{"content":"token"}}]}`
fn extract_sse_delta(json: &Value, format: ApiFormat) -> Option<String> {
    match format {
        ApiFormat::Anthropic => json
            .get("delta")
            .and_then(|d| d.get("text"))
            .and_then(Value::as_str)
            .map(String::from),
        ApiFormat::OpenAi => json
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("delta"))
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
            .map(String::from),
    }
}

/// Set the text delta in a parsed SSE JSON event.
fn set_sse_delta(json: &mut Value, text: &str, format: ApiFormat) {
    match format {
        ApiFormat::Anthropic => {
            if let Some(delta) = json.get_mut("delta") {
                delta["text"] = Value::String(text.to_string());
            }
        }
        ApiFormat::OpenAi => {
            if let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) {
                if let Some(choice) = choices.first_mut() {
                    if let Some(delta) = choice.get_mut("delta") {
                        delta["content"] = Value::String(text.to_string());
                    }
                }
            }
        }
    }
}

/// Build a synthetic SSE data line with a text delta.
fn build_sse_delta(text: &str, format: ApiFormat) -> String {
    match format {
        ApiFormat::Anthropic => {
            let json = serde_json::json!({
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": text}
            });
            serde_json::to_string(&json).unwrap_or_default()
        }
        ApiFormat::OpenAi => {
            let json = serde_json::json!({
                "choices": [{"delta": {"content": text}}]
            });
            serde_json::to_string(&json).unwrap_or_default()
        }
    }
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
