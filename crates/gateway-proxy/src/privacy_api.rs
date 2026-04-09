use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use gateway_anonymizer::placeholder;
use gateway_common::types::PrivacyScore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AnonymizeRequest {
    pub text: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SpanInfo {
    #[serde(rename = "type")]
    pub pii_type: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f64,
    pub implicit: bool,
}

#[derive(Debug, Serialize)]
pub struct AnonymizeResponse {
    pub anonymized: String,
    pub session_id: String,
    pub score: u32,
    pub classification: String,
    pub spans: Vec<SpanInfo>,
}

#[derive(Debug, Deserialize)]
pub struct DeanonymizeRequest {
    pub text: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeanonymizeResponse {
    pub restored: String,
    pub placeholders_replaced: usize,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn anonymize(
    State(state): State<AppState>,
    axum::Json(body): axum::Json<AnonymizeRequest>,
) -> Result<Response, Response> {
    anonymize_inner(state, body).await.map_err(|e| e.into_response())
}

async fn anonymize_inner(
    state: AppState,
    body: AnonymizeRequest,
) -> Result<Response, ErrorResponse> {
    // Validate required field.
    let text = body.text.ok_or_else(|| ErrorResponse {
        status: StatusCode::BAD_REQUEST,
        message: "missing required field: text".into(),
    })?;

    if text.is_empty() {
        return Err(ErrorResponse {
            status: StatusCode::BAD_REQUEST,
            message: "missing required field: text".into(),
        });
    }

    // Generate or use provided session_id.
    let session_id = body
        .session_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Run PII detection.
    debug!(session_id = %session_id, "running PII detection for /v1/anonymize");
    let spans = state.detector.detect(&text).await.map_err(|e| ErrorResponse {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: format!("detection failed: {e}"),
    })?;

    // Compute privacy score.
    let privacy_score = PrivacyScore::compute(&spans);

    // Build span info for the response (before substitution changes offsets).
    let span_infos: Vec<SpanInfo> = spans
        .iter()
        .map(|s| SpanInfo {
            pii_type: s.pii_type.placeholder_prefix().to_string(),
            start: s.start,
            end: s.end,
            text: s.text.clone(),
            confidence: s.confidence,
            implicit: s.implicit,
        })
        .collect();

    // If no PII detected, return original text with score 100.
    if spans.is_empty() {
        let resp = AnonymizeResponse {
            anonymized: text,
            session_id,
            score: privacy_score.value(),
            classification: privacy_score.classification().to_string(),
            spans: span_infos,
        };
        return Ok((StatusCode::OK, axum::Json(resp)).into_response());
    }

    // Substitute PII with placeholders.
    let (substituted, placeholders) = placeholder::substitute(&text, &spans);

    // Store placeholder mappings in session store.
    state
        .session_store
        .store(&session_id, &placeholders)
        .await
        .map_err(|e| ErrorResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!("session store error: {e}"),
        })?;

    let resp = AnonymizeResponse {
        anonymized: substituted,
        session_id,
        score: privacy_score.value(),
        classification: privacy_score.classification().to_string(),
        spans: span_infos,
    };

    Ok((StatusCode::OK, axum::Json(resp)).into_response())
}

pub async fn deanonymize(
    State(state): State<AppState>,
    axum::Json(body): axum::Json<DeanonymizeRequest>,
) -> Result<Response, Response> {
    deanonymize_inner(state, body)
        .await
        .map_err(|e| e.into_response())
}

async fn deanonymize_inner(
    state: AppState,
    body: DeanonymizeRequest,
) -> Result<Response, ErrorResponse> {
    // Validate required fields.
    let text = body.text.ok_or_else(|| ErrorResponse {
        status: StatusCode::BAD_REQUEST,
        message: "missing required field: text".into(),
    })?;

    let session_id = body.session_id.ok_or_else(|| ErrorResponse {
        status: StatusCode::BAD_REQUEST,
        message: "missing required field: session_id".into(),
    })?;

    if session_id.is_empty() {
        return Err(ErrorResponse {
            status: StatusCode::BAD_REQUEST,
            message: "missing required field: session_id".into(),
        });
    }

    // Look up all placeholders for this session.
    debug!(session_id = %session_id, "looking up placeholders for /v1/deanonymize");
    let placeholders = state
        .session_store
        .lookup_all(&session_id)
        .await
        .map_err(|e| ErrorResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!("session store error: {e}"),
        })?;

    // If no placeholders found, the session doesn't exist or has no mappings.
    if placeholders.is_empty() {
        return Err(ErrorResponse {
            status: StatusCode::NOT_FOUND,
            message: format!("session not found: {session_id}"),
        });
    }

    // Restore original text.
    let restored = placeholder::restore(&text, &placeholders);

    // Count how many placeholders were actually replaced.
    let placeholders_replaced = placeholders
        .iter()
        .filter(|p| text.contains(&p.placeholder_text))
        .count();

    let resp = DeanonymizeResponse {
        restored,
        placeholders_replaced,
    };

    Ok((StatusCode::OK, axum::Json(resp)).into_response())
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

struct ErrorResponse {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.message,
        };
        (self.status, axum::Json(body)).into_response()
    }
}
