use thiserror::Error;

/// Errors from the PII detection pipeline.
#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("ollama connection refused: {0}")]
    ConnectionRefused(String),

    #[error("ollama server error: {0}")]
    OllamaServerError(String),

    #[error("model output was not valid JSON: {0}")]
    ModelOutputParseError(String),

    #[error("model returned empty response")]
    EmptyModelResponse,

    #[error("model inference timed out after {0}s")]
    InferenceTimeout(u64),

    #[error("detection failed: {0}")]
    Other(String),
}

/// Errors from placeholder substitution and session management.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("database locked after retries")]
    DatabaseLocked,

    #[error("database disk full")]
    DiskFull,

    #[error("database error: {0}")]
    DatabaseError(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),
}

/// Errors from the audit trail.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit log disk full")]
    AuditDiskFull,

    #[error("audit integrity error: hash chain broken")]
    AuditIntegrityError,

    #[error("audit write failed: {0}")]
    WriteError(String),

    /// The audit writer's bounded queue is full. Returned by
    /// `AuditHandle::write_entry` when downstream disk I/O can't keep up.
    /// Callers should map this to HTTP 503 with a Retry-After header so
    /// the proxy fails loud rather than queuing audit work indefinitely.
    /// Codex F8 backpressure semantic.
    #[error("audit writer overloaded; backpressure applied")]
    Backpressured,

    /// The dedicated audit writer thread is no longer running. Returned
    /// when the writer thread panicked or the receive channel closed.
    /// Operationally this is a process-level failure; the proxy should
    /// surface it via /metrics and the orchestrator should restart.
    #[error("audit writer thread terminated")]
    WriterDown,
}

/// Top-level gateway errors mapping to HTTP status codes.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("request payload too large")]
    PayloadTooLarge,

    #[error("unsupported media type: text-only in v1")]
    UnsupportedMediaType,

    #[error("model unavailable")]
    ModelUnavailable(#[from] DetectionError),

    #[error("session store error")]
    SessionStore(#[from] SessionError),

    #[error("audit trail error")]
    AuditTrail(#[from] AuditError),

    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),

    #[error("upstream error: {status}")]
    UpstreamError { status: u16, body: String },

    #[error("upstream timeout")]
    UpstreamTimeout,

    #[error("internal error: {0}")]
    Internal(String),
}

impl GatewayError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::PayloadTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::ModelUnavailable(_) => 503,
            Self::SessionStore(_) => 503,
            Self::AuditTrail(_) => 503,
            Self::UpstreamUnavailable(_) => 502,
            Self::UpstreamError { status, .. } => *status,
            Self::UpstreamTimeout => 504,
            Self::Internal(_) => 500,
        }
    }
}
