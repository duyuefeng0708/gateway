use async_trait::async_trait;
use gateway_common::errors::DetectionError;
use gateway_common::types::PiiSpan;

/// Trait for PII detection backends. Implementations include regex pre-scan,
/// fast model (4B), deep model (27B), and tiered composition.
///
/// Implementations provide `detect()` for the basic span list. The default
/// `detect_with_metadata()` wraps that into a `DetectionResult` with all
/// tier-tracking flags set to false. `TieredDetector` overrides it to
/// populate the flags honestly so the proxy can emit accurate metrics.
#[async_trait]
pub trait PiiDetector: Send + Sync {
    async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError>;

    /// Run detection and return a `DetectionResult` carrying tier-visibility
    /// metadata. Default impl wraps `detect()` with no-tier metadata; tiered
    /// implementations should override.
    async fn detect_with_metadata(
        &self,
        text: &str,
    ) -> Result<DetectionResult, DetectionError> {
        let spans = self.detect(text).await?;
        Ok(DetectionResult {
            spans,
            ..DetectionResult::default()
        })
    }

    fn name(&self) -> &str;
}

/// Result of PII detection carrying metadata about which tiers ran.
///
/// The flag set distinguishes the six meaningful states of a detection call:
///
/// | Scenario                       | deep_scan_available | deep_attempted | deep_scan_used | deep_error |
/// |--------------------------------|---------------------|----------------|----------------|-----------|
/// | mode=fast                      | false               | false          | false          | None      |
/// | auto, not escalated            | true                | false          | false          | None      |
/// | auto, escalated, success       | true                | true           | true           | None      |
/// | auto, escalated, failed        | true                | true           | false          | Some(e)   |
/// | deep, success                  | true                | true           | true           | None      |
/// | deep, failed (silent fallback) | true                | true           | false          | Some(e)   |
///
/// The same pattern applies to `rules_attempted` / `rules_error` for the
/// optional custom-rules detector.
#[derive(Debug, Default)]
pub struct DetectionResult {
    pub spans: Vec<PiiSpan>,
    /// True iff a deep detector is configured on this TieredDetector.
    pub deep_scan_available: bool,
    /// True iff run_deep_tier() was called (regardless of outcome).
    pub deep_attempted: bool,
    /// True iff deep detection returned Ok (spans merged into result).
    pub deep_scan_used: bool,
    /// Error captured from a failed deep detection attempt (silent fallback).
    pub deep_error: Option<DetectionError>,
    /// True iff the optional custom-rules detector was invoked.
    pub rules_attempted: bool,
    /// Error captured from a failed rules run (continues without rules).
    pub rules_error: Option<DetectionError>,
}
