use async_trait::async_trait;
use gateway_common::errors::DetectionError;
use gateway_common::types::PiiSpan;

/// Trait for PII detection backends. Implementations include regex pre-scan,
/// fast model (4B), deep model (27B), and tiered composition.
#[async_trait]
pub trait PiiDetector: Send + Sync {
    async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError>;
    fn name(&self) -> &str;
}
