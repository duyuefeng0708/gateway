use async_trait::async_trait;
use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, ScanMode};

use crate::detector::PiiDetector;

/// Result of tiered PII detection, including metadata about which tiers ran.
#[derive(Debug)]
pub struct DetectionResult {
    pub spans: Vec<PiiSpan>,
    pub deep_scan_used: bool,
    pub deep_scan_available: bool,
}

/// Composes regex, fast-model, and deep-model detectors with mode-based orchestration.
///
/// In **Fast** mode only the regex and fast (4B) model run.
/// In **Deep** mode all three detectors run and their results are merged.
/// In **Auto** mode the fast tier runs first and the deep (27B) model is
/// invoked only when escalation heuristics fire (low confidence or suspiciously
/// empty results on a long prompt).
pub struct TieredDetector {
    regex: Box<dyn PiiDetector>,
    fast: Box<dyn PiiDetector>,
    deep: Option<Box<dyn PiiDetector>>,
    rules: Option<Box<dyn PiiDetector>>,
    mode: ScanMode,
    confidence_threshold: f64,
    min_prompt_tokens: usize,
}

impl TieredDetector {
    /// Create a new tiered detector with the given sub-detectors and scan mode.
    pub fn new(
        regex: Box<dyn PiiDetector>,
        fast: Box<dyn PiiDetector>,
        deep: Option<Box<dyn PiiDetector>>,
        mode: ScanMode,
    ) -> Self {
        Self {
            regex,
            fast,
            deep,
            rules: None,
            mode,
            confidence_threshold: 0.7,
            min_prompt_tokens: 200,
        }
    }

    /// Attach an optional custom-rules detector (runs alongside the regex pre-scan).
    pub fn with_rules(mut self, rules: Box<dyn PiiDetector>) -> Self {
        self.rules = Some(rules);
        self
    }

    /// Override the default confidence threshold (0.7) for auto-mode escalation.
    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Override the default minimum prompt token count (200) for auto-mode escalation.
    pub fn with_min_prompt_tokens(mut self, tokens: usize) -> Self {
        self.min_prompt_tokens = tokens;
        self
    }

    /// Run detection and return the full metadata result.
    pub async fn detect_with_metadata(
        &self,
        text: &str,
    ) -> Result<DetectionResult, DetectionError> {
        let deep_available = self.deep.is_some();

        match self.mode {
            ScanMode::Fast => {
                let spans = self.run_fast_tier(text).await?;
                let merged = merge_spans(spans);
                Ok(DetectionResult {
                    spans: merged,
                    deep_scan_used: false,
                    deep_scan_available: deep_available,
                })
            }
            ScanMode::Deep => {
                let mut fast_spans = self.run_fast_tier(text).await?;
                match self.run_deep_tier(text).await {
                    Ok(deep_spans) => {
                        fast_spans.extend(deep_spans);
                        let merged = merge_spans(fast_spans);
                        Ok(DetectionResult {
                            spans: merged,
                            deep_scan_used: true,
                            deep_scan_available: deep_available,
                        })
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "deep model unavailable in deep mode, returning fast results only"
                        );
                        let merged = merge_spans(fast_spans);
                        Ok(DetectionResult {
                            spans: merged,
                            deep_scan_used: false,
                            deep_scan_available: false,
                        })
                    }
                }
            }
            ScanMode::Auto => {
                let fast_spans = self.run_fast_tier(text).await?;
                let should_escalate = self.should_escalate(text, &fast_spans);

                if should_escalate && deep_available {
                    match self.run_deep_tier(text).await {
                        Ok(deep_spans) => {
                            let mut all = fast_spans;
                            all.extend(deep_spans);
                            let merged = merge_spans(all);
                            Ok(DetectionResult {
                                spans: merged,
                                deep_scan_used: true,
                                deep_scan_available: true,
                            })
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "deep model unavailable during auto-escalation, returning fast results"
                            );
                            let merged = merge_spans(fast_spans);
                            Ok(DetectionResult {
                                spans: merged,
                                deep_scan_used: false,
                                deep_scan_available: false,
                            })
                        }
                    }
                } else {
                    let merged = merge_spans(fast_spans);
                    Ok(DetectionResult {
                        spans: merged,
                        deep_scan_used: false,
                        deep_scan_available: deep_available,
                    })
                }
            }
        }
    }

    /// Run the regex + rules + fast model tier and collect all spans.
    async fn run_fast_tier(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        let regex_spans = self.regex.detect(text).await?;
        let fast_spans = self.fast.detect(text).await?;
        let mut all = regex_spans;
        all.extend(fast_spans);

        // Custom YAML rules run alongside the regex pre-scan (both are fast).
        if let Some(rules) = &self.rules {
            match rules.detect(text).await {
                Ok(rule_spans) => all.extend(rule_spans),
                Err(e) => {
                    tracing::warn!(error = %e, "custom rules detector failed, continuing without");
                }
            }
        }

        Ok(all)
    }

    /// Run the deep (27B) model tier. Returns an error if the deep model is unavailable.
    async fn run_deep_tier(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        match &self.deep {
            Some(deep) => deep.detect(text).await,
            None => Err(DetectionError::Other(
                "deep model not configured".to_string(),
            )),
        }
    }

    /// Determine whether auto mode should escalate to the deep model.
    ///
    /// Escalation triggers:
    /// 1. Any PII span from the fast tier has confidence below the threshold.
    /// 2. The fast tier found zero PII AND the prompt exceeds the token minimum
    ///    (approximated by whitespace-split word count).
    fn should_escalate(&self, text: &str, fast_spans: &[PiiSpan]) -> bool {
        // Trigger 1: low-confidence span
        let has_low_confidence = fast_spans
            .iter()
            .any(|s| s.confidence < self.confidence_threshold);
        if has_low_confidence {
            return true;
        }

        // Trigger 2: no PII on a long prompt
        if fast_spans.is_empty() {
            let token_count = text.split_whitespace().count();
            if token_count > self.min_prompt_tokens {
                return true;
            }
        }

        false
    }
}

#[async_trait]
impl PiiDetector for TieredDetector {
    async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        let result = self.detect_with_metadata(text).await?;
        Ok(result.spans)
    }

    fn name(&self) -> &str {
        "tiered"
    }
}

/// Merge spans from multiple detectors, deduplicating overlaps.
///
/// Algorithm:
/// 1. Sort by span length descending (longest first).
/// 2. Greedily keep each span unless it is fully contained within an
///    already-kept span.
/// 3. Sort the kept spans by start offset.
///
/// Because longer spans are processed first, when a regex span and a model span
/// overlap, the longer one wins. Likewise 27B spans (typically longer / more
/// precise) beat 4B spans.
fn merge_spans(mut spans: Vec<PiiSpan>) -> Vec<PiiSpan> {
    // Sort by (end - start) descending -- longest spans first
    spans.sort_by(|a, b| {
        let len_a = a.end - a.start;
        let len_b = b.end - b.start;
        len_b.cmp(&len_a)
    });

    let mut kept: Vec<PiiSpan> = Vec::with_capacity(spans.len());
    for span in spans {
        let fully_contained = kept
            .iter()
            .any(|existing| existing.start <= span.start && span.end <= existing.end);
        if !fully_contained {
            kept.push(span);
        }
    }

    // Sort final result by start offset
    kept.sort_by_key(|s| s.start);
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::types::PiiType;

    // -- Mock detector ----------------------------------------------------------

    struct MockDetector {
        spans: Vec<PiiSpan>,
        name: String,
    }

    impl MockDetector {
        fn new(name: &str, spans: Vec<PiiSpan>) -> Self {
            Self {
                spans: spans,
                name: name.to_string(),
            }
        }

        fn boxed(name: &str, spans: Vec<PiiSpan>) -> Box<dyn PiiDetector> {
            Box::new(Self::new(name, spans))
        }
    }

    #[async_trait]
    impl PiiDetector for MockDetector {
        async fn detect(&self, _text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
            Ok(self.spans.clone())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    /// Mock detector that always returns an error (simulates unavailable model).
    struct FailingDetector;

    #[async_trait]
    impl PiiDetector for FailingDetector {
        async fn detect(&self, _text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
            Err(DetectionError::ConnectionRefused(
                "mock: deep model down".to_string(),
            ))
        }

        fn name(&self) -> &str {
            "failing"
        }
    }

    // -- Helpers ----------------------------------------------------------------

    fn span(pii_type: PiiType, start: usize, end: usize, confidence: f64) -> PiiSpan {
        PiiSpan {
            pii_type,
            start,
            end,
            text: String::new(),
            confidence,
            implicit: false,
        }
    }

    fn make_long_text(word_count: usize) -> String {
        std::iter::repeat("word").take(word_count).collect::<Vec<_>>().join(" ")
    }

    // -- Tests ------------------------------------------------------------------

    #[tokio::test]
    async fn fast_mode_only_runs_regex_and_fast() {
        let regex_span = span(PiiType::Email, 0, 10, 1.0);
        let fast_span = span(PiiType::Person, 20, 30, 0.9);
        let deep_span = span(PiiType::Ssn, 40, 50, 0.95);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![regex_span]),
            MockDetector::boxed("fast", vec![fast_span]),
            Some(MockDetector::boxed("deep", vec![deep_span])),
            ScanMode::Fast,
        );

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert_eq!(result.spans.len(), 2);
        assert!(!result.deep_scan_used);
        assert!(result.deep_scan_available);
        // Deep span should NOT appear
        assert!(result
            .spans
            .iter()
            .all(|s| s.pii_type != PiiType::Ssn));
    }

    #[tokio::test]
    async fn deep_mode_runs_all_three() {
        let regex_span = span(PiiType::Email, 0, 10, 1.0);
        let fast_span = span(PiiType::Person, 20, 30, 0.9);
        let deep_span = span(PiiType::Ssn, 40, 51, 0.95);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![regex_span]),
            MockDetector::boxed("fast", vec![fast_span]),
            Some(MockDetector::boxed("deep", vec![deep_span])),
            ScanMode::Deep,
        );

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert_eq!(result.spans.len(), 3);
        assert!(result.deep_scan_used);
        assert!(result.deep_scan_available);
    }

    #[tokio::test]
    async fn auto_mode_no_escalation_when_high_confidence() {
        let fast_span = span(PiiType::Person, 0, 10, 0.9);
        let deep_span = span(PiiType::Ssn, 20, 30, 0.95);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![fast_span]),
            Some(MockDetector::boxed("deep", vec![deep_span])),
            ScanMode::Auto,
        );

        let result = detector.detect_with_metadata("short text").await.unwrap();
        assert_eq!(result.spans.len(), 1);
        assert!(!result.deep_scan_used);
        // Deep span should NOT appear
        assert!(result
            .spans
            .iter()
            .all(|s| s.pii_type != PiiType::Ssn));
    }

    #[tokio::test]
    async fn auto_mode_escalates_on_low_confidence() {
        let fast_span = span(PiiType::Person, 0, 10, 0.5); // below 0.7 threshold
        let deep_span = span(PiiType::Person, 0, 12, 0.95);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![fast_span]),
            Some(MockDetector::boxed("deep", vec![deep_span])),
            ScanMode::Auto,
        );

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert!(result.deep_scan_used);
        // Deep span (0..12) subsumes fast span (0..10), so only one kept
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].end, 12);
    }

    #[tokio::test]
    async fn auto_mode_escalates_on_zero_pii_long_prompt() {
        let deep_span = span(PiiType::Person, 100, 115, 0.85);
        let long_text = make_long_text(300);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![]), // 0 PII from fast
            Some(MockDetector::boxed("deep", vec![deep_span])),
            ScanMode::Auto,
        );

        let result = detector.detect_with_metadata(&long_text).await.unwrap();
        assert!(result.deep_scan_used);
        assert_eq!(result.spans.len(), 1);
    }

    #[tokio::test]
    async fn auto_mode_no_escalation_on_zero_pii_short_prompt() {
        let deep_span = span(PiiType::Person, 0, 10, 0.85);
        let short_text = make_long_text(50);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![]),
            Some(MockDetector::boxed("deep", vec![deep_span])),
            ScanMode::Auto,
        );

        let result = detector.detect_with_metadata(&short_text).await.unwrap();
        assert!(!result.deep_scan_used);
        assert!(result.spans.is_empty());
    }

    #[tokio::test]
    async fn overlapping_spans_deduped_longer_preferred() {
        // Short span fully contained within a longer span
        let short_span = span(PiiType::Email, 5, 15, 1.0);
        let long_span = span(PiiType::Credential, 0, 20, 0.95);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![short_span]),
            MockDetector::boxed("fast", vec![long_span]),
            None,
            ScanMode::Fast,
        );

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert_eq!(result.spans.len(), 1);
        // The longer span (0..20) should be kept
        assert_eq!(result.spans[0].start, 0);
        assert_eq!(result.spans[0].end, 20);
    }

    #[tokio::test]
    async fn deep_model_unavailable_returns_fast_with_flag() {
        let fast_span = span(PiiType::Person, 0, 10, 0.5);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![fast_span]),
            Some(Box::new(FailingDetector)), // deep fails
            ScanMode::Auto,
        );

        let result = detector.detect_with_metadata("test").await.unwrap();
        // Should have escalated (low confidence) but deep failed
        assert!(!result.deep_scan_used);
        assert!(!result.deep_scan_available);
        // Fast results still returned
        assert_eq!(result.spans.len(), 1);
    }

    #[tokio::test]
    async fn pii_detector_trait_returns_spans() {
        let fast_span = span(PiiType::Email, 0, 10, 1.0);

        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![fast_span]),
            None,
            ScanMode::Fast,
        );

        // Test the PiiDetector trait implementation
        let spans = detector.detect("test").await.unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(detector.name(), "tiered");
    }

    #[test]
    fn merge_sorts_by_start_offset() {
        let spans = vec![
            span(PiiType::Person, 30, 40, 0.9),
            span(PiiType::Email, 0, 10, 1.0),
            span(PiiType::Phone, 15, 25, 0.8),
        ];
        let merged = merge_spans(spans);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[1].start, 15);
        assert_eq!(merged[2].start, 30);
    }

    #[test]
    fn merge_removes_fully_contained_spans() {
        let spans = vec![
            span(PiiType::Credential, 0, 30, 0.95),
            span(PiiType::Email, 5, 20, 1.0),   // fully inside 0..30
            span(PiiType::Person, 10, 15, 0.9),  // fully inside 0..30
        ];
        let merged = merge_spans(spans);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 30);
    }

    #[test]
    fn merge_keeps_non_overlapping_spans() {
        let spans = vec![
            span(PiiType::Email, 0, 10, 1.0),
            span(PiiType::Person, 20, 30, 0.9),
        ];
        let merged = merge_spans(spans);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_keeps_partially_overlapping_spans() {
        // Spans that partially overlap but neither fully contains the other
        let spans = vec![
            span(PiiType::Email, 0, 15, 1.0),
            span(PiiType::Person, 10, 25, 0.9),
        ];
        let merged = merge_spans(spans);
        // Both kept since neither fully contains the other
        assert_eq!(merged.len(), 2);
    }
}
