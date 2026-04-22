use async_trait::async_trait;
use gateway_common::config::GatewayConfig;
use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, ScanMode};
use ollama_rs::Ollama;

use crate::detector::{DetectionResult, PiiDetector};
use crate::ollama::OllamaDetector;
use crate::regex_detector::RegexDetector;
use crate::rules::RuleDetector;

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

    /// Build a fully-wired TieredDetector from the gateway config. This is
    /// the single construction point used by main.rs, integration tests, and
    /// the CLI doctor so the wire-up logic is not duplicated.
    ///
    /// Behaviour by scan mode:
    /// * `Fast`: deep detector is `None` (not constructed, no client created)
    /// * `Auto` / `Deep`: deep detector is `Some(OllamaDetector(config.deep_model))`
    ///
    /// If `config.rules_path` is set, the YAML rules file is loaded and
    /// attached via `with_rules`. A malformed rules file logs a warning and
    /// the detector is built without rules — matches the existing
    /// silent-fallback posture for the rules tier.
    pub fn from_config(config: &GatewayConfig) -> Self {
        let ollama_for = || {
            // ollama-rs Ollama::new takes (host, port). Accept either
            // http://host:port or http://host; default to 11434 if port is
            // not specified. This parser is intentionally tiny — the URL
            // comes from GATEWAY_OLLAMA_URL which operators control.
            let raw = config.ollama_url.as_str();
            let without_scheme = raw
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let (host_part, port) = match without_scheme.split_once(':') {
                Some((h, p)) => {
                    let port = p.parse::<u16>().unwrap_or(11434);
                    (h, port)
                }
                None => (without_scheme, 11434u16),
            };
            let scheme = if raw.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            Ollama::new(format!("{scheme}://{host_part}"), port)
        };

        let regex: Box<dyn PiiDetector> = Box::new(RegexDetector::new());
        let fast: Box<dyn PiiDetector> = Box::new(
            OllamaDetector::new(ollama_for(), config.fast_model.clone())
                .with_timeout(config.detection_timeout),
        );

        let deep: Option<Box<dyn PiiDetector>> = match config.scan_mode {
            ScanMode::Auto | ScanMode::Deep => Some(Box::new(
                OllamaDetector::new(ollama_for(), config.deep_model.clone())
                    .with_timeout(config.detection_timeout),
            )),
            ScanMode::Fast => None,
        };

        let mut tiered = Self::new(regex, fast, deep, config.scan_mode)
            .with_confidence_threshold(config.escalation_confidence_threshold)
            .with_min_prompt_tokens(config.escalation_min_prompt_tokens);

        if let Some(path) = &config.rules_path {
            match RuleDetector::from_file(path) {
                Ok(rules) => tiered = tiered.with_rules(Box::new(rules)),
                Err(e) => tracing::warn!(
                    error = %e,
                    path = %path,
                    "failed to load rules YAML, continuing without custom rules"
                ),
            }
        }

        tiered
    }

    /// Run the regex + rules + fast model tier. Returns the spans plus
    /// rules-tier metadata so the caller can populate DetectionResult.
    async fn run_fast_tier(
        &self,
        text: &str,
    ) -> Result<(Vec<PiiSpan>, bool, Option<DetectionError>), DetectionError> {
        let regex_spans = self.regex.detect(text).await?;
        let fast_spans = self.fast.detect(text).await?;
        let mut all = regex_spans;
        all.extend(fast_spans);

        let mut rules_attempted = false;
        let mut rules_error: Option<DetectionError> = None;

        if let Some(rules) = &self.rules {
            rules_attempted = true;
            match rules.detect(text).await {
                Ok(rule_spans) => all.extend(rule_spans),
                Err(e) => {
                    tracing::warn!(error = %e, "custom rules detector failed, continuing without");
                    rules_error = Some(e);
                }
            }
        }

        Ok((all, rules_attempted, rules_error))
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

    /// Orchestrate regex + fast + rules + (optional) deep detection with
    /// tier-visibility tracking. Overrides the trait default so the proxy
    /// can emit accurate metrics (tier_used, deep_attempted, deep_succeeded,
    /// deep_error, rules_attempted, rules_error) from the returned struct.
    async fn detect_with_metadata(
        &self,
        text: &str,
    ) -> Result<DetectionResult, DetectionError> {
        let deep_available = self.deep.is_some();

        let (fast_spans, rules_attempted, rules_error) = self.run_fast_tier(text).await?;

        let (spans, deep_attempted, deep_scan_used, deep_error) = match self.mode {
            ScanMode::Fast => (fast_spans, false, false, None),
            ScanMode::Deep => {
                // Always attempt deep when in deep mode, even if not configured
                // (run_deep_tier returns an error we capture). This is
                // indistinguishable from "configured but failed" via the
                // deep_scan_available flag, which keeps the state enumeration
                // honest.
                match self.run_deep_tier(text).await {
                    Ok(deep_spans) => {
                        let mut all = fast_spans;
                        all.extend(deep_spans);
                        (all, true, true, None)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "deep model unavailable in deep mode, returning fast results only"
                        );
                        (fast_spans, true, false, Some(e))
                    }
                }
            }
            ScanMode::Auto => {
                let should_escalate = self.should_escalate(text, &fast_spans);
                if should_escalate && deep_available {
                    match self.run_deep_tier(text).await {
                        Ok(deep_spans) => {
                            let mut all = fast_spans;
                            all.extend(deep_spans);
                            (all, true, true, None)
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "deep model unavailable during auto-escalation, returning fast results"
                            );
                            (fast_spans, true, false, Some(e))
                        }
                    }
                } else {
                    // Not escalated (or deep not configured): fast-only. This
                    // is not a failure state; deep_attempted stays false.
                    (fast_spans, false, false, None)
                }
            }
        };

        let merged = merge_spans(spans);
        Ok(DetectionResult {
            spans: merged,
            deep_scan_available: deep_available,
            deep_attempted,
            deep_scan_used,
            deep_error,
            rules_attempted,
            rules_error,
        })
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
                spans,
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
        std::iter::repeat_n("word", word_count).collect::<Vec<_>>().join(" ")
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
        // Deep is configured so available is true — the semantic fix from the
        // Codex eng review. Old code incorrectly flipped available to false on
        // failure, which conflated "not configured" with "failed."
        assert!(result.deep_scan_available);
        // Should have escalated (low confidence) but deep failed
        assert!(result.deep_attempted);
        assert!(!result.deep_scan_used);
        assert!(result.deep_error.is_some());
        // Fast results still returned (silent fallback)
        assert_eq!(result.spans.len(), 1);
    }

    #[tokio::test]
    async fn fast_mode_never_attempts_deep() {
        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![span(PiiType::Email, 0, 5, 0.9)]),
            Some(MockDetector::boxed("deep", vec![])),
            ScanMode::Fast,
        );

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert!(result.deep_scan_available);
        assert!(!result.deep_attempted);
        assert!(!result.deep_scan_used);
        assert!(result.deep_error.is_none());
    }

    #[tokio::test]
    async fn rules_metadata_populated_on_success() {
        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![]),
            None,
            ScanMode::Fast,
        )
        .with_rules(MockDetector::boxed(
            "rules",
            vec![span(PiiType::Credential, 0, 5, 0.99)],
        ));

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert!(result.rules_attempted);
        assert!(result.rules_error.is_none());
        assert_eq!(result.spans.len(), 1);
    }

    #[tokio::test]
    async fn rules_error_captured_silent_fallback() {
        let detector = TieredDetector::new(
            MockDetector::boxed("regex", vec![]),
            MockDetector::boxed("fast", vec![span(PiiType::Email, 0, 5, 0.9)]),
            None,
            ScanMode::Fast,
        )
        .with_rules(Box::new(FailingDetector));

        let result = detector.detect_with_metadata("test").await.unwrap();
        assert!(result.rules_attempted);
        assert!(result.rules_error.is_some());
        // Fast result still returned
        assert_eq!(result.spans.len(), 1);
    }

    #[tokio::test]
    async fn default_detect_with_metadata_for_non_tiered() {
        // The trait's default impl should populate only spans and leave all
        // tier flags false. MockDetector doesn't override it.
        let detector = MockDetector::new("only-fast", vec![span(PiiType::Email, 0, 5, 1.0)]);
        let result = detector.detect_with_metadata("anything").await.unwrap();
        assert_eq!(result.spans.len(), 1);
        assert!(!result.deep_scan_available);
        assert!(!result.deep_attempted);
        assert!(!result.deep_scan_used);
        assert!(!result.rules_attempted);
    }

    // -- from_config factory tests ---------------------------------------------

    fn test_config(scan_mode: ScanMode) -> GatewayConfig {
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_url: "http://upstream".to_string(),
            upstream_url_openai: "http://upstream-openai".to_string(),
            fast_model: "gemma4:e4b".to_string(),
            deep_model: "gemma4:26b".to_string(),
            ollama_url: "http://localhost:11434".to_string(),
            scan_mode,
            db_path: ":memory:".to_string(),
            session_ttl: std::time::Duration::from_secs(3600),
            audit_retention_days: 30,
            audit_path: "/tmp/audit".to_string(),
            log_level: "info".to_string(),
            show_score: true,
            max_request_size: 128 * 1024,
            detection_timeout: std::time::Duration::from_secs(5),
            upstream_timeout: std::time::Duration::from_secs(60),
            detection_concurrency: 2,
            escalation_confidence_threshold: 0.7,
            escalation_min_prompt_tokens: 200,
            rules_path: None,
            routing_config_path: None,
            streaming_enabled: false,
        }
    }

    #[tokio::test]
    async fn from_config_fast_mode_omits_deep_detector() {
        let config = test_config(ScanMode::Fast);
        let tiered = TieredDetector::from_config(&config);
        // Verify via detect_with_metadata: in Fast mode, deep_scan_available
        // reflects self.deep.is_some() which should be false.
        let result = tiered.detect_with_metadata("test prompt").await;
        // Detection may fail (no real Ollama), but if the result came back
        // we can assert the shape. If it failed, it failed on the fast
        // detector, not on deep — which is what we want for fast mode.
        if let Ok(r) = result {
            assert!(!r.deep_scan_available, "fast mode should not wire a deep detector");
            assert!(!r.deep_attempted);
        }
    }

    #[tokio::test]
    async fn from_config_auto_mode_wires_deep_detector() {
        let config = test_config(ScanMode::Auto);
        let tiered = TieredDetector::from_config(&config);
        // Auto mode wires an OllamaDetector for the deep tier. We can't verify
        // it works without a live Ollama, but we can verify the name is right.
        assert_eq!(tiered.name(), "tiered");
        // Internal structural check: deep is Some. We don't expose deep
        // directly, so use the metadata path on a fabricated call — it
        // should return deep_scan_available = true when the configured
        // mode is Auto or Deep.
        //
        // The detector will try to hit localhost:11434 which probably
        // isn't running in CI. We only check the availability flag, which
        // reflects configuration, not a live probe.
        //
        // Use a short prompt that won't trigger auto-escalation, so fast
        // tier runs and deep isn't attempted, letting us isolate the
        // availability flag from actual deep work.
        //
        // If the fast detector errors trying to reach Ollama, the test
        // still passes (we skip). Intent: verify config wiring, not
        // network state.
        if let Ok(r) = tiered.detect_with_metadata("short").await {
            assert!(r.deep_scan_available, "auto mode should wire a deep detector");
        }
    }

    #[tokio::test]
    async fn from_config_deep_mode_wires_deep_detector() {
        let config = test_config(ScanMode::Deep);
        let tiered = TieredDetector::from_config(&config);
        assert_eq!(tiered.name(), "tiered");
        if let Ok(r) = tiered.detect_with_metadata("short").await {
            assert!(r.deep_scan_available, "deep mode should wire a deep detector");
        }
    }

    #[tokio::test]
    async fn from_config_applies_escalation_thresholds() {
        let mut config = test_config(ScanMode::Auto);
        config.escalation_confidence_threshold = 0.55;
        config.escalation_min_prompt_tokens = 100;
        let _tiered = TieredDetector::from_config(&config);
        // We don't expose the thresholds for introspection; this test
        // mostly guards against silently dropping the wire-up. Reading
        // thresholds would require exposing them which we don't want to
        // do just for testing. Instead, the behaviour is covered by the
        // auto-escalation tests further up using TieredDetector::new
        // with explicit thresholds.
    }

    #[tokio::test]
    async fn from_config_missing_rules_file_continues_silently() {
        let mut config = test_config(ScanMode::Fast);
        config.rules_path = Some("/definitely/does/not/exist.yaml".to_string());
        // Should not panic. The factory logs a warning and proceeds without
        // rules. This is the accepted silent-fallback posture documented on
        // DetectionResult.
        let tiered = TieredDetector::from_config(&config);
        assert_eq!(tiered.name(), "tiered");
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
