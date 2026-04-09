use gateway_anonymizer::rules::RuleDetector;
use gateway_anonymizer::detector::PiiDetector;
use gateway_common::types::PiiType;

/// Helper: run detect synchronously.
fn detect_blocking(detector: &RuleDetector, text: &str) -> Vec<gateway_common::types::PiiSpan> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(detector.detect(text)).unwrap()
}

// ── Regex rule ──────────────────────────────────────────────────────────────

#[test]
fn regex_rule_detects_matching_text() {
    let yaml = r#"
rules:
  - name: "project-codenames"
    type: "ORGANIZATION"
    patterns:
      - "Project\\s+Phoenix"
    confidence: 0.9
"#;
    let det = RuleDetector::from_yaml(yaml).unwrap();
    let spans = detect_blocking(&det, "We are launching Project Phoenix next month.");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].pii_type, PiiType::Organization);
    assert_eq!(spans[0].text, "Project Phoenix");
    assert_eq!(spans[0].confidence, 0.9);
    assert!(!spans[0].implicit);
}

// ── Keyword rule ────────────────────────────────────────────────────────────

#[test]
fn keyword_rule_detects_exact_match() {
    let yaml = r#"
rules:
  - name: "client-names"
    type: "PERSON"
    keywords:
      - "Dr. Martinez"
    confidence: 0.95
"#;
    let det = RuleDetector::from_yaml(yaml).unwrap();
    let spans = detect_blocking(&det, "Meeting with Dr. Martinez at 3pm.");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].pii_type, PiiType::Person);
    assert_eq!(spans[0].text, "Dr. Martinez");
    assert_eq!(spans[0].confidence, 0.95);
}

// ── Multiple rules ──────────────────────────────────────────────────────────

#[test]
fn multiple_rules_all_applied() {
    let yaml = r#"
rules:
  - name: "project-codenames"
    type: "ORGANIZATION"
    patterns:
      - "Project\\s+Phoenix"
    confidence: 0.9
  - name: "client-names"
    type: "PERSON"
    keywords:
      - "Dr. Martinez"
    confidence: 0.95
  - name: "offices"
    type: "LOCATION"
    keywords:
      - "Building 42"
    confidence: 0.7
"#;
    let det = RuleDetector::from_yaml(yaml).unwrap();
    let text = "Dr. Martinez discussed Project Phoenix in Building 42.";
    let spans = detect_blocking(&det, text);
    assert_eq!(spans.len(), 3);

    let types: Vec<PiiType> = spans.iter().map(|s| s.pii_type).collect();
    assert!(types.contains(&PiiType::Person));
    assert!(types.contains(&PiiType::Organization));
    assert!(types.contains(&PiiType::Location));
}

// ── Empty rules ─────────────────────────────────────────────────────────────

#[test]
fn empty_rules_no_detections() {
    let yaml = "rules: []\n";
    let det = RuleDetector::from_yaml(yaml).unwrap();
    let spans = detect_blocking(&det, "This text contains alice@example.com and other PII.");
    assert!(spans.is_empty());
}

// ── Invalid regex ───────────────────────────────────────────────────────────

#[test]
fn invalid_regex_skipped_others_still_work() {
    let yaml = r#"
rules:
  - name: "mixed"
    type: "ORGANIZATION"
    patterns:
      - "(unclosed"
      - "Project\\s+Titan"
    confidence: 0.9
"#;
    let det = RuleDetector::from_yaml(yaml).unwrap();
    let spans = detect_blocking(&det, "Launch Project Titan next quarter.");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].text, "Project Titan");
}

// ── Malformed YAML ──────────────────────────────────────────────────────────

#[test]
fn malformed_yaml_returns_error() {
    let yaml = "not: valid: yaml: [";
    let result = RuleDetector::from_yaml(yaml);
    assert!(result.is_err());
}

// ── Rule overlap with regex detector → deduped by merge_spans ───────────────

#[test]
fn rule_overlap_deduped_by_merge_spans() {
    use gateway_anonymizer::tiered::TieredDetector;
    use gateway_anonymizer::regex_detector::RegexDetector;
    use gateway_common::types::ScanMode;

    // A keyword rule that matches the same email the regex detector finds.
    let yaml = r#"
rules:
  - name: "known-emails"
    type: "EMAIL"
    keywords:
      - "alice@example.com"
    confidence: 0.95
"#;
    let rule_det = RuleDetector::from_yaml(yaml).unwrap();

    // Build a mock fast detector that returns nothing (we only care about
    // regex + rules overlap here).
    struct EmptyDetector;

    #[async_trait::async_trait]
    impl PiiDetector for EmptyDetector {
        async fn detect(
            &self,
            _text: &str,
        ) -> Result<Vec<gateway_common::types::PiiSpan>, gateway_common::errors::DetectionError> {
            Ok(vec![])
        }
        fn name(&self) -> &str {
            "empty"
        }
    }

    let tiered = TieredDetector::new(
        Box::new(RegexDetector::new()),
        Box::new(EmptyDetector),
        None,
        ScanMode::Fast,
    )
    .with_rules(Box::new(rule_det));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(tiered.detect_with_metadata("Contact alice@example.com for info."));
    let spans = result.unwrap().spans;

    // Both detectors found the same email, but merge_spans should collapse them.
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].text, "alice@example.com");
}

// ── from_file with a real file ──────────────────────────────────────────────

#[test]
fn from_file_loads_and_detects() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.yaml");
    std::fs::write(
        &path,
        r#"
rules:
  - name: "test-rule"
    type: "PERSON"
    keywords:
      - "Jane Doe"
    confidence: 0.9
"#,
    )
    .unwrap();

    let det = RuleDetector::from_file(path.to_str().unwrap()).unwrap();
    let spans = detect_blocking(&det, "Please contact Jane Doe.");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].text, "Jane Doe");
}

#[test]
fn from_file_nonexistent_returns_error() {
    let result = RuleDetector::from_file("/tmp/does_not_exist_98765.yaml");
    assert!(result.is_err());
}
