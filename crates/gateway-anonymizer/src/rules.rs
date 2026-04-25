use async_trait::async_trait;
use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, PiiType};
use regex::Regex;
use serde::Deserialize;

use crate::detector::PiiDetector;

// ---------------------------------------------------------------------------
// YAML schema structs
// ---------------------------------------------------------------------------

/// Top-level YAML document containing a list of custom PII rules.
#[derive(Debug, Deserialize)]
pub struct RulesFile {
    #[serde(default)]
    pub rules: Vec<RuleDef>,
}

/// A single rule definition as written in YAML.
#[derive(Debug, Deserialize)]
pub struct RuleDef {
    pub name: String,
    #[serde(rename = "type")]
    pub pii_type_str: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

fn default_confidence() -> f64 {
    0.8
}

// ---------------------------------------------------------------------------
// Compiled rule (internal)
// ---------------------------------------------------------------------------

/// A compiled rule ready for scanning.
struct CompiledRule {
    #[allow(dead_code)]
    name: String,
    pii_type: PiiType,
    regexes: Vec<Regex>,
    keywords: Vec<String>,
    confidence: f64,
}

// ---------------------------------------------------------------------------
// RuleDetector
// ---------------------------------------------------------------------------

/// A PII detector driven by user-defined YAML rules.
///
/// Rules may specify regex `patterns` (compiled once at construction) and/or
/// literal `keywords` (case-sensitive substring search). Each match produces a
/// `PiiSpan` with `implicit: false` and the configured confidence.
pub struct RuleDetector {
    rules: Vec<CompiledRule>,
}

impl RuleDetector {
    /// Load rules from a YAML file on disk.
    pub fn from_file(path: &str) -> Result<Self, DetectionError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DetectionError::Other(format!("failed to read rules file {path}: {e}")))?;
        Self::from_yaml(&content)
    }

    /// Parse rules from a YAML string.
    pub fn from_yaml(yaml_str: &str) -> Result<Self, DetectionError> {
        let file: RulesFile = serde_yaml::from_str(yaml_str)
            .map_err(|e| DetectionError::Other(format!("invalid rules YAML: {e}")))?;

        let mut compiled = Vec::with_capacity(file.rules.len());

        for def in file.rules {
            let pii_type = parse_pii_type(&def.pii_type_str).unwrap_or_else(|| {
                tracing::warn!(
                    rule = %def.name,
                    pii_type = %def.pii_type_str,
                    "unknown PII type in rule, defaulting to Person"
                );
                PiiType::Person
            });

            let mut regexes = Vec::with_capacity(def.patterns.len());
            for pat in &def.patterns {
                match Regex::new(pat) {
                    Ok(re) => regexes.push(re),
                    Err(e) => {
                        tracing::warn!(
                            rule = %def.name,
                            pattern = %pat,
                            error = %e,
                            "invalid regex in rule, skipping pattern"
                        );
                    }
                }
            }

            compiled.push(CompiledRule {
                name: def.name,
                pii_type,
                regexes,
                keywords: def.keywords,
                confidence: def.confidence,
            });
        }

        Ok(Self { rules: compiled })
    }
}

#[async_trait]
impl PiiDetector for RuleDetector {
    async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        let mut results = Vec::new();

        for rule in &self.rules {
            // Regex patterns
            for re in &rule.regexes {
                for m in re.find_iter(text) {
                    results.push(PiiSpan {
                        pii_type: rule.pii_type,
                        start: m.start(),
                        end: m.end(),
                        text: m.as_str().to_string(),
                        confidence: rule.confidence,
                        implicit: false,
                    });
                }
            }

            // Keyword substring matches (case-sensitive)
            for kw in &rule.keywords {
                let mut search_from = 0;
                while let Some(pos) = text[search_from..].find(kw.as_str()) {
                    let start = search_from + pos;
                    let end = start + kw.len();
                    results.push(PiiSpan {
                        pii_type: rule.pii_type,
                        start,
                        end,
                        text: kw.clone(),
                        confidence: rule.confidence,
                        implicit: false,
                    });
                    search_from = end;
                }
            }
        }

        // Sort by start offset for deterministic output
        results.sort_by_key(|s| s.start);
        Ok(results)
    }

    fn name(&self) -> &str {
        "rules"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a YAML type string to a PiiType variant.
fn parse_pii_type(s: &str) -> Option<PiiType> {
    match s.to_uppercase().as_str() {
        "PERSON" => Some(PiiType::Person),
        "ORGANIZATION" | "ORG" => Some(PiiType::Organization),
        "LOCATION" => Some(PiiType::Location),
        "EMAIL" => Some(PiiType::Email),
        "PHONE" => Some(PiiType::Phone),
        "SSN" => Some(PiiType::Ssn),
        "CREDENTIAL" => Some(PiiType::Credential),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_blocking(detector: &RuleDetector, text: &str) -> Vec<PiiSpan> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(detector.detect(text)).unwrap()
    }

    #[test]
    fn regex_rule_detects_match() {
        let yaml = r#"
rules:
  - name: "project-codenames"
    type: "ORGANIZATION"
    patterns:
      - "Project\\s+Phoenix"
    confidence: 0.9
"#;
        let det = RuleDetector::from_yaml(yaml).unwrap();
        let spans = detect_blocking(&det, "We discussed Project Phoenix last week.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Organization);
        assert_eq!(spans[0].text, "Project Phoenix");
        assert_eq!(spans[0].confidence, 0.9);
        assert!(!spans[0].implicit);
    }

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
        let spans = detect_blocking(&det, "Please schedule a call with Dr. Martinez tomorrow.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Person);
        assert_eq!(spans[0].text, "Dr. Martinez");
        assert_eq!(spans[0].confidence, 0.95);
    }

    #[test]
    fn keyword_not_found_returns_empty() {
        let yaml = r#"
rules:
  - name: "client-names"
    type: "PERSON"
    keywords:
      - "Dr. Martinez"
    confidence: 0.95
"#;
        let det = RuleDetector::from_yaml(yaml).unwrap();
        let spans = detect_blocking(&det, "The weather is nice today.");
        assert!(spans.is_empty());
    }

    #[test]
    fn multiple_keyword_occurrences() {
        let yaml = r#"
rules:
  - name: "names"
    type: "PERSON"
    keywords:
      - "Alice"
    confidence: 0.9
"#;
        let det = RuleDetector::from_yaml(yaml).unwrap();
        let spans = detect_blocking(&det, "Alice met Alice at the park.");
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn empty_rules_file_no_detections() {
        let yaml = "rules: []\n";
        let det = RuleDetector::from_yaml(yaml).unwrap();
        let spans = detect_blocking(&det, "Contact alice@example.com for info.");
        assert!(spans.is_empty());
    }

    #[test]
    fn invalid_regex_skipped_others_work() {
        let yaml = r#"
rules:
  - name: "bad-and-good"
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

    #[test]
    fn malformed_yaml_returns_error() {
        let yaml = "not: valid: yaml: [";
        let result = RuleDetector::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn default_confidence_when_omitted() {
        let yaml = r#"
rules:
  - name: "no-conf"
    type: "PERSON"
    keywords:
      - "Bob"
"#;
        let det = RuleDetector::from_yaml(yaml).unwrap();
        let spans = detect_blocking(&det, "Ask Bob.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].confidence, 0.8); // default
    }

    #[test]
    fn unknown_pii_type_defaults_to_person() {
        let yaml = r#"
rules:
  - name: "custom-type"
    type: "UNKNOWN_TYPE"
    keywords:
      - "secret-thing"
    confidence: 0.85
"#;
        let det = RuleDetector::from_yaml(yaml).unwrap();
        let spans = detect_blocking(&det, "Found secret-thing in the logs.");
        assert_eq!(spans[0].pii_type, PiiType::Person);
    }

    #[test]
    fn name_returns_rules() {
        let det = RuleDetector::from_yaml("rules: []").unwrap();
        assert_eq!(det.name(), "rules");
    }
}
