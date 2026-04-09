use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Categories of personally identifiable information.
///
/// Each variant carries a severity weight used in privacy score computation:
///   PERSON(implicit)=15, PERSON(explicit)=10, ORG(implicit)=8, ORG(explicit)=5,
///   LOCATION=5, EMAIL/PHONE/SSN=12, CREDENTIAL=20
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PiiType {
    Person,
    Organization,
    Location,
    Email,
    Phone,
    Ssn,
    Credential,
}

impl PiiType {
    /// Placeholder prefix used in substitution, e.g. `[PERSON_a7f3b2c1]`.
    pub fn placeholder_prefix(&self) -> &'static str {
        match self {
            Self::Person => "PERSON",
            Self::Organization => "ORG",
            Self::Location => "LOCATION",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::Ssn => "SSN",
            Self::Credential => "CREDENTIAL",
        }
    }

    /// Severity weight for privacy score computation.
    pub fn weight(&self, implicit: bool) -> u32 {
        match (self, implicit) {
            (Self::Person, true) => 15,
            (Self::Person, false) => 10,
            (Self::Organization, true) => 8,
            (Self::Organization, false) => 5,
            (Self::Location, _) => 5,
            (Self::Email, _) => 12,
            (Self::Phone, _) => 12,
            (Self::Ssn, _) => 12,
            (Self::Credential, _) => 20,
        }
    }
}

/// A detected PII entity within a text span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiSpan {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f64,
    pub implicit: bool,
}

/// A placeholder that replaced a PII entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Placeholder {
    pub id: String,
    pub pii_type: PiiType,
    pub placeholder_text: String,
    pub original_text: String,
}

impl Placeholder {
    pub fn new(pii_type: PiiType, original_text: String) -> Self {
        let short_id = &uuid::Uuid::new_v4().to_string()[..8];
        let placeholder_text = format!("[{}_{short_id}]", pii_type.placeholder_prefix());
        Self {
            id: short_id.to_string(),
            pii_type,
            placeholder_text,
            original_text,
        }
    }
}

/// Session-keyed mapping of placeholders for multi-turn deanonymization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMapping {
    pub session_id: String,
    pub placeholders: HashMap<String, Placeholder>,
    pub created_at: DateTime<Utc>,
}

/// A single entry in the hash-chained audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub pii_spans_detected: usize,
    pub pii_types: Vec<PiiType>,
    pub placeholders_generated: usize,
    pub privacy_score: u32,
    pub hash: String,
    pub prev_hash: String,
}

/// Privacy score for a single request (0-100).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PrivacyScore(pub u32);

impl PrivacyScore {
    pub fn compute(spans: &[PiiSpan]) -> Self {
        let total_weight: f64 = spans
            .iter()
            .map(|s| f64::from(s.pii_type.weight(s.implicit)) * s.confidence)
            .sum();
        let score = (100.0 - total_weight).max(0.0) as u32;
        Self(score.min(100))
    }

    pub fn value(&self) -> u32 {
        self.0
    }

    pub fn classification(&self) -> &'static str {
        match self.0 {
            90..=100 => "LOW",
            50..=89 => "MEDIUM",
            _ => "HIGH",
        }
    }
}

/// Scan mode for tiered PII detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Fast,
    Deep,
    Auto,
}

impl std::str::FromStr for ScanMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fast" => Ok(Self::Fast),
            "deep" => Ok(Self::Deep),
            "auto" => Ok(Self::Auto),
            other => Err(format!("invalid scan mode: {other}. expected: fast, deep, auto")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_span_serializes_to_json() {
        let span = PiiSpan {
            pii_type: PiiType::Person,
            start: 0,
            end: 10,
            text: "John Smith".into(),
            confidence: 0.95,
            implicit: false,
        };
        let json = serde_json::to_string(&span).unwrap();
        let deserialized: PiiSpan = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pii_type, PiiType::Person);
        assert_eq!(deserialized.text, "John Smith");
    }

    #[test]
    fn pii_type_covers_all_categories() {
        let types = [
            PiiType::Person,
            PiiType::Organization,
            PiiType::Location,
            PiiType::Email,
            PiiType::Phone,
            PiiType::Ssn,
            PiiType::Credential,
        ];
        assert_eq!(types.len(), 7);
        for t in &types {
            assert!(!t.placeholder_prefix().is_empty());
            assert!(t.weight(false) > 0);
        }
    }

    #[test]
    fn placeholder_generates_unique_ids() {
        let p1 = Placeholder::new(PiiType::Person, "Alice".into());
        let p2 = Placeholder::new(PiiType::Person, "Bob".into());
        assert_ne!(p1.id, p2.id);
        assert!(p1.placeholder_text.starts_with("[PERSON_"));
        assert!(p1.placeholder_text.ends_with(']'));
    }

    #[test]
    fn privacy_score_no_pii_is_100() {
        let score = PrivacyScore::compute(&[]);
        assert_eq!(score.value(), 100);
        assert_eq!(score.classification(), "LOW");
    }

    #[test]
    fn privacy_score_floors_at_zero() {
        let spans: Vec<PiiSpan> = (0..20)
            .map(|i| PiiSpan {
                pii_type: PiiType::Credential,
                start: i * 10,
                end: i * 10 + 5,
                text: format!("key_{i}"),
                confidence: 1.0,
                implicit: false,
            })
            .collect();
        let score = PrivacyScore::compute(&spans);
        assert_eq!(score.value(), 0);
        assert_eq!(score.classification(), "HIGH");
    }

    #[test]
    fn privacy_score_weights_implicit_higher() {
        let explicit = PiiSpan {
            pii_type: PiiType::Person,
            start: 0,
            end: 5,
            text: "Alice".into(),
            confidence: 1.0,
            implicit: false,
        };
        let implicit = PiiSpan {
            pii_type: PiiType::Person,
            start: 0,
            end: 5,
            text: "the professor".into(),
            confidence: 1.0,
            implicit: true,
        };
        let score_explicit = PrivacyScore::compute(&[explicit]);
        let score_implicit = PrivacyScore::compute(&[implicit]);
        assert!(score_implicit.value() < score_explicit.value());
    }

    #[test]
    fn scan_mode_parses_from_string() {
        assert_eq!("fast".parse::<ScanMode>().unwrap(), ScanMode::Fast);
        assert_eq!("Deep".parse::<ScanMode>().unwrap(), ScanMode::Deep);
        assert_eq!("AUTO".parse::<ScanMode>().unwrap(), ScanMode::Auto);
        assert!("invalid".parse::<ScanMode>().is_err());
    }
}
