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

/// Status of an audit entry's response hash. Streaming responses can't
/// finalise the hash until the stream completes, so receipts emitted
/// during streaming declare `pending` and are upgraded to `final` once
/// the response body is fully consumed. Codex F9.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseHashStatus {
    #[default]
    Final,
    Pending,
}

/// Status of a transparency-log anchor for an audit entry. Receipts are
/// returned to clients as soon as the entry is written, often before the
/// next batched Rekor checkpoint. Anchoring is best-effort against a
/// public-good service with a 99.5% SLO; receipts must verify offline
/// first and report anchor state explicitly. Codex F15.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    #[default]
    NotYetAnchored,
    Anchored,
    AnchorFailed,
}

/// A single entry in the hash-chained audit trail.
///
/// `hash_recipe` controls how `hash` was computed. Legacy entries written
/// before 2026-04-25 do not carry the field; deserialisation defaults
/// missing values to `audit-v1` so they continue to verify under the
/// original 5-field SHA-256 recipe. Entries written today use
/// `audit-v2-canonical-json`, which authenticates every field except
/// `hash` itself, eliminating the previous unauthenticated-field gap
/// (Codex F2 + F3 from the 2026-04-25 plan-eng-review).
///
/// All fields added since the v2 recipe landed carry `#[serde(default)]`
/// so that ANY future on-disk entry written under v2 verifies under
/// canonical-JSON-of-the-current-struct without forking the chain on
/// older deployments. The hash is computed over the entry's serialised
/// canonical JSON minus the `hash` field, which is independent of which
/// fields a particular writer chose to populate.
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
    /// Identifier for the hashing scheme used to produce `hash`. Missing
    /// in legacy on-disk entries (deserialises as `audit-v1`).
    #[serde(default = "default_hash_recipe")]
    pub hash_recipe: String,

    // ---- v2 fields added 2026-04-25 (PR-A1) -----------------------------
    /// Per-request UUID. Used as the receipt identifier; clients receive
    /// it in the `x-gateway-receipt` response header and look up the full
    /// receipt at `/v1/receipts/{request_id}`. Codex F11.
    #[serde(default)]
    pub request_id: String,

    /// Model name the client originally requested in their JSON body.
    /// Disambiguates from the upstream-routed model under smart routing.
    #[serde(default)]
    pub client_requested_model: String,

    /// Smart-router decision: which configured route was selected
    /// (e.g. "anthropic-direct", "anonymized-cheap"). Empty if no
    /// routing config is in effect.
    #[serde(default)]
    pub gateway_selected_route: String,

    /// Model name actually sent to the upstream after routing. Equals
    /// client_requested_model when smart routing is off.
    #[serde(default)]
    pub upstream_requested_model: String,

    /// Model name the upstream returned in its response body.
    /// Sometimes diverges from upstream_requested_model when the
    /// upstream silently routes between model versions.
    #[serde(default)]
    pub upstream_reported_model: String,

    /// Fast-tier detector model name (e.g. "gemma4:e4b").
    #[serde(default)]
    pub detector_fast_model: String,

    /// Deep-tier detector model name when configured (e.g. "gemma4:26b").
    #[serde(default)]
    pub detector_deep_model: String,

    /// HMAC-SHA256 of the post-redaction (placeholder-bearing) prompt.
    /// Hex-encoded. Empty when no PII was detected and the prompt was
    /// forwarded verbatim. Codex F12: keyed digest defeats confirmation
    /// attacks against bare hashes.
    #[serde(default)]
    pub prompt_hmac: String,

    /// HMAC-SHA256 of the pre-deanon (placeholder-bearing) upstream
    /// response. For streaming responses this is the rolling HMAC
    /// finalised at stream end; `response_hash_status` indicates which.
    #[serde(default)]
    pub response_hmac: String,

    /// Stable identifier for the HMAC key used. Verifiers fetch the key
    /// from a trust store keyed by this id. Rotation: deploy a new key
    /// with a new id; old receipts continue to validate against the
    /// archived key by id.
    #[serde(default)]
    pub hmac_key_id: String,

    /// Whether `response_hmac` is the final value or still being
    /// rolled. See `ResponseHashStatus` doc.
    #[serde(default)]
    pub response_hash_status: ResponseHashStatus,

    /// Identifier of the Ed25519 key that signs this entry's batch
    /// when it gets anchored to Rekor. Rotation safety: archive old
    /// public keys forever.
    #[serde(default)]
    pub signing_key_id: String,

    /// Signature algorithm name (e.g. "ed25519"). Forward-compat for
    /// future post-quantum signatures.
    #[serde(default)]
    pub signature_alg: String,

    /// Anchoring status as of receipt emission. Anchoring is async; a
    /// fresh receipt almost always says `not_yet_anchored`. Subsequent
    /// receipt lookups return updated status as the publisher catches up.
    #[serde(default)]
    pub anchor_status: AnchorStatus,

    /// Rekor entry UUID once the batch containing this entry has been
    /// anchored. Empty until then.
    #[serde(default)]
    pub rekor_uuid: String,

    /// Rekor log index. -1 sentinel until anchored.
    #[serde(default = "default_log_index")]
    pub log_index: i64,

    /// Rekor integrated_time (unix seconds) when the batch was accepted.
    /// 0 until anchored.
    #[serde(default)]
    pub integrated_time: u64,
}

pub(crate) fn default_log_index() -> i64 {
    -1
}

impl Default for AuditEntry {
    fn default() -> Self {
        Self {
            timestamp: DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(Utc::now),
            session_id: String::new(),
            pii_spans_detected: 0,
            pii_types: Vec::new(),
            placeholders_generated: 0,
            privacy_score: 100,
            hash: String::new(),
            prev_hash: "0".repeat(64),
            hash_recipe: HASH_RECIPE_V2_CANONICAL_JSON.to_string(),
            request_id: String::new(),
            client_requested_model: String::new(),
            gateway_selected_route: String::new(),
            upstream_requested_model: String::new(),
            upstream_reported_model: String::new(),
            detector_fast_model: String::new(),
            detector_deep_model: String::new(),
            prompt_hmac: String::new(),
            response_hmac: String::new(),
            hmac_key_id: String::new(),
            response_hash_status: ResponseHashStatus::Final,
            signing_key_id: String::new(),
            signature_alg: String::new(),
            anchor_status: AnchorStatus::NotYetAnchored,
            rekor_uuid: String::new(),
            log_index: -1,
            integrated_time: 0,
        }
    }
}

pub(crate) fn default_hash_recipe() -> String {
    "audit-v1".to_string()
}

/// Stable identifier for the canonical-JSON hash recipe shipped 2026-04-25.
pub const HASH_RECIPE_V2_CANONICAL_JSON: &str = "audit-v2-canonical-json";

/// Stable identifier for the legacy 5-field SHA-256 recipe.
pub const HASH_RECIPE_V1: &str = "audit-v1";

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
            other => Err(format!(
                "invalid scan mode: {other}. expected: fast, deep, auto"
            )),
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
