//! On-disk baseline format for the canary fingerprint.
//!
//! Lives in `gateway-common` rather than `gateway-proxy::canary` because
//! both the proxy (which loads it at boot) and the CLI (which writes it
//! during `gateway canary bootstrap`) need to (de)serialise it. The
//! runtime state that consumes it lives next to the proxy in
//! `gateway-proxy::canary::state`.
//!
//! The baseline is checked into the repo at `eval/canary_baseline.json`
//! so a fresh deployment has something to compare against from the very
//! first probe. Operators bootstrap a fresh baseline from their own
//! upstream via `gateway canary bootstrap`. Codex F16: live-bootstrap
//! is rejected because a man-in-the-middle present at bootstrap would
//! poison the fingerprint silently.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Per-prompt expected fingerprint. Each probe captures the same four
/// signals; the live probe's fingerprint is then compared against this
/// baseline to score similarity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeFingerprint {
    /// Deterministic SHA-256 of the response content under
    /// `lowercase(trim(content))`. Stable for temperature=0 prompts.
    pub output_hash: String,
    /// Log2 bucket of response token count
    /// (`floor(log2(max(1, count)))`). Tolerates +/-50% noise; flags
    /// dramatic shifts.
    pub length_bucket: u32,
    /// `stop_reason` / `finish_reason` field from the upstream response.
    /// Anthropic uses values like "end_turn", "max_tokens", "stop_sequence";
    /// OpenAI uses "stop", "length", "tool_calls".
    pub stop_reason: String,
    /// Log2 bucket of wall-clock latency in ms
    /// (`floor(log2(max(1, ms)))`). Tolerates the natural variance of
    /// network + inference; catches order-of-magnitude shifts.
    pub latency_bucket: u32,
}

/// Top-level baseline file. Maps prompt strings to expected fingerprints.
/// `model_label` documents which upstream model+version this baseline
/// was captured against; `created_at` and `gateway_version` are for
/// auditability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub model_label: String,
    pub created_at: String,
    pub gateway_version: String,
    /// Map prompt -> expected fingerprint. BTreeMap for deterministic
    /// ordering when serialised back to disk.
    pub prompts: BTreeMap<String, ProbeFingerprint>,
}

impl Baseline {
    /// Construct an empty baseline (used by the bootstrap CLI and tests).
    pub fn empty(model_label: impl Into<String>) -> Self {
        Self {
            model_label: model_label.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            gateway_version: env!("CARGO_PKG_VERSION").to_string(),
            prompts: BTreeMap::new(),
        }
    }

    /// Return the prompt set in stable order. Useful for the probe loop
    /// to iterate without re-sorting on every call.
    pub fn prompt_keys(&self) -> Vec<String> {
        self.prompts.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_baseline_round_trips() {
        let baseline = Baseline::empty("test-model");
        let json = serde_json::to_string(&baseline).unwrap();
        let parsed: Baseline = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.model_label, "test-model");
        assert!(parsed.prompts.is_empty());
    }

    #[test]
    fn baseline_with_fingerprint_round_trips() {
        let mut baseline = Baseline::empty("claude-sonnet-4");
        baseline.prompts.insert(
            "What is 2+2?".to_string(),
            ProbeFingerprint {
                output_hash: "abc123".to_string(),
                length_bucket: 3,
                stop_reason: "end_turn".to_string(),
                latency_bucket: 9,
            },
        );
        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let parsed: Baseline = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prompts.len(), 1);
        let fp = parsed.prompts.get("What is 2+2?").unwrap();
        assert_eq!(fp.output_hash, "abc123");
        assert_eq!(fp.length_bucket, 3);
        assert_eq!(fp.stop_reason, "end_turn");
    }

    #[test]
    fn prompt_keys_returns_sorted_order() {
        let mut baseline = Baseline::empty("m");
        for k in ["zeta", "alpha", "mu"] {
            baseline.prompts.insert(
                k.to_string(),
                ProbeFingerprint {
                    output_hash: String::new(),
                    length_bucket: 0,
                    stop_reason: String::new(),
                    latency_bucket: 0,
                },
            );
        }
        assert_eq!(baseline.prompt_keys(), vec!["alpha", "mu", "zeta"]);
    }
}
