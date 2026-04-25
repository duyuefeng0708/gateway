//! Per-feature scoring for the canary fingerprint comparison.
//!
//! Each feature compares one signal of the live probe against the
//! baseline and returns a score in `[0.0, 1.0]`, where 1.0 is "matches
//! baseline exactly" and 0.0 is "completely different." The composite
//! confidence is the arithmetic mean of all four. A drift in any single
//! feature pulls the composite down; coordinated drift across all four
//! is the strongest signal of an upstream model swap.

use sha2::{Digest, Sha256};

use gateway_common::canary_baseline::ProbeFingerprint;

/// SHA-256 of `lowercase(trim(content))`. Hex-encoded.
///
/// Used as the `output_hash` field on each probe. Deterministic for
/// temperature=0 prompts, so any change in the upstream's tokens flips
/// this completely. Trimming + lowercasing absorbs the small
/// whitespace/casing differences that don't matter operationally.
pub fn output_hash(content: &str) -> String {
    let normalised = content.trim().to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(normalised.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// `floor(log2(max(1, value)))`. Used for both length and latency
/// bucketing. Bucket boundaries: 0 → bucket 0, 1 → 0, 2-3 → 1, 4-7 → 2,
/// 8-15 → 3, ...
pub fn log2_bucket(value: u64) -> u32 {
    let v = value.max(1);
    63 - v.leading_zeros()
}

/// Score `output_hash` similarity. Exact match = 1.0; mismatch = 0.0.
/// The prompts in the bank are deterministic (temperature=0), so any
/// non-trivial drift is immediately visible.
pub fn score_output(observed_hash: &str, baseline: &ProbeFingerprint) -> f64 {
    if observed_hash == baseline.output_hash {
        1.0
    } else {
        0.0
    }
}

/// Score length bucket adjacency. Same bucket = 1.0; one off = 0.5;
/// two or more off = 0.0. Tolerates the natural variance of inference
/// (which can produce slightly more or fewer tokens within the same
/// bucket boundary) without becoming insensitive to dramatic shifts.
pub fn score_length(observed_bucket: u32, baseline: &ProbeFingerprint) -> f64 {
    let delta = observed_bucket.abs_diff(baseline.length_bucket);
    match delta {
        0 => 1.0,
        1 => 0.5,
        _ => 0.0,
    }
}

/// Score stop-reason match. Exact = 1.0; otherwise 0.0. Anthropic uses
/// `end_turn` / `max_tokens` / `stop_sequence`; OpenAI uses
/// `stop` / `length` / `tool_calls`. A swap from one provider to the
/// other flips this signal completely.
pub fn score_stop_reason(observed: &str, baseline: &ProbeFingerprint) -> f64 {
    if observed == baseline.stop_reason {
        1.0
    } else {
        0.0
    }
}

/// Score latency bucket adjacency. Same bucket = 1.0; one off = 0.7
/// (latency varies more than length); two off = 0.3; further = 0.0.
/// Detects order-of-magnitude shifts that suggest a model swap (a
/// 4B model vs a 27B model has very different latency characteristics).
pub fn score_latency(observed_bucket: u32, baseline: &ProbeFingerprint) -> f64 {
    let delta = observed_bucket.abs_diff(baseline.latency_bucket);
    match delta {
        0 => 1.0,
        1 => 0.7,
        2 => 0.3,
        _ => 0.0,
    }
}

/// Composite confidence: arithmetic mean of all four feature scores.
/// Returns NaN-free f64 in `[0.0, 1.0]`.
pub fn composite(observed: &ProbeFingerprint, baseline: &ProbeFingerprint) -> f64 {
    let s_output = score_output(&observed.output_hash, baseline);
    let s_length = score_length(observed.length_bucket, baseline);
    let s_stop = score_stop_reason(&observed.stop_reason, baseline);
    let s_latency = score_latency(observed.latency_bucket, baseline);
    (s_output + s_length + s_stop + s_latency) / 4.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_fp() -> ProbeFingerprint {
        ProbeFingerprint {
            output_hash: output_hash("Paris is the capital of France."),
            length_bucket: 5,
            stop_reason: "end_turn".to_string(),
            latency_bucket: 9,
        }
    }

    #[test]
    fn output_hash_is_deterministic_and_normalised() {
        assert_eq!(
            output_hash("  Hello World  "),
            output_hash("hello world"),
        );
    }

    #[test]
    fn output_hash_differs_for_different_content() {
        assert_ne!(output_hash("yes"), output_hash("no"));
    }

    #[test]
    fn log2_bucket_matches_doc() {
        assert_eq!(log2_bucket(0), 0);
        assert_eq!(log2_bucket(1), 0);
        assert_eq!(log2_bucket(2), 1);
        assert_eq!(log2_bucket(3), 1);
        assert_eq!(log2_bucket(4), 2);
        assert_eq!(log2_bucket(7), 2);
        assert_eq!(log2_bucket(8), 3);
        assert_eq!(log2_bucket(1024), 10);
    }

    #[test]
    fn perfect_match_scores_one() {
        let baseline = baseline_fp();
        let observed = baseline.clone();
        assert_eq!(composite(&observed, &baseline), 1.0);
    }

    #[test]
    fn output_hash_drift_drops_composite_to_seventy_five_percent() {
        let baseline = baseline_fp();
        let mut observed = baseline.clone();
        observed.output_hash = output_hash("different content");
        // 0 + 1 + 1 + 1 / 4 = 0.75
        assert!((composite(&observed, &baseline) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn length_bucket_one_off_scores_partial() {
        let baseline = baseline_fp();
        let mut observed = baseline.clone();
        observed.length_bucket = 4; // baseline is 5
        // 1 + 0.5 + 1 + 1 / 4 = 0.875
        assert!((composite(&observed, &baseline) - 0.875).abs() < 1e-9);
    }

    #[test]
    fn length_bucket_far_off_scores_zero() {
        let baseline = baseline_fp();
        let mut observed = baseline.clone();
        observed.length_bucket = 20; // baseline is 5
        // 1 + 0 + 1 + 1 / 4 = 0.75
        assert!((composite(&observed, &baseline) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn stop_reason_swap_drops_score() {
        let baseline = baseline_fp();
        let mut observed = baseline.clone();
        observed.stop_reason = "stop".to_string(); // OpenAI-style vs Anthropic
        assert!((composite(&observed, &baseline) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn coordinated_drift_collapses_score() {
        let baseline = baseline_fp();
        let observed = ProbeFingerprint {
            output_hash: output_hash("totally different"),
            length_bucket: 20,
            stop_reason: "stop".to_string(),
            latency_bucket: 3,
        };
        // 0 + 0 + 0 + 0 / 4 = 0.0
        assert_eq!(composite(&observed, &baseline), 0.0);
    }

    #[test]
    fn latency_bucket_one_off_scores_partial() {
        let baseline = baseline_fp();
        let mut observed = baseline.clone();
        observed.latency_bucket = 10;
        // latency=1-off → 0.7. Composite: 1 + 1 + 1 + 0.7 / 4 = 0.925
        assert!((composite(&observed, &baseline) - 0.925).abs() < 1e-9);
    }
}
