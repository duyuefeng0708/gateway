//! PII detection evaluation harness.
//!
//! Loads a JSONL benchmark, runs each prompt through a `PiiDetector`,
//! and computes entity-level precision, recall, and F1.

use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, PiiType};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::detector::PiiDetector;

// ---------------------------------------------------------------------------
// Benchmark schema
// ---------------------------------------------------------------------------

/// A single benchmark entry loaded from JSONL.
#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkEntry {
    pub prompt: String,
    pub spans: Vec<LabeledSpan>,
}

/// A labeled span in the benchmark. Mirrors PiiSpan but uses a string type
/// field matching the SCREAMING_SNAKE_CASE names from PiiType serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledSpan {
    #[serde(rename = "type")]
    pub pii_type: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f64,
    #[serde(default)]
    pub implicit: bool,
}

impl LabeledSpan {
    /// Convert the string type to our enum. Returns None for unknown types.
    pub fn to_pii_type(&self) -> Option<PiiType> {
        match self.pii_type.as_str() {
            "PERSON" => Some(PiiType::Person),
            "ORGANIZATION" => Some(PiiType::Organization),
            "LOCATION" => Some(PiiType::Location),
            "EMAIL" => Some(PiiType::Email),
            "PHONE" => Some(PiiType::Phone),
            "SSN" => Some(PiiType::Ssn),
            "CREDENTIAL" => Some(PiiType::Credential),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Precision / recall / F1 triple.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Metrics {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

impl Metrics {
    pub fn compute(tp: usize, fp: usize, fn_: usize) -> Self {
        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            1.0 // no predictions => vacuously precise
        };
        let recall = if tp + fn_ > 0 {
            tp as f64 / (tp + fn_) as f64
        } else {
            1.0 // no ground truth => vacuously recalled
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        Self {
            precision,
            recall,
            f1,
        }
    }
}

/// Per-entry result stored in the report.
#[derive(Debug, Clone, Serialize)]
pub struct EntryResult {
    pub prompt_excerpt: String,
    pub expected_count: usize,
    pub detected_count: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
}

/// Full evaluation report.
#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    pub detector_name: String,
    pub total_entries: usize,
    pub overall: Metrics,
    pub explicit_metrics: Metrics,
    pub implicit_metrics: Metrics,
    pub entries: Vec<EntryResult>,
}

// ---------------------------------------------------------------------------
// Matching logic
// ---------------------------------------------------------------------------

/// Two spans match if they have the same PII type and their byte ranges
/// overlap (partial overlap counts).
fn spans_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

fn pii_type_from_str(s: &str) -> Option<PiiType> {
    match s {
        "PERSON" => Some(PiiType::Person),
        "ORGANIZATION" => Some(PiiType::Organization),
        "LOCATION" => Some(PiiType::Location),
        "EMAIL" => Some(PiiType::Email),
        "PHONE" => Some(PiiType::Phone),
        "SSN" => Some(PiiType::Ssn),
        "CREDENTIAL" => Some(PiiType::Credential),
        _ => None,
    }
}

/// Given ground-truth and detected spans, compute (TP, FP, FN) counts.
///
/// A detected span is a TP if it overlaps a ground-truth span with the same
/// PiiType.  Each ground-truth span can match at most one detected span (and
/// vice-versa).
fn count_matches(
    expected: &[LabeledSpan],
    detected: &[PiiSpan],
) -> (usize, usize, usize) {
    let mut matched_expected = vec![false; expected.len()];
    let mut matched_detected = vec![false; detected.len()];

    // Greedy matching: iterate detected spans and find first unmatched
    // expected span that overlaps with same type.
    for (di, det) in detected.iter().enumerate() {
        for (ei, exp) in expected.iter().enumerate() {
            if matched_expected[ei] {
                continue;
            }
            let exp_type = match pii_type_from_str(&exp.pii_type) {
                Some(t) => t,
                None => continue,
            };
            if exp_type == det.pii_type
                && spans_overlap(exp.start, exp.end, det.start, det.end)
            {
                matched_expected[ei] = true;
                matched_detected[di] = true;
                break;
            }
        }
    }

    let tp = matched_detected.iter().filter(|&&m| m).count();
    let fp = matched_detected.iter().filter(|&&m| !m).count();
    let fn_ = matched_expected.iter().filter(|&&m| !m).count();
    (tp, fp, fn_)
}

/// Split spans by implicit flag and compute separate match counts.
fn count_matches_by_implicit(
    expected: &[LabeledSpan],
    detected: &[PiiSpan],
    implicit: bool,
) -> (usize, usize, usize) {
    let exp_filtered: Vec<_> = expected.iter().filter(|s| s.implicit == implicit).cloned().collect();
    let det_filtered: Vec<_> = detected.iter().filter(|s| s.implicit == implicit).cloned().collect();
    count_matches(&exp_filtered, &det_filtered)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Load benchmark entries from a JSONL file.
pub fn load_benchmark(path: &Path) -> Result<Vec<BenchmarkEntry>, DetectionError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| DetectionError::Other(format!("failed to read benchmark file: {e}")))?;

    let mut entries = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: BenchmarkEntry = serde_json::from_str(line).map_err(|e| {
            DetectionError::Other(format!("benchmark line {}: {e}", i + 1))
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Run the evaluation harness: detect PII in every benchmark prompt,
/// compare against labeled spans, and produce a report.
pub async fn run_eval(
    detector: &dyn PiiDetector,
    entries: &[BenchmarkEntry],
) -> Result<EvalReport, DetectionError> {
    let mut total_tp = 0usize;
    let mut total_fp = 0usize;
    let mut total_fn = 0usize;

    let mut explicit_tp = 0usize;
    let mut explicit_fp = 0usize;
    let mut explicit_fn = 0usize;

    let mut implicit_tp = 0usize;
    let mut implicit_fp = 0usize;
    let mut implicit_fn = 0usize;

    let mut entry_results = Vec::with_capacity(entries.len());

    for entry in entries {
        let detected = detector.detect(&entry.prompt).await?;

        let (tp, fp, fn_) = count_matches(&entry.spans, &detected);
        total_tp += tp;
        total_fp += fp;
        total_fn += fn_;

        let (etp, efp, efn) = count_matches_by_implicit(&entry.spans, &detected, false);
        explicit_tp += etp;
        explicit_fp += efp;
        explicit_fn += efn;

        let (itp, ifp, ifn) = count_matches_by_implicit(&entry.spans, &detected, true);
        implicit_tp += itp;
        implicit_fp += ifp;
        implicit_fn += ifn;

        let excerpt = if entry.prompt.len() > 60 {
            format!("{}...", &entry.prompt[..57])
        } else {
            entry.prompt.clone()
        };

        entry_results.push(EntryResult {
            prompt_excerpt: excerpt,
            expected_count: entry.spans.len(),
            detected_count: detected.len(),
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_,
        });
    }

    let overall = Metrics::compute(total_tp, total_fp, total_fn);
    let explicit_metrics = Metrics::compute(explicit_tp, explicit_fp, explicit_fn);
    let implicit_metrics = Metrics::compute(implicit_tp, implicit_fp, implicit_fn);

    Ok(EvalReport {
        detector_name: detector.name().to_string(),
        total_entries: entries.len(),
        overall,
        explicit_metrics,
        implicit_metrics,
        entries: entry_results,
    })
}

/// Print a human-readable summary table to stdout.
pub fn print_report(report: &EvalReport) {
    println!("=== PII Eval Report: {} ===", report.detector_name);
    println!("Entries evaluated: {}", report.total_entries);
    println!();
    println!(
        "{:<20} {:>10} {:>10} {:>10}",
        "Category", "Precision", "Recall", "F1"
    );
    println!("{:-<54}", "");
    println!(
        "{:<20} {:>10.3} {:>10.3} {:>10.3}",
        "Overall", report.overall.precision, report.overall.recall, report.overall.f1
    );
    println!(
        "{:<20} {:>10.3} {:>10.3} {:>10.3}",
        "Explicit PII",
        report.explicit_metrics.precision,
        report.explicit_metrics.recall,
        report.explicit_metrics.f1
    );
    println!(
        "{:<20} {:>10.3} {:>10.3} {:>10.3}",
        "Implicit PII",
        report.implicit_metrics.precision,
        report.implicit_metrics.recall,
        report.implicit_metrics.f1
    );
    println!();
    println!("Per-entry breakdown:");
    for (i, e) in report.entries.iter().enumerate() {
        println!(
            "  [{}] {} | expected={} detected={} TP={} FP={} FN={}",
            i, e.prompt_excerpt, e.expected_count, e.detected_count,
            e.true_positives, e.false_positives, e.false_negatives
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_perfect_score() {
        let m = Metrics::compute(5, 0, 0);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.recall - 1.0).abs() < 1e-9);
        assert!((m.f1 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn metrics_no_predictions_no_truth() {
        let m = Metrics::compute(0, 0, 0);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.recall - 1.0).abs() < 1e-9);
    }

    #[test]
    fn metrics_half_recall() {
        // 1 TP, 0 FP, 1 FN => precision=1.0, recall=0.5
        let m = Metrics::compute(1, 0, 1);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.recall - 0.5).abs() < 1e-9);
    }

    #[test]
    fn metrics_half_precision() {
        // 1 TP, 1 FP, 0 FN => precision=0.5, recall=1.0
        let m = Metrics::compute(1, 1, 0);
        assert!((m.precision - 0.5).abs() < 1e-9);
        assert!((m.recall - 1.0).abs() < 1e-9);
    }

    #[test]
    fn overlap_detection() {
        assert!(spans_overlap(0, 10, 5, 15));
        assert!(spans_overlap(5, 15, 0, 10));
        assert!(!spans_overlap(0, 5, 5, 10)); // touching but not overlapping
        assert!(!spans_overlap(0, 5, 10, 15));
    }

    #[test]
    fn count_matches_basic() {
        let expected = vec![
            LabeledSpan {
                pii_type: "EMAIL".to_string(),
                start: 8,
                end: 25,
                text: "alice@example.com".to_string(),
                confidence: 1.0,
                implicit: false,
            },
        ];
        let detected = vec![
            PiiSpan {
                pii_type: PiiType::Email,
                start: 8,
                end: 25,
                text: "alice@example.com".to_string(),
                confidence: 1.0,
                implicit: false,
            },
        ];
        let (tp, fp, fn_) = count_matches(&expected, &detected);
        assert_eq!(tp, 1);
        assert_eq!(fp, 0);
        assert_eq!(fn_, 0);
    }

    #[test]
    fn count_matches_with_false_positive() {
        let expected = vec![];
        let detected = vec![
            PiiSpan {
                pii_type: PiiType::Phone,
                start: 0,
                end: 12,
                text: "555-123-4567".to_string(),
                confidence: 1.0,
                implicit: false,
            },
        ];
        let (tp, fp, fn_) = count_matches(&expected, &detected);
        assert_eq!(tp, 0);
        assert_eq!(fp, 1);
        assert_eq!(fn_, 0);
    }

    #[test]
    fn count_matches_with_false_negative() {
        let expected = vec![
            LabeledSpan {
                pii_type: "PERSON".to_string(),
                start: 0,
                end: 5,
                text: "Alice".to_string(),
                confidence: 1.0,
                implicit: false,
            },
        ];
        let detected = vec![];
        let (tp, fp, fn_) = count_matches(&expected, &detected);
        assert_eq!(tp, 0);
        assert_eq!(fp, 0);
        assert_eq!(fn_, 1);
    }

    #[test]
    fn load_benchmark_parses_jsonl() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("eval")
            .join("sample_benchmark.jsonl");
        if path.exists() {
            let entries = load_benchmark(&path).unwrap();
            assert!(!entries.is_empty());
        }
    }
}
