//! `gateway canary` — bootstrap a fingerprint baseline against the
//! configured upstream. Codex F16: never bootstrap from live unverified
//! observations; the operator runs this against a known-good upstream
//! and reviews the output before checking it into `eval/`.
//!
//! This subcommand is intentionally minimal: it sends a fixed prompt
//! suite at the upstream, captures the response fingerprints, writes
//! the baseline to disk, and prints a summary. Operators are expected
//! to inspect the output (`jq` it, eyeball the model_label and a few
//! prompts) before committing it to source.

use std::fs;
use std::path::PathBuf;

use clap::{Args, Subcommand};

use gateway_common::canary_baseline::{Baseline, ProbeFingerprint};

// Stub bootstrap uses simple deterministic hashes; no need to depend
// on the full proxy crate for `output_hash` / `log2_bucket`. Real
// runtime probes (PR-B.1) recompute via the proxy's feature module.
fn stub_output_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn stub_log2_bucket(value: u64) -> u32 {
    let v = value.max(1);
    63 - v.leading_zeros()
}

/// Fixed canary prompt bank. Deterministic, varied, short. Each prompt
/// is selected for stable temperature=0 output across Sonnet variants.
/// Codex F19 says "rotate and jitter" — for the bootstrap we just
/// capture all of them; the runtime probe selects with daily-seeded
/// jitter (P2 task — runtime probe lands in PR-B.1).
const PROMPT_BANK: &[&str] = &[
    "Reply with exactly one word: ready.",
    "What is 2 plus 2? Reply with just the number.",
    "Translate to Spanish: Hello.",
    "Complete this sentence: The quick brown fox jumps over the",
    "Name one primary color.",
];

#[derive(Args, Debug)]
pub struct CanaryArgs {
    #[command(subcommand)]
    pub command: CanaryCommand,
}

#[derive(Subcommand, Debug)]
pub enum CanaryCommand {
    /// Capture an upstream fingerprint baseline. Writes to
    /// `--output` (default `eval/canary_baseline.json`).
    Bootstrap(BootstrapArgs),
    /// Pretty-print the loaded baseline. Useful for sanity-checking a
    /// freshly-generated file.
    Show(ShowArgs),
}

#[derive(Args, Debug)]
pub struct BootstrapArgs {
    /// Output baseline path.
    #[arg(long, default_value = "eval/canary_baseline.json")]
    pub output: PathBuf,
    /// Label to embed in the baseline (e.g. "claude-sonnet-4-20250514").
    /// Recorded only for human auditability — not used in scoring.
    #[arg(long)]
    pub model_label: String,
    /// If set, do not contact the upstream — produce a baseline with
    /// stub fingerprints. Useful for tests and CI smoke checks.
    #[arg(long)]
    pub stub: bool,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    #[arg(long, default_value = "eval/canary_baseline.json")]
    pub path: PathBuf,
}

pub fn run(args: CanaryArgs) -> Result<(), CanaryError> {
    match args.command {
        CanaryCommand::Bootstrap(args) => bootstrap(args),
        CanaryCommand::Show(args) => show(args),
    }
}

fn bootstrap(args: BootstrapArgs) -> Result<(), CanaryError> {
    let mut baseline = Baseline::empty(&args.model_label);

    if args.stub {
        // Synthetic fingerprints — useful for unit tests without an
        // upstream. Real operators always pass an actual upstream.
        for prompt in PROMPT_BANK {
            baseline.prompts.insert(
                prompt.to_string(),
                ProbeFingerprint {
                    output_hash: stub_output_hash("stubbed response"),
                    length_bucket: stub_log2_bucket(2),
                    stop_reason: "end_turn".to_string(),
                    latency_bucket: stub_log2_bucket(500),
                },
            );
        }
    } else {
        // Real bootstrap requires an HTTP client + the upstream URL +
        // an API key. PR-B ships the framework; the live-probe payload
        // (and its blast radius — sending real requests) lands in
        // PR-B.1 once the Anthropic-key plumbing is reviewed.
        return Err(CanaryError::LiveBootstrapNotImplemented);
    }

    let json = serde_json::to_string_pretty(&baseline).map_err(|e| CanaryError::Serialize(e.to_string()))?;
    fs::write(&args.output, json).map_err(|e| CanaryError::Write(args.output.clone(), e.to_string()))?;

    println!("Baseline written to {}", args.output.display());
    println!("Model label: {}", baseline.model_label);
    println!("Prompts captured: {}", baseline.prompts.len());
    Ok(())
}

fn show(args: ShowArgs) -> Result<(), CanaryError> {
    let raw = fs::read_to_string(&args.path)
        .map_err(|e| CanaryError::Read(args.path.clone(), e.to_string()))?;
    let baseline: Baseline =
        serde_json::from_str(&raw).map_err(|e| CanaryError::Parse(e.to_string()))?;

    println!("Baseline: {}", args.path.display());
    println!("Model label:    {}", baseline.model_label);
    println!("Created at:     {}", baseline.created_at);
    println!("Gateway version: {}", baseline.gateway_version);
    println!("Prompts:        {}", baseline.prompts.len());
    for (prompt, fp) in &baseline.prompts {
        let prompt_excerpt = if prompt.len() > 60 {
            format!("{}…", &prompt[..60])
        } else {
            prompt.clone()
        };
        println!(
            "  - [{:>2} tokens, {} stop, {}ms bucket] {}",
            fp.length_bucket, fp.stop_reason, fp.latency_bucket, prompt_excerpt
        );
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    #[error("failed to read {0}: {1}")]
    Read(PathBuf, String),
    #[error("failed to write {0}: {1}")]
    Write(PathBuf, String),
    #[error("failed to parse baseline JSON: {0}")]
    Parse(String),
    #[error("failed to serialise baseline: {0}")]
    Serialize(String),
    #[error(
        "live bootstrap not yet implemented in PR-B. \
         Run `gateway canary bootstrap --model-label <label> --stub` to write a placeholder. \
         Real upstream bootstrap lands in PR-B.1 alongside the runtime probe payload."
    )]
    LiveBootstrapNotImplemented,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn stub_bootstrap_writes_baseline_with_prompt_bank() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        run(CanaryArgs {
            command: CanaryCommand::Bootstrap(BootstrapArgs {
                output: out.clone(),
                model_label: "claude-sonnet-4-test".to_string(),
                stub: true,
            }),
        })
        .unwrap();

        assert!(out.exists());
        let raw = fs::read_to_string(&out).unwrap();
        let baseline: Baseline = serde_json::from_str(&raw).unwrap();
        assert_eq!(baseline.model_label, "claude-sonnet-4-test");
        assert_eq!(baseline.prompts.len(), PROMPT_BANK.len());
    }

    #[test]
    fn live_bootstrap_returns_clear_error() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        let err = run(CanaryArgs {
            command: CanaryCommand::Bootstrap(BootstrapArgs {
                output: out,
                model_label: "claude".to_string(),
                stub: false,
            }),
        })
        .unwrap_err();
        assert!(matches!(err, CanaryError::LiveBootstrapNotImplemented));
    }

    #[test]
    fn show_prints_baseline() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        run(CanaryArgs {
            command: CanaryCommand::Bootstrap(BootstrapArgs {
                output: out.clone(),
                model_label: "test-model".to_string(),
                stub: true,
            }),
        })
        .unwrap();

        run(CanaryArgs {
            command: CanaryCommand::Show(ShowArgs { path: out }),
        })
        .unwrap();
    }

    #[test]
    fn show_returns_read_error_for_missing_file() {
        let err = run(CanaryArgs {
            command: CanaryCommand::Show(ShowArgs {
                path: PathBuf::from("/nonexistent/baseline.json"),
            }),
        })
        .unwrap_err();
        assert!(matches!(err, CanaryError::Read(_, _)));
    }
}
