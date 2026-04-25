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
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use serde::Deserialize;

use gateway_common::canary_baseline::{Baseline, ProbeFingerprint};

/// Same normalisation as the runtime probe (`gateway_proxy::canary::features::output_hash`).
/// Lifted into the CLI so it doesn't depend on the proxy crate.
fn output_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let normalised = content.trim().to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(normalised.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn log2_bucket(value: u64) -> u32 {
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
    /// Label to embed in the baseline. MUST be the upstream model id
    /// (e.g. "claude-sonnet-4-20250514") because the runtime probe
    /// loop sends this exact string in the `model` field of every
    /// `/v1/messages` call. The label doubles as a human-readable
    /// audit marker.
    #[arg(long)]
    pub model_label: String,
    /// If set, do not contact the upstream — produce a baseline with
    /// stub fingerprints. Useful for tests and CI smoke checks.
    #[arg(long)]
    pub stub: bool,
    /// Upstream URL. Defaults to `GATEWAY_UPSTREAM` env var, then
    /// `https://api.anthropic.com`.
    #[arg(long, env = "GATEWAY_UPSTREAM", default_value = "https://api.anthropic.com")]
    pub upstream: String,
    /// Anthropic API key. Defaults to `ANTHROPIC_API_KEY` env var. Not
    /// required for `--stub` mode.
    #[arg(long, env = "ANTHROPIC_API_KEY")]
    pub api_key: Option<String>,
    /// Per-prompt request timeout. Default 60s — generous so the
    /// bootstrap doesn't false-fail on a cold upstream.
    #[arg(long, default_value = "60")]
    pub timeout_secs: u64,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    #[arg(long, default_value = "eval/canary_baseline.json")]
    pub path: PathBuf,
}

pub async fn run(args: CanaryArgs) -> Result<(), CanaryError> {
    match args.command {
        CanaryCommand::Bootstrap(args) => bootstrap(args).await,
        CanaryCommand::Show(args) => show(args),
    }
}

async fn bootstrap(args: BootstrapArgs) -> Result<(), CanaryError> {
    let mut baseline = Baseline::empty(&args.model_label);

    if args.stub {
        // Synthetic fingerprints — useful for unit tests without an
        // upstream. Real operators always pass an actual upstream.
        for prompt in PROMPT_BANK {
            baseline.prompts.insert(
                prompt.to_string(),
                ProbeFingerprint {
                    output_hash: output_hash("stubbed response"),
                    length_bucket: log2_bucket(2),
                    stop_reason: "end_turn".to_string(),
                    latency_bucket: log2_bucket(500),
                },
            );
        }
    } else {
        // Live bootstrap (PR-B.1): hit the configured upstream once per
        // prompt. Operator MUST review the resulting fingerprints before
        // committing the baseline (Codex F16 — a man-in-the-middle present
        // at bootstrap silently poisons every future probe).
        let api_key = args
            .api_key
            .clone()
            .filter(|k| !k.is_empty())
            .ok_or(CanaryError::MissingApiKey)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout_secs))
            .build()
            .map_err(|e| CanaryError::HttpClient(e.to_string()))?;
        let upstream = args.upstream.trim_end_matches('/').to_string();

        for prompt in PROMPT_BANK {
            let fp = capture_fingerprint(
                &client,
                &upstream,
                &api_key,
                &args.model_label,
                prompt,
            )
            .await
            .map_err(|e| CanaryError::Probe(prompt.to_string(), e.to_string()))?;
            baseline.prompts.insert(prompt.to_string(), fp);
        }
    }

    let json = serde_json::to_string_pretty(&baseline).map_err(|e| CanaryError::Serialize(e.to_string()))?;
    fs::write(&args.output, json).map_err(|e| CanaryError::Write(args.output.clone(), e.to_string()))?;

    println!("Baseline written to {}", args.output.display());
    println!("Model label: {}", baseline.model_label);
    println!("Prompts captured: {}", baseline.prompts.len());
    if !args.stub {
        println!();
        println!("REVIEW BEFORE COMMITTING (Codex F16):");
        println!("  - Confirm the model label matches the upstream you intended.");
        println!("  - Spot-check a few fingerprints with `gateway canary show`.");
        println!("  - Only commit baselines captured against a known-good upstream.");
    }
    Ok(())
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
    stop_reason: String,
    usage: AnthropicUsage,
}

#[derive(Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicUsage {
    output_tokens: u64,
}

/// Send one prompt at the upstream and return the captured fingerprint.
/// Same shape as the runtime probe in `gateway_proxy::canary::probe`,
/// duplicated here so the CLI doesn't depend on the proxy crate.
async fn capture_fingerprint(
    client: &reqwest::Client,
    upstream_url: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<ProbeFingerprint, String> {
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 64,
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}]
    });
    let url = format!("{upstream_url}/v1/messages");

    let start = Instant::now();
    let resp = client
        .post(&url)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("upstream HTTP {status}: {body_text}"));
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let parsed: AnthropicResponse = resp
        .json()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

    let text = parsed
        .content
        .iter()
        .filter(|c| c.block_type == "text")
        .filter_map(|c| c.text.as_deref())
        .next()
        .unwrap_or("")
        .to_string();

    Ok(ProbeFingerprint {
        output_hash: output_hash(&text),
        length_bucket: log2_bucket(parsed.usage.output_tokens),
        stop_reason: parsed.stop_reason,
        latency_bucket: log2_bucket(elapsed_ms),
    })
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
        "missing Anthropic API key — set ANTHROPIC_API_KEY or pass --api-key. \
         For an offline placeholder use `--stub`."
    )]
    MissingApiKey,
    #[error("failed to build HTTP client: {0}")]
    HttpClient(String),
    #[error("probe for prompt {0:?} failed: {1}")]
    Probe(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn stub_args(out: PathBuf, label: &str) -> BootstrapArgs {
        BootstrapArgs {
            output: out,
            model_label: label.to_string(),
            stub: true,
            upstream: "https://example.invalid".to_string(),
            api_key: None,
            timeout_secs: 60,
        }
    }

    fn live_args(out: PathBuf, label: &str, upstream: String, api_key: Option<String>) -> BootstrapArgs {
        BootstrapArgs {
            output: out,
            model_label: label.to_string(),
            stub: false,
            upstream,
            api_key,
            timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn stub_bootstrap_writes_baseline_with_prompt_bank() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        run(CanaryArgs {
            command: CanaryCommand::Bootstrap(stub_args(out.clone(), "claude-sonnet-4-test")),
        })
        .await
        .unwrap();

        assert!(out.exists());
        let raw = fs::read_to_string(&out).unwrap();
        let baseline: Baseline = serde_json::from_str(&raw).unwrap();
        assert_eq!(baseline.model_label, "claude-sonnet-4-test");
        assert_eq!(baseline.prompts.len(), PROMPT_BANK.len());
    }

    #[tokio::test]
    async fn live_bootstrap_without_api_key_errors() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        let err = run(CanaryArgs {
            command: CanaryCommand::Bootstrap(live_args(
                out,
                "claude",
                "http://127.0.0.1:1".to_string(),
                None,
            )),
        })
        .await
        .unwrap_err();
        assert!(matches!(err, CanaryError::MissingApiKey));
    }

    #[tokio::test]
    async fn live_bootstrap_with_mock_upstream_writes_baseline() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            })))
            .mount(&server)
            .await;

        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        run(CanaryArgs {
            command: CanaryCommand::Bootstrap(live_args(
                out.clone(),
                "claude-mock",
                server.uri(),
                Some("test-key".to_string()),
            )),
        })
        .await
        .expect("live bootstrap with mock upstream succeeds");

        let raw = fs::read_to_string(&out).unwrap();
        let baseline: Baseline = serde_json::from_str(&raw).unwrap();
        assert_eq!(baseline.model_label, "claude-mock");
        assert_eq!(baseline.prompts.len(), PROMPT_BANK.len());
        for prompt in PROMPT_BANK {
            let fp = baseline.prompts.get(*prompt).expect("prompt captured");
            assert_eq!(fp.stop_reason, "end_turn");
            assert_eq!(fp.output_hash, output_hash("ok"));
        }
    }

    #[tokio::test]
    async fn live_bootstrap_propagates_http_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        let err = run(CanaryArgs {
            command: CanaryCommand::Bootstrap(live_args(
                out,
                "claude-mock",
                server.uri(),
                Some("test-key".to_string()),
            )),
        })
        .await
        .unwrap_err();
        assert!(matches!(err, CanaryError::Probe(_, _)));
    }

    #[tokio::test]
    async fn show_prints_baseline() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("baseline.json");
        run(CanaryArgs {
            command: CanaryCommand::Bootstrap(stub_args(out.clone(), "test-model")),
        })
        .await
        .unwrap();

        run(CanaryArgs {
            command: CanaryCommand::Show(ShowArgs { path: out }),
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn show_returns_read_error_for_missing_file() {
        let err = run(CanaryArgs {
            command: CanaryCommand::Show(ShowArgs {
                path: PathBuf::from("/nonexistent/baseline.json"),
            }),
        })
        .await
        .unwrap_err();
        assert!(matches!(err, CanaryError::Read(_, _)));
    }
}
