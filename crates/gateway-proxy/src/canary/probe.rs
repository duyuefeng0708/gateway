//! Runtime canary probe payload (PR-B.1).
//!
//! [`ProbeRunner`] sends a single baseline prompt at the configured
//! upstream every cycle, parses the response, computes a
//! [`ProbeFingerprint`], and feeds the composite score into
//! [`CanaryState::record_probe`].
//!
//! Codex F19 — prompt selection is daily-seeded so within-day probes
//! rotate through the same shuffled order (lets ops watch drift
//! accumulate against one fixture sequence) and across days the order
//! changes (so an adversary can't pre-bake responses to a fixed prompt).
//! Interval jitter is ±20% per cycle on top of `GATEWAY_CANARY_INTERVAL`.
//!
//! Failure handling is intentionally quiet: a network error, non-2xx
//! status, or malformed payload skips the cycle and logs a warning. The
//! rolling window only sees scores from successful probes; missing
//! probes show up as "probes_in_window" lagging behind wall-clock time.

use std::time::{Duration, Instant};

use chrono::{Datelike, NaiveDate, Utc};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::Deserialize;

use gateway_common::canary_baseline::ProbeFingerprint;

use crate::canary::features;
use crate::canary::state::CanaryState;

/// Convert an ISO-day index into a deterministic seed. We use
/// `num_days_from_ce()` (proleptic Gregorian, 0001-01-01 = 1) because it's
/// monotonic and stable across timezones — the seed only needs to roll
/// once per day, not match a specific epoch.
fn date_seed(date: NaiveDate) -> u64 {
    date.num_days_from_ce() as u64
}

/// Today's daily seed in UTC. Wrapper for tests that want to override.
pub fn daily_seed_now() -> u64 {
    date_seed(Utc::now().date_naive())
}

/// Pick the prompt for cycle `n` from a daily-shuffled order.
///
/// Same `(prompts, seed)` pair always produces the same shuffle, so
/// `cycle=0..N` walks through the day's prompts in a stable order.
/// `cycle` wraps via modulo, so cycles beyond the prompt count revisit
/// the same prompts.
pub fn pick_prompt(prompts: &[String], seed: u64, cycle: u64) -> Option<&str> {
    if prompts.is_empty() {
        return None;
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let mut indices: Vec<usize> = (0..prompts.len()).collect();
    indices.shuffle(&mut rng);
    let idx = indices[(cycle as usize) % indices.len()];
    Some(prompts[idx].as_str())
}

/// Apply ±20% jitter to a base interval. Empty intervals stay empty;
/// otherwise the result is in `[0.8, 1.2] × base`. Codex F19.
pub fn jittered_interval(base: Duration, rng: &mut StdRng) -> Duration {
    if base.is_zero() {
        return base;
    }
    let factor: f64 = rng.gen_range(0.8..=1.2);
    let nanos = (base.as_nanos() as f64 * factor).round() as u64;
    Duration::from_nanos(nanos)
}

/// Anthropic `/v1/messages` response shape, scoped to the fields the
/// canary cares about. Other fields (id, model, usage.input_tokens, ...)
/// are deserialised by serde's default-ignore.
#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
    stop_reason: String,
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    output_tokens: u64,
}

/// Built once at boot, cloned into the spawned probe loop. Holds the HTTP
/// client + key + handle to [`CanaryState`] so each cycle can record a
/// score without re-allocating.
#[derive(Clone)]
pub struct ProbeRunner {
    http_client: reqwest::Client,
    upstream_url: String,
    api_key: String,
    state: CanaryState,
}

impl ProbeRunner {
    pub fn new(
        http_client: reqwest::Client,
        upstream_url: String,
        api_key: String,
        state: CanaryState,
    ) -> Self {
        Self { http_client, upstream_url, api_key, state }
    }

    /// Run a single cycle. Picks today's prompt for slot `cycle`, sends
    /// it upstream, scores the response, records the score. Failures log
    /// and return without recording.
    pub async fn run_one_cycle(&self, cycle: u64) {
        let prompts = self.state.baseline().prompt_keys();
        let prompt = match pick_prompt(&prompts, daily_seed_now(), cycle) {
            Some(p) => p.to_string(),
            None => {
                tracing::debug!("canary baseline has no prompts; skipping cycle");
                return;
            }
        };
        match self.probe_once(&prompt).await {
            Ok(score) => {
                self.state.record_probe(score).await;
                tracing::debug!(score, "canary probe recorded");
            }
            Err(e) => {
                tracing::warn!(error = %e, "canary probe failed; cycle skipped");
            }
        }
    }

    /// Send one prompt at the upstream and score the response. Public
    /// for tests; production callers go through `run_one_cycle`.
    pub async fn probe_once(&self, prompt: &str) -> Result<f64, ProbeError> {
        let baseline_fp = self
            .state
            .baseline()
            .prompts
            .get(prompt)
            .cloned()
            .ok_or_else(|| ProbeError::PromptNotInBaseline(prompt.to_string()))?;

        let url = format!("{}/v1/messages", self.upstream_url.trim_end_matches('/'));
        let model = self.state.baseline().model_label.clone();

        let body = serde_json::json!({
            "model": model,
            "max_tokens": 64,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}]
        });

        let start = Instant::now();
        let resp = self
            .http_client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ProbeError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ProbeError::HttpStatus(status.as_u16()));
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let parsed: AnthropicResponse = resp
            .json()
            .await
            .map_err(|e| ProbeError::Parse(e.to_string()))?;

        let text = parsed
            .content
            .iter()
            .filter(|c| c.block_type == "text")
            .filter_map(|c| c.text.as_deref())
            .next()
            .unwrap_or("")
            .to_string();

        let observed = ProbeFingerprint {
            output_hash: features::output_hash(&text),
            length_bucket: features::log2_bucket(parsed.usage.output_tokens),
            stop_reason: parsed.stop_reason,
            latency_bucket: features::log2_bucket(elapsed_ms),
        };

        Ok(features::composite(&observed, &baseline_fp))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("network error: {0}")]
    Network(String),
    #[error("upstream returned HTTP {0}")]
    HttpStatus(u16),
    #[error("failed to parse upstream response: {0}")]
    Parse(String),
    #[error("prompt not present in baseline: {0}")]
    PromptNotInBaseline(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::canary_baseline::Baseline;

    #[test]
    fn date_seed_is_deterministic_and_unique_per_day() {
        let d1 = NaiveDate::from_ymd_opt(2026, 4, 25).unwrap();
        let d2 = NaiveDate::from_ymd_opt(2026, 4, 26).unwrap();
        assert_eq!(date_seed(d1), date_seed(d1));
        assert_ne!(date_seed(d1), date_seed(d2));
    }

    #[test]
    fn pick_prompt_is_stable_for_same_seed_and_cycle() {
        let prompts: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let seed = 42;
        for cycle in 0..20 {
            let p1 = pick_prompt(&prompts, seed, cycle);
            let p2 = pick_prompt(&prompts, seed, cycle);
            assert_eq!(p1, p2);
        }
    }

    #[test]
    fn pick_prompt_walks_all_prompts_within_day() {
        let prompts: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let seed = 7;
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for cycle in 0..prompts.len() as u64 {
            seen.insert(pick_prompt(&prompts, seed, cycle).unwrap());
        }
        assert_eq!(seen.len(), prompts.len(), "all prompts visited within one day's cycle");
    }

    #[test]
    fn pick_prompt_orders_differ_across_seeds() {
        let prompts: Vec<String> = ["a", "b", "c", "d", "e", "f", "g", "h"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let order_seed_1: Vec<&str> = (0..prompts.len() as u64)
            .map(|c| pick_prompt(&prompts, 1, c).unwrap())
            .collect();
        let order_seed_2: Vec<&str> = (0..prompts.len() as u64)
            .map(|c| pick_prompt(&prompts, 2, c).unwrap())
            .collect();
        assert_ne!(order_seed_1, order_seed_2, "different seeds give different orders");
    }

    #[test]
    fn pick_prompt_returns_none_for_empty() {
        let prompts: Vec<String> = vec![];
        assert!(pick_prompt(&prompts, 0, 0).is_none());
    }

    #[test]
    fn jittered_interval_stays_within_twenty_percent() {
        let base = Duration::from_secs(900);
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..1000 {
            let j = jittered_interval(base, &mut rng);
            let lo = (base.as_nanos() as f64 * 0.8) as u128;
            let hi = (base.as_nanos() as f64 * 1.2) as u128;
            assert!(
                j.as_nanos() >= lo && j.as_nanos() <= hi,
                "j={:?} out of range [{lo}, {hi}]",
                j
            );
        }
    }

    #[test]
    fn jittered_interval_zero_stays_zero() {
        let mut rng = StdRng::seed_from_u64(0);
        assert_eq!(jittered_interval(Duration::ZERO, &mut rng), Duration::ZERO);
    }

    fn baseline_with_prompt(prompt: &str, fp: ProbeFingerprint) -> Baseline {
        let mut b = Baseline::empty("claude-test-model");
        b.prompts.insert(prompt.to_string(), fp);
        b
    }

    #[tokio::test]
    async fn probe_once_returns_one_for_perfect_match() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let prompt = "ping";
        let response_text = "pong";

        // Build the expected baseline AS IF we'd captured the upstream
        // returning `response_text`. Then send the same response again
        // via wiremock and expect score == 1.0.
        let baseline_fp = ProbeFingerprint {
            output_hash: features::output_hash(response_text),
            length_bucket: features::log2_bucket(2),
            stop_reason: "end_turn".to_string(),
            // Latency bucket covers a wide range so the test isn't flaky
            // on slower CI; we deliberately keep score_latency tolerant.
            latency_bucket: 4,
        };
        let baseline = baseline_with_prompt(prompt, baseline_fp);
        let state = CanaryState::from_baseline(baseline);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": response_text}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 2}
            })))
            .mount(&server)
            .await;

        let runner = ProbeRunner::new(
            reqwest::Client::new(),
            server.uri(),
            "test-key".to_string(),
            state,
        );

        let score = runner.probe_once(prompt).await.expect("probe succeeds");
        // output_hash, length, stop_reason all match exactly. Latency
        // bucket may differ by a few — score_latency is tolerant. Floor
        // is 0.75 (output 1.0, length 1.0, stop 1.0, latency >= 0.0).
        assert!(score >= 0.75, "score {} below floor", score);
    }

    #[tokio::test]
    async fn probe_once_drops_score_on_drift() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let prompt = "ping";
        let baseline_fp = ProbeFingerprint {
            output_hash: features::output_hash("pong"),
            length_bucket: 1,
            stop_reason: "end_turn".to_string(),
            latency_bucket: 4,
        };
        let baseline = baseline_with_prompt(prompt, baseline_fp);
        let state = CanaryState::from_baseline(baseline);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": "completely-different-output"}],
                "stop_reason": "max_tokens",
                "usage": {"input_tokens": 1, "output_tokens": 64}
            })))
            .mount(&server)
            .await;

        let runner = ProbeRunner::new(
            reqwest::Client::new(),
            server.uri(),
            "test-key".to_string(),
            state,
        );

        let score = runner.probe_once(prompt).await.expect("probe succeeds");
        // Output hash differs, stop_reason differs, length way off.
        // Composite floor heavily.
        assert!(score < 0.3, "score {} too high — drift not detected", score);
    }

    #[tokio::test]
    async fn probe_once_returns_http_error_for_non_2xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let prompt = "ping";
        let baseline = baseline_with_prompt(
            prompt,
            ProbeFingerprint {
                output_hash: "x".to_string(),
                length_bucket: 0,
                stop_reason: "end_turn".to_string(),
                latency_bucket: 0,
            },
        );
        let state = CanaryState::from_baseline(baseline);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let runner = ProbeRunner::new(
            reqwest::Client::new(),
            server.uri(),
            "test-key".to_string(),
            state,
        );

        let err = runner.probe_once(prompt).await.expect_err("probe fails");
        assert!(matches!(err, ProbeError::HttpStatus(500)));
    }

    #[tokio::test]
    async fn probe_once_rejects_unknown_prompt() {
        let baseline = baseline_with_prompt(
            "known",
            ProbeFingerprint {
                output_hash: "x".to_string(),
                length_bucket: 0,
                stop_reason: "end_turn".to_string(),
                latency_bucket: 0,
            },
        );
        let state = CanaryState::from_baseline(baseline);
        let runner = ProbeRunner::new(
            reqwest::Client::new(),
            "http://localhost:1".to_string(),
            "key".to_string(),
            state,
        );
        let err = runner.probe_once("unknown").await.expect_err("missing prompt");
        assert!(matches!(err, ProbeError::PromptNotInBaseline(_)));
    }

    #[tokio::test]
    async fn run_one_cycle_records_probe_on_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let prompt = "ping";
        let baseline_fp = ProbeFingerprint {
            output_hash: features::output_hash("pong"),
            length_bucket: features::log2_bucket(2),
            stop_reason: "end_turn".to_string(),
            latency_bucket: 4,
        };
        let baseline = baseline_with_prompt(prompt, baseline_fp);
        let state = CanaryState::from_baseline(baseline);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": "pong"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 2}
            })))
            .mount(&server)
            .await;

        let runner = ProbeRunner::new(
            reqwest::Client::new(),
            server.uri(),
            "key".to_string(),
            state.clone(),
        );

        // run_one_cycle is best-effort, doesn't return errors. Verify
        // success by reading the rolling window.
        runner.run_one_cycle(0).await;
        let snapshot = state.status_snapshot().await;
        assert_eq!(snapshot.probes_in_window, 1);
    }

    #[tokio::test]
    async fn run_one_cycle_skips_silently_on_network_error() {
        let prompt = "ping";
        let baseline = baseline_with_prompt(
            prompt,
            ProbeFingerprint {
                output_hash: "x".to_string(),
                length_bucket: 0,
                stop_reason: "end_turn".to_string(),
                latency_bucket: 0,
            },
        );
        let state = CanaryState::from_baseline(baseline);
        let runner = ProbeRunner::new(
            reqwest::Client::new(),
            // Port 1 reliably refuses connections in CI.
            "http://127.0.0.1:1".to_string(),
            "key".to_string(),
            state.clone(),
        );

        runner.run_one_cycle(0).await;
        let snapshot = state.status_snapshot().await;
        // Network failure → no recorded score.
        assert_eq!(snapshot.probes_in_window, 0);
    }
}
