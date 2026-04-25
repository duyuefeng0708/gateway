//! Runtime canary state and the public status surface.
//!
//! The state holds the loaded baseline and a sliding window of recent
//! probe outcomes. The background probe loop (see
//! [`CanaryState::spawn_probe`]) wakes every
//! `GATEWAY_CANARY_INTERVAL` (default 900s / 15min), picks a prompt
//! from the bank with daily-seeded jitter (Codex F19), runs the
//! upstream call, scores the response against the baseline, and
//! updates the rolling confidence.

use std::path::PathBuf;
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use tokio::sync::RwLock;

use gateway_common::canary_baseline::Baseline;

use crate::canary::probe::{jittered_interval, ProbeRunner};

const DEFAULT_INTERVAL_SECS: u64 = 900;
const DEFAULT_HEALTHY_THRESHOLD: f64 = 0.8;
const DEFAULT_DEGRADED_THRESHOLD: f64 = 0.5;
const DEFAULT_HISTORY_SIZE: usize = 8;

/// Coarse public status. Codex F17 — never expose per-feature scores
/// or raw probe output via this enum; that would let an attacker tune
/// a spoof against the canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CanaryHealth {
    /// Confidence ≥ 0.8 across the rolling window. Upstream behaviour
    /// matches the baseline closely.
    Healthy,
    /// Confidence < 0.5. Upstream has likely been swapped or has
    /// drifted dramatically.
    Degraded,
    /// Either no probe has run yet (cold start) or confidence sits
    /// in `[0.5, 0.8)` — too noisy to call. Operators should wait for
    /// more probes before acting.
    Unknown,
}

/// JSON returned by `GET /v1/canary/status`. Coarse on purpose. Codex
/// F17.
#[derive(Debug, Clone, Serialize)]
pub struct CanaryStatus {
    pub health: CanaryHealth,
    pub last_probe_at: Option<String>,
    pub probes_in_window: usize,
    pub baseline_model_label: String,
}

#[derive(Debug, Default)]
struct InnerState {
    /// Recent composite confidence scores. Bounded to
    /// `DEFAULT_HISTORY_SIZE`; older values evicted FIFO.
    recent_scores: Vec<f64>,
    /// Wall-clock of the most recent probe (success or failure).
    last_probe_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Public canary handle. Cheaply cloneable. The probe loop lives behind
/// a detached `tokio::spawn`; the handle just exposes the snapshot
/// surface and a `record_probe` method called from the loop.
#[derive(Clone)]
pub struct CanaryState {
    inner: Arc<RwLock<InnerState>>,
    baseline: Arc<Baseline>,
    interval_secs: u64,
    healthy_threshold: f64,
    degraded_threshold: f64,
    history_size: usize,
}

impl CanaryState {
    /// Construct from a path to the baseline JSON file. Used by main.rs
    /// at boot. Returns Err if the file is missing or malformed —
    /// fail-loud is the right default; running the canary against a
    /// missing baseline silently is worse than refusing to start.
    pub fn from_baseline_path(path: PathBuf) -> Result<Self, CanaryError> {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| CanaryError::Read(path.clone(), e.to_string()))?;
        let baseline: Baseline =
            serde_json::from_str(&raw).map_err(|e| CanaryError::Parse(e.to_string()))?;

        let interval_secs = std::env::var("GATEWAY_CANARY_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_INTERVAL_SECS);

        Ok(Self {
            inner: Arc::new(RwLock::new(InnerState::default())),
            baseline: Arc::new(baseline),
            interval_secs,
            healthy_threshold: DEFAULT_HEALTHY_THRESHOLD,
            degraded_threshold: DEFAULT_DEGRADED_THRESHOLD,
            history_size: DEFAULT_HISTORY_SIZE,
        })
    }

    /// Build directly from a constructed Baseline. Tests use this; main.rs
    /// uses `from_baseline_path`.
    pub fn from_baseline(baseline: Baseline) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerState::default())),
            baseline: Arc::new(baseline),
            interval_secs: DEFAULT_INTERVAL_SECS,
            healthy_threshold: DEFAULT_HEALTHY_THRESHOLD,
            degraded_threshold: DEFAULT_DEGRADED_THRESHOLD,
            history_size: DEFAULT_HISTORY_SIZE,
        }
    }

    /// Construct a stub canary that's permanently `Unknown`. Used in
    /// tests that don't care about the canary surface but still need
    /// to populate AppState.
    pub fn stub() -> Self {
        Self::from_baseline(Baseline::empty("test-stub"))
    }

    pub fn interval_secs(&self) -> u64 {
        self.interval_secs
    }

    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Record a probe outcome. Pushes the score onto the rolling
    /// window, evicts the oldest if the window is full.
    pub async fn record_probe(&self, score: f64) {
        let mut inner = self.inner.write().await;
        if inner.recent_scores.len() >= self.history_size {
            inner.recent_scores.remove(0);
        }
        inner.recent_scores.push(score);
        inner.last_probe_at = Some(chrono::Utc::now());
    }

    /// Compute the current public snapshot. Cheap; only acquires the
    /// read lock briefly.
    pub async fn status_snapshot(&self) -> CanaryStatus {
        let inner = self.inner.read().await;

        let health = if inner.recent_scores.is_empty() {
            CanaryHealth::Unknown
        } else {
            let avg: f64 =
                inner.recent_scores.iter().sum::<f64>() / inner.recent_scores.len() as f64;
            if avg >= self.healthy_threshold {
                CanaryHealth::Healthy
            } else if avg < self.degraded_threshold {
                CanaryHealth::Degraded
            } else {
                CanaryHealth::Unknown
            }
        };

        CanaryStatus {
            health,
            last_probe_at: inner.last_probe_at.map(|t| t.to_rfc3339()),
            probes_in_window: inner.recent_scores.len(),
            baseline_model_label: self.baseline.model_label.clone(),
        }
    }

    /// Drive a single probe cycle. Test helper; production code spawns
    /// the loop via `spawn_probe`.
    #[doc(hidden)]
    pub async fn run_one_cycle_for_test(&self, score: f64) {
        self.record_probe(score).await;
    }

    /// Spawn the probe loop.
    ///
    /// With `Some(runner)`, each cycle fires a real upstream probe via
    /// [`ProbeRunner::run_one_cycle`] and records the score. With
    /// `None` (e.g. no API key, stub baseline), the loop just logs every
    /// interval so operators can see the canary is alive without
    /// generating traffic.
    ///
    /// Interval is the configured base ± 20% jitter per cycle (Codex F19).
    pub fn spawn_probe(self, runner: Option<ProbeRunner>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let base = std::time::Duration::from_secs(self.interval_secs);
            let mut rng = StdRng::from_entropy();
            let mut cycle: u64 = 0;
            tracing::info!(
                interval_secs = self.interval_secs,
                model = %self.baseline.model_label,
                prompts = self.baseline.prompts.len(),
                live = runner.is_some(),
                "canary probe loop started"
            );
            loop {
                let sleep_for = jittered_interval(base, &mut rng);
                tokio::time::sleep(sleep_for).await;
                match runner.as_ref() {
                    Some(r) => r.run_one_cycle(cycle).await,
                    None => tracing::debug!(
                        cycle,
                        "canary probe interval elapsed (no runner; baseline is stub or upstream key missing)"
                    ),
                }
                cycle = cycle.wrapping_add(1);
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    #[error("failed to read baseline at {0}: {1}")]
    Read(PathBuf, String),
    #[error("failed to parse baseline JSON: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::canary_baseline::ProbeFingerprint;

    fn baseline_with_one_prompt() -> Baseline {
        let mut b = Baseline::empty("test-model");
        b.prompts.insert(
            "What is 2+2?".to_string(),
            ProbeFingerprint {
                output_hash: "abc".to_string(),
                length_bucket: 3,
                stop_reason: "end_turn".to_string(),
                latency_bucket: 9,
            },
        );
        b
    }

    #[tokio::test]
    async fn fresh_state_returns_unknown() {
        let state = CanaryState::from_baseline(baseline_with_one_prompt());
        let status = state.status_snapshot().await;
        assert_eq!(status.health, CanaryHealth::Unknown);
        assert_eq!(status.probes_in_window, 0);
        assert_eq!(status.baseline_model_label, "test-model");
        assert!(status.last_probe_at.is_none());
    }

    #[tokio::test]
    async fn high_score_yields_healthy() {
        let state = CanaryState::from_baseline(baseline_with_one_prompt());
        for _ in 0..5 {
            state.record_probe(0.95).await;
        }
        let status = state.status_snapshot().await;
        assert_eq!(status.health, CanaryHealth::Healthy);
        assert_eq!(status.probes_in_window, 5);
        assert!(status.last_probe_at.is_some());
    }

    #[tokio::test]
    async fn low_score_yields_degraded() {
        let state = CanaryState::from_baseline(baseline_with_one_prompt());
        for _ in 0..5 {
            state.record_probe(0.2).await;
        }
        let status = state.status_snapshot().await;
        assert_eq!(status.health, CanaryHealth::Degraded);
    }

    #[tokio::test]
    async fn middling_score_yields_unknown() {
        let state = CanaryState::from_baseline(baseline_with_one_prompt());
        for _ in 0..5 {
            state.record_probe(0.65).await;
        }
        let status = state.status_snapshot().await;
        assert_eq!(status.health, CanaryHealth::Unknown);
    }

    #[tokio::test]
    async fn rolling_window_evicts_oldest() {
        let state = CanaryState::from_baseline(baseline_with_one_prompt());
        // Fill the window with degraded scores...
        for _ in 0..DEFAULT_HISTORY_SIZE {
            state.record_probe(0.1).await;
        }
        assert_eq!(
            state.status_snapshot().await.health,
            CanaryHealth::Degraded
        );
        // ...then push enough healthy ones to overwrite all of them.
        for _ in 0..DEFAULT_HISTORY_SIZE {
            state.record_probe(0.95).await;
        }
        assert_eq!(state.status_snapshot().await.health, CanaryHealth::Healthy);
    }

    #[tokio::test]
    async fn from_baseline_path_rejects_missing_file() {
        let result = CanaryState::from_baseline_path("/nonexistent/baseline.json".into());
        assert!(matches!(result, Err(CanaryError::Read(_, _))));
    }

    #[tokio::test]
    async fn from_baseline_path_loads_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let baseline = baseline_with_one_prompt();
        std::fs::write(&path, serde_json::to_string(&baseline).unwrap()).unwrap();

        let state = CanaryState::from_baseline_path(path).unwrap();
        assert_eq!(state.baseline().model_label, "test-model");
    }
}
