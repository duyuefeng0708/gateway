use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::{info, warn};

use crate::metrics;
use crate::state::AppState;

/// Short, cheap synthetic prompt containing one trivial PII span. The email
/// ensures the pipeline has something to return; the brevity keeps the
/// Ollama cost of warm-up minimal (see TODOS.md P2 Codex T8 for the
/// self-DOS discussion — a short prompt minimises server-side waste when
/// the client timeout fires before Ollama finishes generating).
const WARMUP_PROMPT: &str = "ping: my email is test@example.com";

/// Exponential backoff schedule. Totals ~62 seconds across 5 attempts.
const RETRY_BACKOFF_SECS: &[u64] = &[2, 4, 8, 16, 32];

/// Run the warm-up probe against the configured detector.
///
/// Tries up to 5 times with exponential backoff. On first success, sets
/// `state.warm = true` and records `gateway_readiness_warmup_duration_seconds`.
/// On all-fail, emits an ERROR log; `state.warm` stays `false` and `/ready`
/// will continue returning 503 — silent-fallback at request time will still
/// happen, but operators can alert on the readiness gap.
///
/// Returns once the probe either succeeds or exhausts all retries. Callers
/// are expected to bind the listener AFTER this returns so docker-compose
/// `depends_on` + healthcheck semantics are honest.
pub async fn run_with_retry(state: &AppState) {
    // In fast-regex-only mode, the warm-up probe doesn't need Ollama — the
    // regex detector has no startup cost. Flip warm to true and move on.
    if matches!(
        state.config.scan_mode,
        gateway_common::types::ScanMode::Fast
    ) && state.detector.name() == "regex"
    {
        state.warm.store(true, Ordering::Release);
        info!("warm-up skipped (regex-only detector, no Ollama dependency)");
        return;
    }

    let start = Instant::now();
    for (attempt, delay_secs) in RETRY_BACKOFF_SECS.iter().enumerate() {
        let attempt_num = attempt + 1;
        info!(attempt = attempt_num, "warm-up probe starting");

        match state
            .detector
            .detect_with_metadata(WARMUP_PROMPT)
            .await
        {
            Ok(_) => {
                let elapsed = start.elapsed();
                state.warm.store(true, Ordering::Release);
                metrics::record_warmup_duration_secs(elapsed.as_secs_f64());
                info!(
                    attempt = attempt_num,
                    duration_s = elapsed.as_secs_f64(),
                    "warm-up probe succeeded, binding listener"
                );
                return;
            }
            Err(e) => {
                warn!(
                    attempt = attempt_num,
                    error = %e,
                    next_retry_secs = delay_secs,
                    "warm-up probe failed, retrying"
                );
                // Don't sleep after the last attempt — we're about to return.
                if attempt_num < RETRY_BACKOFF_SECS.len() {
                    sleep(Duration::from_secs(*delay_secs)).await;
                }
            }
        }
    }

    tracing::error!(
        attempts = RETRY_BACKOFF_SECS.len(),
        total_elapsed_s = start.elapsed().as_secs_f64(),
        "warm-up probe exhausted all retries; listener will bind with warm=false. \
         /ready will report 503 until a detection succeeds organically."
    );
}
