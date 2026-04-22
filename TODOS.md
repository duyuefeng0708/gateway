# TODOs

Generated 2026-04-22 from `/plan-ceo-review`. Each item has a concrete revisit date.

## P1 — Product Validity

### Kill criterion: "one person says 'I would pay'"

**Deadline:** 2026-05-06 (14 days from 2026-04-22).

**Why:** Critique observed the project has no named customer, no landing, no signup, no pricing. A one-man team can't afford to build platform + GTM without demand validation.

**Measure:** Before 2026-05-06, at least one real person (not peer, not friend) says "I would pay $X/month for this." If not → reconsider project viability, not just scope.

**Started:** 2026-04-22
**Revisit:** 2026-05-06

---

### Re-benchmark under Ollama with 100+ prompts

**Deadline:** immediately runnable. Blocks any external recall claim.

**Why:** Two gaps rolled into one item:
1. Existing `eval/BENCHMARK_RESULTS.md` used llama.cpp / LM Studio, NOT Ollama. Config defaults now target `gemma4:e4b` + `gemma4:26b` via Ollama. Benchmark numbers don't transfer — different runtime, different prompt shape handling, different tokenization.
2. `eval/sample_benchmark.jsonl` is 5 prompts / 7 spans. Claim depth = vibes. External claim requires ≥100 prompts.

**Status (2026-04-22): READY TO RUN.**
- `eval/run_benchmark.py` extended with `--backend ollama` (default) and `--backend llamacpp`. Ollama backend hits `/api/chat` with `stream=false` and the same system prompt.
- `eval/generate_pii_100.py` produces `eval/pii_100.jsonl` — **105 entries, 169 ground-truth spans** (143 explicit + 26 implicit). Six categories: explicit PII, implicit PII, multi-PII, non-PII controls, code blocks, Unicode/edge-case inputs. All span offsets auto-computed and verified.
- `eval/BENCHMARK_RESULTS.md` annotated: "NOT VALIDATED UNDER OLLAMA. Re-benchmark pending."

**To run:**
```
ollama pull gemma4:e4b      # ~4 GB
ollama pull gemma4:26b      # ~18 GB (optional, only if you want the deep tier)
ollama serve                 # usually already running

python3 eval/run_benchmark.py --model gemma4:e4b --dataset eval/pii_100.jsonl \
    --output eval/results_e4b.jsonl
python3 eval/run_benchmark.py --model gemma4:26b --dataset eval/pii_100.jsonl \
    --output eval/results_26b.jsonl
```

**After running:** update `eval/BENCHMARK_RESULTS.md` with the Ollama numbers,
remove the "NOT VALIDATED" banner, and compare against the prior llama.cpp
figures to see whether the runtime change moves recall/latency meaningfully.

**Revisit:** once Ollama-backed numbers are in hand, latest 2026-05-22.

---

### Silent-fallback risk flag

**Accepted:** 2026-04-22. Deep-tier errors fall back to regex-only, surfaced only via Prometheus metrics.

**Why accepted:** Simplest wire-up. User-owned risk.

**Revisit trigger:** After 7 days of real traffic, if `deep_tier_succeeded_total / deep_tier_attempted_total < 0.5`, the "deep scan" claim is not honest. Consider hard-failing in deep mode at that point.

**Revisit:** 2026-05-22 or first real user, whichever first.

---

## P2 — Dead-Code Audit (30-day revisit)

All retained under HOLD SCOPE decision on 2026-04-22. If unused in real path by 2026-05-22, flag for deletion or feature-flag behind env var.

### eBPF loader + programs (~800 LOC)

**Files:** `crates/gateway-ebpf-loader/*`, `crates/gateway-ebpf-programs/*`
**Status:** Works on Linux 6.14, byte-order + cgroup bugs fixed.
**Load-bearing?** Only if a user complains that `HTTPS_PROXY` env var is too hard. No such user yet.
**Revisit:** 2026-05-22. If no user has cited transparent interception as valuable, move to a separate experimental branch.

### Smart routing (376 LOC)

**File:** `crates/gateway-proxy/src/routing.rs`
**Load-bearing?** Only if multiple upstreams are configured simultaneously (Anthropic + OpenAI + others). Default config uses one upstream.
**Revisit:** 2026-05-22. If no user configures >1 upstream, move behind `GATEWAY_FEATURE_ROUTING` flag.

### OpenAI compat surface (~200 LOC)

**File:** `crates/gateway-proxy/src/format.rs` (OpenAI-shaped path)
**Load-bearing?** Only if users point OpenAI-compatible clients at the gateway. Anthropic is the primary documented target.
**Revisit:** 2026-05-22. If no OpenAI-format request has hit `/metrics`, remove the branch or feature-flag.

### Custom rules engine (YAML) (334 LOC)

**File:** `crates/gateway-anonymizer/src/rules.rs`
**Load-bearing?** Only if users write `rules.yaml`. Default config has no rules file.
**Revisit:** 2026-05-22. If no user has created rules.yaml, feature-flag behind `GATEWAY_FEATURE_CUSTOM_RULES`.

### Warm-up self-DOS risk (Codex T8)

**Concern:** At 8s client timeout + 86s server-side generation, Ollama keeps processing the probe request after the client hangs up. 5 retries × 86s = ~7 minutes of wasted model time per boot. No cancellation today.

**Plan:**
- Warm-up probe should use a minimal synthetic prompt (1–2 tokens: e.g., `"hi"`).
- Investigate Ollama's request cancellation behavior via HTTP connection close — does it kill generation or keep going?
- Consider `/api/generate` with `keep_alive=0` to avoid warming a persistent model instance at probe time.

**Priority:** P2 — not blocking wire-up but real operational waste. Revisit first time warm-up is observed in practice.

**Revisit:** After first real-world deployment observation, max 2026-05-22.

---

### Hash-chained audit trail (276 LOC)

**File:** `crates/gateway-anonymizer/src/audit.rs`
**Load-bearing?** Only if session_id flows + a compliance user is asking for it. No compliance user yet.
**Revisit:** 2026-05-22. If no user cites audit as a reason they use the product, move behind `GATEWAY_FEATURE_AUDIT`.

---

## Shipped since 2026-04-22

- **PR #1** — TieredDetector wire-up (30 items from the plan below). 1,854 lines added, 266 removed, 31 files. 296/296 tests pass, clippy clean. Merged to `main`.
- **PR #2** — Ollama benchmark runnable end-to-end. `eval/run_benchmark.py --backend ollama` + 105-entry `eval/pii_100.jsonl` (169 spans, 143 explicit + 26 implicit). Merged.
- **PR #3** — Docker compose wired to new `/ready` endpoint. One-shot `gateway-ollama-pull` sidecar pre-pulls models before the proxy boots. `gateway-ebpf` now waits for `service_healthy` on the proxy. Merged.

The P1 block below is retained for historical reference.

---

## P1 — Wire-up Plan (shipped in PR #1 2026-04-22)

Implementation tasks produced by this review + eng review + Codex adjudication.
Do NOT defer these. Ordered loosely by dependency.

### Trait + data model
1. Add `PiiDetector::detect_with_metadata` default impl to trait. Default wraps `detect()` returning `DetectionResult { spans, deep_scan_used=false, deep_scan_available=false, deep_attempted=false, deep_error=None, rules_attempted=false, rules_error=None }`.
2. Extend `DetectionResult` with `deep_attempted: bool`, `deep_error: Option<DetectionError>`, `rules_attempted: bool`, `rules_error: Option<DetectionError>`. Keeps in `gateway-anonymizer/src/tiered.rs` (NOT moved to common).
3. `TieredDetector::detect_with_metadata` populates the new fields honestly in all three scan modes.

### Config
4. Split `model_timeout` into `detection_timeout` (`GATEWAY_DETECTION_TIMEOUT`, default 8s) and `upstream_timeout` (`GATEWAY_UPSTREAM_TIMEOUT`, default 60s). Remove the conflated `model_timeout` field.
5. Change config defaults to `fast_model=gemma4:e4b`, `deep_model=gemma4:26b` (Ollama tags per Codex).
6. Add `detection_concurrency: usize` (env `GATEWAY_DETECTION_CONCURRENCY`, default 2) to `GatewayConfig`.
7. Keep `scan_mode` default = `fast`. Deep remains opt-in.

### Wire-up + factory
8. `TieredDetector::from_config(&GatewayConfig)` factory. Builds regex + fast + deep (optional) + rules (if `GATEWAY_RULES_PATH` set) based on scan mode. One place owns construction.
9. Replace `RegexDetector::new()` in `main.rs:37` with `TieredDetector::from_config(&config)`.
10. `AppState` gains `warm: Arc<AtomicBool>` (starts false) and `detection_semaphore: Arc<tokio::sync::Semaphore>` (from `detection_concurrency`).

### Bootstrap + readiness
11. Add `pub fn build_server(state: AppState) -> Router` to `gateway-proxy/src/lib.rs`. Tests + main both call it. Enables integration testing of the router.
12. Warm-up probe on startup: 5 retries with exponential backoff (2/4/8/16/32s). Probe sends `"ping: my email is test@example.com"` through `detector.detect_with_metadata()`. On success → `warm.store(true, Release)`. All 5 fail → log ERROR, `warm` stays false.
13. Warm-up probe MUST NOT create session store entries or audit rows.
14. Listener binds AFTER warm-up completes (success or all-retries-exhausted).
15. Add `GET /ready` route: 200 if `warm.load(Acquire)==true`, else 503. `Content-Type: text/plain`.

### Multi-message handler (T4 from Codex)
16. Refactor `handler.rs:175-207` from sequential loop to bounded parallel detection. Use `Arc::clone(&state.detection_semaphore)` to cap in-flight detect calls. Collect results preserving original message index. Sort back to input order before placeholder substitution.

### Placeholder correctness (T13 from Codex)
17. Update `placeholder::substitute` (`placeholder.rs:13-38`) to validate:
    - `start` and `end` are UTF-8 char boundaries (use `text.is_char_boundary(start) && text.is_char_boundary(end)`).
    - `text[start..end] == span.text` exactly.
    - If offsets invalid: fall back to searching for `span.text` in original text without overlap with already-substituted ranges.
18. Add tests `placeholder_test.rs`:
    - Unicode boundary (emoji prefix, multi-byte name).
    - Bad offsets from model (off-by-one, overrun).
    - Text-mismatch detection.

### Metrics (6 new + 1 helper)
19. Add to `metrics.rs`:
    - `record_tier_used(tier: &str)` — counter `gateway_detector_tier_used{tier}`, label in {regex, fast, deep}.
    - `record_deep_tier_attempted()`, `record_deep_tier_succeeded()`, `record_deep_tier_failed(kind)` — counters.
    - `record_deep_tier_latency(Instant)` — histogram `gateway_deep_tier_latency_seconds`, custom buckets [0.1, 0.5, 1, 2, 5, 10, 30, 60, 90, 120, 180, 300].
    - `record_ollama_connection_error()` — counter.
    - `record_warmup_duration(Instant)` — gauge `gateway_readiness_warmup_duration_seconds`.
20. Wire metrics from `DetectionResult` fields in `handler.rs` after each `detect_with_metadata` call.

### Install + distribution (T3 from Codex)
21. Update `scripts/install.sh:324,331-337`: replace MTBS references with `${GATEWAY_FAST_MODEL:-gemma4:e4b}`. Add `--with-deep` flag + `GATEWAY_INSTALL_DEEP=1` env that additionally pulls `${GATEWAY_DEEP_MODEL:-gemma4:26b}`.
22. Update `README.md:27-28,69-71`: document `GATEWAY_SCAN_MODE` options, silent-fallback behavior, `deep_tier_attempted_total - deep_tier_succeeded_total` alert, laptop-deep-experiment path (mode=auto + timeout=120s + expect 86s/request).
23. Update `crates/gateway-cli/src/doctor.rs:28-34`: check fast model always, deep model only when `config.scan_mode` is `Auto` or `Deep`. Update doctor tests at `doctor.rs:316-338`.

### Eval/bench note (T2 from Codex)
24. Annotate top of `eval/BENCHMARK_RESULTS.md`: "NOT VALIDATED UNDER OLLAMA. Numbers reflect llama.cpp / LM Studio runs. Re-benchmark pending."

### Tests (full coverage of 16 paths per coverage diagram)
25. Add `wiremock = "0.6"` and `temp_env = "0.3"` dev-deps.
26. Refactor existing env tests (`config_requires_api_key`, `config_parses_with_defaults`) to use `temp_env::with_var`.
27. Unit tests in `tiered.rs`:
    - `from_config` builds correctly for Fast/Deep/Auto.
    - `from_config` loads rules when `GATEWAY_RULES_PATH` set.
    - `DetectionResult` fields populated correctly on deep error / deep timeout / deep disabled.
28. Integration tests in `handler_test.rs`:
    - wiremock Ollama + mode=auto + metric assertions (tier_used increments, attempted/succeeded increments).
    - wiremock Ollama returns 500 → silent-fallback observable via metric.
    - wiremock Ollama returns malformed JSON → retry-once fires.
29. New integration test `tests/readiness_test.rs`:
    - /ready pre-warm → 503.
    - /ready post-warm → 200.
    - All 5 warm-up retries fail → listener binds + /ready stays 503.
30. New integration test for bounded concurrency: 10 messages, semaphore=2, assert no more than 2 detect calls in flight at once.

---

## Cadence Commitment (2026-04-22)

- **Daily:** one commit EOD. WIP OK.
- **Weekly:** Sunday `/retro` skill run to catch drift before another 12-day gap.
- **Kill criterion above is load-bearing** — do not bury it.
