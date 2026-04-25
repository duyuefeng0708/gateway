# TODOs

Generated 2026-04-22 from `/plan-ceo-review`. Updated 2026-04-25 with verifiability plan from `/plan-eng-review`. Each item has a concrete revisit date.

---

## Shipped 2026-04-25 — verifiability roadmap

Four PRs landed end-to-end across the day. The verifiability story
("auditable by anyone") is now shippable in production.

* **PR #6 (PR-A0)** — Audit hardening. verify_chain recomputes, hash
  recipe canonical-JSON, single Utc::now, sync_data, file lock, async
  AuditHandle. Codex F1-F8.
* **PR #7 (PR-A1 partial)** — Wire AuditHandle into request path,
  HMAC'd digests, /v1/receipts/{id}, x-gateway-receipt header.
  Codex F11, F12.
* **PR #8 (PR-A1.5)** — Transparency state wired, Rekor publisher
  spawned, /v1/transparency/head route, gateway verify CLI, README
  "Receipts and tamper-evidence" section. Codex F10, F14, F15.
* **PR #9 (PR-B)** — Canary fingerprint framework, four feature
  scoring, /v1/canary/status, gateway canary bootstrap/show CLI.
  Codex F16, F17, F18, F19-partial.

Tests: 318 → 377 (+59). Clippy clean throughout.

## Shipped 2026-04-25 — PR-B.1 (runtime probe payload)

The canary loop now sends real upstream calls. Codex F19 closed.

* New `crates/gateway-proxy/src/canary/probe.rs` — `ProbeRunner` builds
  Anthropic `/v1/messages` request, parses response, computes
  `ProbeFingerprint`, scores via `features::composite`.
* Daily-seeded prompt rotation: `pick_prompt(prompts, daily_seed, cycle)`
  shuffles deterministically per ISO day; cycles within a day walk
  through the same shuffled order; cross-day order rotates so an
  adversary can't pre-bake responses to a fixed prompt.
* ±20% interval jitter on every cycle (`jittered_interval`).
* `gateway canary bootstrap` now hits a real upstream when `--stub`
  isn't set. Same prompt suite as the runtime probe. Operator review
  text printed alongside the success message (Codex F16).
* `main.rs` wires a `ProbeRunner` only when `ANTHROPIC_API_KEY` is set
  AND the baseline has prompts. Missing either falls back to the
  no-op loop posture introduced in PR-B.

Tests: 392 (+15). Clippy clean.

## Open verifiability items (P2)

* **F9 — streaming response_hmac finalisation.** Today response_hmac
  is empty for both streaming and non-streaming requests; the rolling
  HMAC over the response stream needs to write back to the audit
  entry, which requires audit-log entry-update support that doesn't
  exist yet. Revisit when there's a customer who wants verifiable
  response integrity.
* **F13 — KMS-backed signer.** PR-A1.5 ships with file-or-env Ed25519
  key. KMS/HSM signer is a small refactor to a Signer trait; revisit
  before any managed production deployment.
* **Multi-replica audit chain coordination.** Single-host file lock
  landed in PR-A0. Revisit when deploying >1 proxy replica.
* **Rekor sharding policy.** Periodic Merkle checkpoints scale
  ~100x better than per-request. Revisit at >1M receipts/day.

---

## P1 — Verifiability (planned 2026-04-25, COMPLETE)

### PR-A0: Harden existing audit.rs (~1 day CC)

Pre-condition for PR-A1. Without this, PR-A1's security claim is hollow because the existing `verify_chain` only checks `prev_hash` adjacency without recomputing entry hashes (Codex F1), and the existing hash recipe ignores most entry fields (Codex F2).

Changes in `crates/gateway-anonymizer/src/audit.rs`:
1. **F1:** `verify_chain` recomputes every entry hash. Tests must mutate `privacy_score`, `pii_types`, and `hash` to confirm rejection.
2. **F2:** `compute_hash` switches to canonical-JSON over the entire entry struct excluding only the `hash` field. All current and future fields authenticated.
3. **F3:** Add `hash_recipe: String` to `AuditEntry`. Existing rows (no value) treated as `audit-v1`; new rows use `audit-v2-canonical-json`. Verifier picks recipe by field value. Mixed V1/V2 verification test required.
4. **F4:** Add `verify_dir(path)` that walks daily files in lex order and confirms each file's first `prev_hash` equals the previous file's last `hash`. Test two-day chain + forked-first-entry rejection.
5. **F5:** Single `Utc::now()` per `write_entry`, captured once. Used for both entry timestamp and filename. Test with injected clock at midnight boundary.
6. **F6:** `file.sync_data()` after `writeln!`. Update README receipt-durability claim to match.
7. **F7 (single-host only):** `audit.lock` exclusive file lock acquired in `AuditWriter::new`. Multi-replica coordination → P2 (see below).
8. **F8:** New async `AuditHandle` with bounded `mpsc` channel + `spawn_blocking` writer task. Async handlers send entries, never block on file I/O. Backpressure semantics: full channel returns `AuditError::Backpressured`, propagates to a 503.

### PR-A1: Receipts + Rekor anchor + verify CLI (~2 days CC)

Depends on PR-A0. Adds the user-facing verifiability surface.

1. **F11:** `AuditEntry` gains 6 model-routing fields, each populated honestly: `client_requested_model`, `gateway_selected_route`, `upstream_requested_model`, `upstream_reported_model`, `detector_fast_model`, `detector_deep_model`. The single ambiguous `claimed_model` field is gone.
2. **F12:** `prompt_hmac` and `response_hmac` (HMAC-SHA-256, not bare SHA-256) plus `hmac_key_id`. Per-instance HMAC key in env. Verifier needs the key to confirm digests; without it, structural verification still works. Defeats confirmation attacks on candidate prompts.
3. **F9:** Streaming responses get rolling `response_hmac` finalized at stream end. New field `response_hash_status: pending|final`. Non-streaming returns receipt inline; streaming stores it for later lookup by `receipt_id`.
4. **F13:** `signing_key_id`, `signature_alg` fields. Verifier maintains a trust store and a revocation list. KMS signer backend → P2.
5. **F14:** Rekor anchors **periodic signed checkpoints** (Merkle root over all entries since the last checkpoint), not every per-request receipt. `GATEWAY_REKOR_ANCHOR_INTERVAL` defaults to 15m. Drops Rekor load by ~100×.
6. **F15:** Receipts include `anchor_status: not_yet_anchored|anchored|anchor_failed`, `rekor_uuid`, `log_index`, `integrated_time`, plus inclusion proof fields. CLI `gateway-cli verify` does offline signature/hash check first, then optional Rekor inclusion check.
7. **F10:** README and CLI help language never says "attestation." Receipts are "tamper-evident records anchored to a public transparency log." The README explicitly lists what receipts do NOT prove (PII removal correctness, model authenticity, response integrity in transit).
8. New axum routes via `lib.rs::build_server`: `GET /v1/receipts/{id}`, `GET /v1/transparency/head`.
9. New module `gateway-cli/src/verify.rs` + subcommand registration in `gateway-cli/src/main.rs`.

### PR-B: Canary fingerprint (~1 day CC)

Depends on PR-A1 only for the dashboard tile location; otherwise independent.

1. **F18:** Four feature ensemble (replacing the original spec, which included an infeasible top-token-distribution feature):
   - normalized output similarity against checked-in expected fingerprints
   - output token-count bucket
   - stop-reason / tool-shape match
   - latency bucket
2. **F16:** Baseline is `eval/canary_baseline.json`, **checked into the repo**, generated and reviewed by the operator from known-good captures. New deployments start in **observation mode** (probe but don't gate) until manual quorum approval.
3. **F19:** Probes pull from a prompt bank with daily-seeded selection, paraphrase templates, and ±20% interval jitter around the locked 15-minute default. Fixed-prompt fingerprinting becomes infeasible.
4. **F17:** `/v1/canary/status` is admin-authenticated, rate-limited, and returns coarse states only: `healthy | degraded | unknown`. No per-feature scores or raw probe output. Defeats the feedback-oracle attack.
5. New module `gateway-proxy/src/canary/` with `mod.rs`, `baseline.rs`, and `features/{output_similarity, length_bucket, stop_reason, latency_bucket}.rs`.
6. New CLI subcommands: `gateway-cli canary bootstrap`, `gateway-cli canary accept-drift`.

### TODOS deferred from this plan (P2)

- **Multi-replica audit chain coordination.** Single-host file lock landed in PR-A0. Revisit when deploying >1 proxy replica per audit stream. Likely solution: dedicated audit-coordinator service or shared-storage with leases.
- **KMS-backed signing key.** PR-A1 ships with file-or-env Ed25519 key. KMS/HSM signer is a small refactor to a `Signer` trait; revisit before any managed production deployment.
- **Rekor sharding and batch policy.** PR-A1 ships periodic checkpoints which scale ~100× better than per-request. Revisit at >1M receipts/day or >10k instances.
- **Receipt search by upstream_reported_model + time range.** Today receipts are looked up only by `receipt_id`. Operators may want to query "show all receipts where upstream returned a different model than requested in the last 24h." Index this when there's a real query.

---

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

### Warm-up self-DOS risk (Codex T8) — MITIGATED

**Status 2026-04-22:** Investigation written up in `docs/investigations/2026-04-22-codex-t8-warmup-self-dos.md`. Confirmed behaviour: Ollama does NOT abort in-flight generation when the client disconnects. A timed-out `send` wastes up to `num_predict` tokens of server compute.

**Mitigation shipped:** `OllamaDetector::build_request` now attaches `num_predict = 1024` to every `ChatMessageRequest`. Worst-case server-side waste per timed-out call drops from "generation runs to model-chosen limit" to a deterministic 1024-token ceiling (~40s on laptop Gemma-4-26B).

**Remaining concern:** Cold-boot contention with concurrent real traffic. Operators should treat `/ready == 503` as "do not send traffic yet." `docker-compose.yml` wires the healthcheck to do this automatically.

**Further work deferred:** Smaller probe-specific `num_predict` budget (e.g. 128 for warm-up only). Not shipped because it would require threading per-call budgets through the `PiiDetector` trait. Deferred until there's a real operational signal.

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
