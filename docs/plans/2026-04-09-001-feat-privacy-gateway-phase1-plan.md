---
title: "feat: Privacy Gateway Phase 1 — Rust Semantic Anonymizer Proxy"
type: feat
status: active
date: 2026-04-09
origin: ~/.gstack/projects/gateway/ceo-plans/2026-04-09-privacy-gateway.md
---

# Privacy Gateway Phase 1 — Rust Semantic Anonymizer Proxy

## Overview

Build a Rust reverse proxy that intercepts LLM API requests, detects PII using a tiered
local model strategy (4B fast + 27B deep scan), replaces PII with UUID-based placeholders,
forwards the anonymized request to the upstream provider, deanonymizes the response, and
returns it to the client. Standalone by default (no cc-gateway dependency). Includes a
split terminal demo, privacy score, health check CLI, and hash-chained audit trail.

## Problem Frame

AI engineers accept either degraded output from local models or privacy exposure from
cloud APIs. Existing PII detection in gateways uses regex/NER that misses implicit PII
("the Stanford professor who testified at the Senate hearing"). CloakPipe and AnonymizerSLM
exist but neither catches implicit PII via reasoning. This gateway differentiates by
offering tiered detection: fast explicit PII via a purpose-built 4B model, plus optional
deep implicit PII detection via a 27B reasoning model.

(see origin: CEO plan, Competitive Landscape section)

## Requirements Trace

- R1. Un-anonymized data NEVER reaches the upstream provider (fail-closed iron rule)
- R2. Explicit PII recall >= 90% (entity-level, on benchmark dataset)
- R3. Implicit PII recall >= 70% (entity-level, deep scan mode)
- R4. Kill criterion: < 60% implicit recall by Week 6
- R5. Privacy score computed and displayed per request (0-100, weighted)
- R6. Multi-turn session persistence (entity mappings survive across conversation turns)
- R7. Hash-chained audit trail with TEE-compatible format
- R8. Code blocks in prompts are NOT anonymized (developer UX critical)
- R9. Standalone default (works without cc-gateway)
- R10. Docker compose deployment (proxy + Ollama sidecar)
- R11. Split terminal demo showing original vs anonymized prompt

## Scope Boundaries

- Phase 1 ONLY (Weeks 1-8). Phase 2+ features are explicitly out of scope.
- Non-streaming: proxy buffers full response before deanonymizing (streaming is Phase 2)
- Text-only: images, files, audio rejected with 415 (multi-modal is Phase 3+)
- Anthropic API only for Phase 1 (OpenAI compatibility is Phase 2)
- No prompt enhancement (Phase 2)
- No smart model routing (Phase 2)
- No plugin system for custom PII rules (Phase 2)
- No eBPF transparent interception (Phase 3)
- No enterprise management UI (Phase 4)

## Context & Research

### Relevant Code and Patterns

Greenfield project. No existing code. Key external references:

- `ollama-rs` v0.3.4: Rust Ollama client crate. Use for all model API calls.
- `ratatui`: TUI framework for split terminal demo
- `rusqlite`: SQLite bindings. Use with `tokio::task::spawn_blocking` for async compat.
- `axum` + `tower`: HTTP framework. Custom handler (NOT axum-reverse-proxy; see eng review).
- `reqwest`: HTTP client for upstream forwarding.
- `thiserror`: Error type derivation per crate.
- `serde` + `serde_json`: JSON serialization for model output, audit entries, config.
- `sha2`: SHA-256 hashing for audit trail hash chains.
- `uuid`: UUID generation for placeholder IDs.

### Institutional Learnings

From CEO review and eng review (see origin):

- **Tiered model strategy**: AnonymizerSLM 4B (fast) + Qwen3.5-27B (deep). MTBS/anonymizer
  on Ollama as Plan A for 4B tier. (confidence: 9/10, cross-model validated)
- **Ollama structured output bug**: Issue #15260 and #14645. `think=false` on Qwen3.5 breaks
  JSON format parameter. Use prompt-based JSON output instead. (confidence: 10/10, verified)
- **axum-reverse-proxy rejected**: Crate handles forwarding, not body-level interception with
  async model calls. Custom Axum handler required. (confidence: 9/10, cross-model validated)
- **Full-scope preference**: User explicitly chose full Phase 1 scope over trimmed MVP.
  (confidence: 10/10, user-stated)

### External References

- [CloakPipe](https://cloakpipe.co/) — Rust PII proxy competitor. Study SSE rehydration for Phase 2.
- [AnonymizerSLM](https://huggingface.co/blog/pratyushrt/anonymizerslm) — Purpose-built PII models.
- [LOPSIDED (arXiv 2510.27016)](https://arxiv.org/abs/2510.27016) — Academic pseudonymization framework.
- [Ollama Issue #15260](https://github.com/ollama/ollama/issues/15260) — Structured output bug.
- [Axum reverse proxy example](https://github.com/tokio-rs/axum/blob/main/examples/reverse-proxy/src/main.rs)

## Key Technical Decisions

- **Custom Axum handler over reverse proxy crate**: The proxy buffers request body, calls
  a model mid-pipeline, rewrites the body, then forwards. This is request transformation,
  not reverse proxying. axum-reverse-proxy cannot handle async body interception.
  (see origin: eng review, cross-model tension #1)

- **Prompt-based JSON over Ollama format parameter**: Ollama bug #15260 breaks structured
  output on Qwen3.5 with `think=false`. Prompt-based JSON is more portable across model
  families and doesn't depend on Ollama fixing the bug.
  (see origin: eng review, cross-model tension #2)

- **MTBS/anonymizer as 4B Plan A**: Already on Ollama (4.7GB, 128K context). AnonymizerSLM
  needs GGUF conversion. Benchmark both in Week 2, pick the winner.
  (see origin: eng review, issue #1)

- **UUID-based placeholders**: Format `[PERSON_a7f3b2c1]` with regex
  `\[(PERSON|ORG|EMAIL|LOCATION|CREDENTIAL)_[a-f0-9]{8}\]`. Eliminates collision risk
  (vs sequential counters) and avoids false-matching code constructs like `arr[0]`.
  (see origin: CEO review, error gap resolution)

- **4B confidence threshold for auto-mode escalation**: If any PII detection has confidence
  < 0.7 OR 4B found 0 PII in a prompt > 200 tokens, escalate to 27B deep scan.
  (see origin: eng review, issue #3)

- **Auto-warm Ollama on startup**: Send a ping prompt before accepting connections. Avoids
  10-30s cold start timeout on first real request.
  (see origin: eng review, performance issue)

- **Fail-closed on audit write failure**: If audit log can't write (disk full), proxy
  returns 503. Verifiability guarantee is not optional.
  (see origin: CEO review, error gap resolution)

- **rusqlite with spawn_blocking**: Synchronous SQLite client wrapped in Tokio spawn_blocking.
  Simpler than sqlx for Phase 1 single-user workload. WAL mode for concurrent read/write.

## Open Questions

### Resolved During Planning

- **Which 4B model for fast tier?** MTBS/anonymizer (already on Ollama). Benchmark vs
  AnonymizerSLM GGUF conversion in Week 2.
- **How does auto-mode escalation work?** 4B confidence threshold < 0.7 triggers 27B.
- **Streaming in Phase 1?** No. Buffer full response. Streaming is Phase 2.
- **Ollama structured output?** Prompt-based JSON, not format parameter.

### Deferred to Implementation

- Exact system prompt wording for PII detection (depends on model behavior during eval)
- Privacy score weight tuning (initial weights defined, may adjust based on eval results)
- Optimal SQLite connection pool size under concurrent load
- ratatui layout details for split terminal (design during CLI implementation)
- Exact benchmark dataset composition (existing datasets + hand-labeled supplement)

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not
> implementation specification. The implementing agent should treat it as context, not
> code to reproduce.*

```
REQUEST FLOW (per request):

Client ──HTTPS──▶ Axum Handler
                    │
                    ├─ 1. Parse JSON body, extract prompt text
                    ├─ 2. Detect code blocks (markdown fences), mark as skip zones
                    ├─ 3. Run regex pre-scan (emails, SSNs, phones, credentials)
                    ├─ 4. Send prompt to Ollama (4B fast model)
                    │     └─ Parse structured JSON: [{type, start, end, text, confidence}]
                    ├─ 5. If auto-mode AND (confidence < 0.7 OR no PII in long prompt):
                    │     └─ Escalate: send to Ollama (27B deep model)
                    ├─ 6. Merge regex + model PII spans (dedup, prefer model)
                    ├─ 7. Generate UUID placeholders, substitute in prompt
                    ├─ 8. Store entity map in SQLite (session-keyed)
                    ├─ 9. Compute privacy score
                    ├─ 10. Write audit entry (hash-chained)
                    ├─ 11. Forward anonymized request to upstream via reqwest
                    │
                    ◀─── Response from upstream
                    │
                    ├─ 12. Buffer full response body
                    ├─ 13. Regex scan for [TYPE_uuid] placeholders
                    ├─ 14. Look up each in SQLite, replace with original
                    ├─ 15. Add X-Gateway-Privacy-Score header
                    └─ 16. Return deanonymized response to client

TRAIT HIERARCHY:

PiiDetector (trait)
  ├── RegexDetector        — emails, SSNs, phones, API keys. Sub-millisecond.
  ├── OllamaDetector<Fast> — MTBS/anonymizer 4B. Sub-second.
  ├── OllamaDetector<Deep> — Qwen3.5-27B. 2-8 seconds.
  └── TieredDetector       — Runs regex + fast. Escalates to deep if needed.
```

## Implementation Units

### Week 1: Foundation + Eval (Priority)

- [ ] **Unit 1: Workspace + Common Types**

  **Goal:** Create the Rust workspace with 4 crates and define all shared types.

  **Requirements:** Foundation for all other units.

  **Dependencies:** None.

  **Files:**
  - Create: `Cargo.toml` (workspace root)
  - Create: `crates/gateway-common/Cargo.toml`
  - Create: `crates/gateway-common/src/lib.rs`
  - Create: `crates/gateway-common/src/types.rs`
  - Create: `crates/gateway-common/src/errors.rs`
  - Create: `crates/gateway-common/src/config.rs`
  - Create: `crates/gateway-proxy/Cargo.toml`
  - Create: `crates/gateway-proxy/src/main.rs` (placeholder)
  - Create: `crates/gateway-anonymizer/Cargo.toml`
  - Create: `crates/gateway-anonymizer/src/lib.rs`
  - Create: `crates/gateway-cli/Cargo.toml`
  - Create: `crates/gateway-cli/src/main.rs` (placeholder)
  - Create: `.gitignore`
  - Test: `crates/gateway-common/src/types.rs` (inline tests)

  **Approach:**
  - Workspace members: gateway-proxy, gateway-anonymizer, gateway-cli, gateway-common
  - gateway-common exports: `PiiSpan`, `PiiType`, `Placeholder`, `PlaceholderMap`,
    `SessionMapping`, `AuditEntry`, `PrivacyScore`, `GatewayConfig`, `GatewayError`
  - Config parsing from env vars with defaults (see corrected config table in eng review)
  - Error types per domain using thiserror

  **Patterns to follow:**
  - Standard Rust workspace layout
  - thiserror for library errors, anyhow for CLI/binary errors only

  **Test scenarios:**
  - Happy path: PiiSpan serializes to/from JSON correctly
  - Happy path: GatewayConfig parses from env vars with all defaults
  - Edge case: GatewayConfig with missing required env var (ANTHROPIC_API_KEY) returns clear error
  - Edge case: PiiType enum covers all 7 categories from privacy score weights

  **Verification:** `cargo build --workspace` succeeds. `cargo test -p gateway-common` passes.

- [ ] **Unit 2: PII Eval Harness**

  **Goal:** Standalone binary that loads both models via Ollama, runs a PII benchmark
  dataset, and reports recall/precision/F1 for explicit and implicit PII.

  **Requirements:** R2, R3, R4 (recall thresholds and kill criterion)

  **Dependencies:** Unit 1 (common types)

  **Files:**
  - Create: `crates/gateway-anonymizer/src/detector.rs` (PiiDetector trait)
  - Create: `crates/gateway-anonymizer/src/ollama.rs` (OllamaDetector implementation)
  - Create: `crates/gateway-anonymizer/src/regex.rs` (RegexDetector implementation)
  - Create: `crates/gateway-anonymizer/src/eval.rs` (benchmark runner)
  - Create: `eval/benchmark.jsonl` (PII benchmark dataset: existing datasets + 20 hand-labeled)
  - Create: `eval/run_eval.rs` (standalone eval binary, or as a cargo example)
  - Test: `crates/gateway-anonymizer/tests/detector_test.rs`

  **Execution note:** This is the Week 1 priority. Ship this before any proxy code.
  The eval harness validates whether the product thesis works. If it doesn't, nothing
  else matters.

  **Approach:**
  - PiiDetector trait with `async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>>`
  - OllamaDetector calls ollama-rs with prompt-based JSON (NOT format parameter)
  - System prompt instructs model to output JSON array of PII spans
  - Eval runner loads benchmark.jsonl, runs each prompt through detector, compares
    against labeled spans, computes entity-level recall/precision/F1
  - Separate metrics for explicit vs implicit PII
  - Output: console table with metrics + JSON report file

  **Patterns to follow:**
  - ollama-rs chat API for model interaction
  - serde for JSON parsing of model output
  - Standard precision/recall computation (true positives = overlapping spans with matching type)

  **Test scenarios:**
  - Happy path: OllamaDetector returns correct PiiSpan list for prompt with known PII
  - Happy path: RegexDetector catches email, SSN, phone number patterns
  - Happy path: Eval runner computes correct recall/precision from known inputs
  - Edge case: Model returns empty JSON array (no PII detected)
  - Edge case: Model returns malformed JSON (detector returns error, not panic)
  - Edge case: Model returns PII span with confidence < 0.7 (flagged for escalation)
  - Error path: Ollama unreachable (ConnectionRefused error)
  - Error path: Ollama timeout > 8s (InferenceTimeout error)
  - Integration: Full eval pipeline runs on 3 sample prompts and produces metrics report

  **Verification:** Both models load in Ollama and produce parseable JSON output.
  Eval report shows explicit recall on at least 10 benchmark prompts.

### Week 2-3: Core Anonymization Pipeline

- [ ] **Unit 3: Placeholder Engine + Session Store**

  **Goal:** UUID-based placeholder generation, text substitution, and SQLite session
  persistence for multi-turn entity mapping.

  **Requirements:** R1 (data never leaks), R6 (multi-turn persistence)

  **Dependencies:** Unit 1 (common types)

  **Files:**
  - Create: `crates/gateway-anonymizer/src/placeholder.rs`
  - Create: `crates/gateway-anonymizer/src/session.rs`
  - Test: `crates/gateway-anonymizer/tests/placeholder_test.rs`
  - Test: `crates/gateway-anonymizer/tests/session_test.rs`

  **Approach:**
  - Placeholder format: `[TYPE_xxxxxxxx]` where TYPE is the PII category and xxxxxxxx
    is 8 hex chars from a UUID. Regex pattern: `\[(PERSON|ORG|EMAIL|LOCATION|CREDENTIAL)_[a-f0-9]{8}\]`
  - Substitution: iterate PII spans in reverse order (to preserve positions), replace
    each with its placeholder. Store the mapping.
  - Session store: rusqlite with WAL mode. Table: `sessions(session_id, entity_original,
    entity_placeholder, pii_type, created_at)`. TTL cleanup via background task.
  - Restoration (deanonymization): regex scan response for placeholder pattern, look up
    each in session table, replace with original.

  **Patterns to follow:**
  - rusqlite with tokio::task::spawn_blocking for async compat
  - uuid crate for UUID generation

  **Test scenarios:**
  - Happy path: Single PII entity substituted and restored correctly
  - Happy path: Multiple PII entities in same prompt, all substituted with unique UUIDs
  - Happy path: Multi-turn: entity from turn 1 correctly deanonymized in turn 2 response
  - Edge case: Entity text contains brackets `[]` — escaped before substitution
  - Edge case: Entity text contains quotes or special chars — handled correctly
  - Edge case: Two entities have identical text — get same placeholder (dedup)
  - Edge case: Session TTL expired — mapping returns None, placeholder left in response
  - Error path: SQLite locked — retry 3x with backoff, then error
  - Error path: SQLite disk full — error (fail-closed, surfaces as 503)

  **Verification:** Round-trip test: substitute all PII in a prompt, then restore all
  placeholders in a response. Original text matches exactly.

- [ ] **Unit 4: Proxy Handler + Forwarding**

  **Goal:** Axum HTTP server that intercepts requests, runs the anonymization pipeline,
  forwards to upstream, deanonymizes the response, and returns it.

  **Requirements:** R1, R8, R9

  **Dependencies:** Unit 2 (detector), Unit 3 (placeholder + session)

  **Files:**
  - Create: `crates/gateway-proxy/src/handler.rs`
  - Create: `crates/gateway-proxy/src/middleware.rs` (auto-warm, error handling)
  - Modify: `crates/gateway-proxy/src/main.rs` (server setup, config, Ollama warm)
  - Test: `crates/gateway-proxy/tests/handler_test.rs`
  - Test: `crates/gateway-proxy/tests/integration_test.rs`

  **Approach:**
  - Custom Axum handler (not middleware) that owns the full request/response lifecycle
  - Request path: parse body → detect code blocks → TieredDetector.detect() →
    substitute placeholders → store session → compute score → write audit → forward
  - Response path: buffer full body → regex scan placeholders → restore from session →
    add X-Gateway-Privacy-Score header → return
  - Code block detection: parse markdown fenced blocks (``` and ~~~), pass boundaries
    to detector so it skips PII in code blocks
  - Auto-warm: on server startup, before binding the listen port, send a short test
    prompt to Ollama to trigger model loading. Log "Loading model..." during warm-up.
  - Upstream forwarding via reqwest: copy relevant headers, swap body, forward to
    GATEWAY_UPSTREAM URL. Copy response headers back.

  **Patterns to follow:**
  - Axum handler with State for shared config, detector, session store
  - reqwest::Client with connection pooling for upstream

  **Test scenarios:**
  - Happy path: Full request round-trip with mock Ollama (PII detected, substituted, forwarded, deanonymized)
  - Happy path: Request with no PII — passes through without modification
  - Happy path: Code block containing email address — NOT anonymized
  - Edge case: Empty prompt body — pass through (no model call)
  - Edge case: Non-JSON request body — reject with 400
  - Edge case: Request body too large (>128KB) — reject with 413
  - Edge case: Non-text content type — reject with 415
  - Error path: Ollama unreachable — 503 (fail-closed)
  - Error path: Ollama returns malformed JSON — retry 1x, then 503
  - Error path: Ollama timeout > 8s — 504
  - Error path: Upstream returns 429 — forward 429 with retry-after to client
  - Error path: Upstream returns 401 — forward 401 (bad API key)
  - Integration: Docker compose with real Ollama, send prompt with known PII, verify
    anonymized request reaches upstream mock, deanonymized response reaches client

  **Verification:** `cargo test -p gateway-proxy` passes. Manual test: start server,
  send curl request with PII, verify response is deanonymized correctly.

### Week 4-5: Audit, Score, and Tiered Detection

- [ ] **Unit 5: Audit Trail + Privacy Score**

  **Goal:** Hash-chained JSON audit trail and privacy score computation with weighted
  severity formula.

  **Requirements:** R5, R7

  **Dependencies:** Unit 3 (session store), Unit 4 (proxy handler)

  **Files:**
  - Create: `crates/gateway-anonymizer/src/audit.rs`
  - Create: `crates/gateway-anonymizer/src/score.rs`
  - Test: `crates/gateway-anonymizer/tests/audit_test.rs`
  - Test: `crates/gateway-anonymizer/tests/score_test.rs`

  **Approach:**
  - Audit entry: JSON object with timestamp, session_id, pii_spans (anonymized, no
    original text), placeholders_generated, privacy_score, hash (SHA-256 of entry content),
    prev_hash (hash of previous entry). First entry uses prev_hash = "0" * 64.
  - Append-only: one file per day in GATEWAY_AUDIT_PATH. New entry = append line.
  - Fail-closed: if write fails (disk full, permission), proxy returns 503.
  - Privacy score: `100 - sum(weight[type] * confidence)` per detected entity, capped at 0.
    Weights: PERSON_implicit=15, PERSON_explicit=10, ORG_implicit=8, ORG_explicit=5,
    LOCATION=5, EMAIL/PHONE/SSN=12, CREDENTIAL=20.
  - Score returned in X-Gateway-Privacy-Score response header.

  **Patterns to follow:**
  - sha2 crate for SHA-256
  - serde_json for audit entry serialization
  - Standard append-only log file pattern

  **Test scenarios:**
  - Happy path: Audit entry written with correct hash chain (entry N references hash of entry N-1)
  - Happy path: Privacy score = 100 for prompt with no PII
  - Happy path: Privacy score = 0 (floor) for prompt with many high-weight PII entities
  - Happy path: Privacy score correctly weights implicit PERSON (15) vs explicit ORG (5)
  - Edge case: First audit entry has prev_hash = "000...000"
  - Edge case: Audit entry never contains original PII text (only span positions and types)
  - Error path: Audit file write fails (disk full) — returns AuditDiskFull error
  - Error path: Audit directory doesn't exist — create it on startup

  **Verification:** Write 5 audit entries, read back, verify hash chain is valid
  (each entry's prev_hash matches the hash of the previous entry).

- [ ] **Unit 6: Tiered Detection + Auto-Mode**

  **Goal:** TieredDetector that runs regex + 4B fast model, optionally escalates to 27B
  deep model based on confidence threshold.

  **Requirements:** R2, R3

  **Dependencies:** Unit 2 (detector implementations)

  **Files:**
  - Create: `crates/gateway-anonymizer/src/tiered.rs`
  - Test: `crates/gateway-anonymizer/tests/tiered_test.rs`

  **Approach:**
  - TieredDetector composes RegexDetector + OllamaDetector<Fast> + OllamaDetector<Deep>
  - Always runs: regex pre-scan + 4B fast model
  - Escalation to 27B if: any PII span has confidence < 0.7, OR no PII found and
    prompt > 200 tokens, OR GATEWAY_SCAN_MODE=deep
  - If 27B unavailable (not loaded, error): log warning, return 4B results with
    X-Gateway-Deep-Scan: unavailable header
  - Merges results: dedup overlapping spans, prefer model results over regex when
    they conflict, prefer 27B over 4B for the same span

  **Patterns to follow:**
  - Composition pattern: TieredDetector holds references to sub-detectors
  - Strategy pattern for scan mode (fast/deep/auto)

  **Test scenarios:**
  - Happy path: fast mode — only regex + 4B run, 27B never called
  - Happy path: deep mode — regex + 4B + 27B all run
  - Happy path: auto mode — 4B confidence > 0.7 — no escalation
  - Happy path: auto mode — 4B confidence < 0.7 — escalates to 27B
  - Happy path: auto mode — 0 PII in 300-token prompt — escalates to 27B
  - Edge case: auto mode — 0 PII in 50-token prompt — does NOT escalate (short prompt)
  - Edge case: Overlapping spans from regex and 4B — deduped, model preferred
  - Error path: 27B model unavailable — returns 4B results + warning header
  - Error path: 4B model unavailable — fails with 503 (no detection possible)

  **Verification:** `cargo test -p gateway-anonymizer` passes for all tiered scenarios.

### Week 6-7: CLI + Demo

- [ ] **Unit 7: CLI Tools (Doctor + Split Terminal)**

  **Goal:** `gateway doctor` health check and split terminal demo showing real-time
  anonymization.

  **Requirements:** R11

  **Dependencies:** Unit 4 (proxy running), Unit 5 (audit + score)

  **Files:**
  - Modify: `crates/gateway-cli/src/main.rs` (CLI entry point with subcommands)
  - Create: `crates/gateway-cli/src/doctor.rs`
  - Create: `crates/gateway-cli/src/demo.rs`
  - Test: `crates/gateway-cli/tests/doctor_test.rs`

  **Approach:**
  - `gateway doctor`: checks Ollama reachable, model loaded, SQLite writable, upstream
    reachable (if configured), disk space for audit logs. Output: colored ✓/✗ per check
    plus `--json` flag for programmatic access.
  - `gateway demo`: ratatui split-pane TUI. Left: original prompt. Right: anonymized prompt.
    Bottom bar: privacy score. User types a prompt, sees anonymization in real-time.
    Sends to proxy on localhost (proxy must be running).
  - CLI uses clap for argument parsing. Subcommands: `gateway doctor`, `gateway demo`.

  **Patterns to follow:**
  - ratatui examples for split-pane layout
  - clap derive API for subcommands

  **Test scenarios:**
  - Happy path: doctor reports all green when Ollama + SQLite + proxy are healthy
  - Happy path: doctor reports red ✗ when Ollama is unreachable
  - Happy path: doctor --json outputs valid JSON with check results
  - Edge case: doctor when only some checks pass (mixed ✓/✗)
  - Integration: demo sends a prompt with PII, left pane shows original, right shows anonymized

  **Verification:** `gateway doctor` runs successfully against a healthy local setup.
  `gateway demo` displays the split terminal and processes a prompt.

### Week 7-8: Infrastructure + Polish

- [ ] **Unit 8: Docker + CI/CD + Final Integration**

  **Goal:** Docker compose deployment, GitHub Actions CI/CD, and end-to-end integration
  tests.

  **Requirements:** R9, R10

  **Dependencies:** All previous units.

  **Files:**
  - Create: `Dockerfile` (multi-stage build for gateway-proxy binary)
  - Create: `docker-compose.yml` (standalone: proxy + ollama)
  - Create: `docker-compose.full.yml` (adds cc-gateway)
  - Create: `.github/workflows/ci.yml` (cargo test + clippy + fmt on PR)
  - Create: `.github/workflows/release.yml` (Docker build + push on tag)
  - Create: `README.md`
  - Test: `tests/e2e/docker_compose_test.sh` (shell script E2E test)

  **Approach:**
  - Multi-stage Dockerfile: build stage (rust:latest, cargo build --release), runtime
    stage (debian:slim, copy binary). Small final image.
  - docker-compose.yml: gateway-proxy (port 8443) + gateway-ollama (with model pull on start).
    Health checks: proxy depends on ollama healthy.
  - docker-compose.full.yml: extends docker-compose.yml, adds cc-gateway service.
  - CI: cargo test --workspace, cargo clippy --workspace -- -D warnings, cargo fmt --check
  - Release: on tag push, build Docker image, push to ghcr.io.
  - E2E test: docker compose up, wait for healthy, send curl with known PII, verify
    response is deanonymized, docker compose down.
  - README: quick start, architecture diagram, configuration reference, demo GIF placeholder.

  **Patterns to follow:**
  - Standard multi-stage Rust Dockerfile
  - GitHub Actions for Rust projects

  **Test scenarios:**
  - Happy path: `docker compose up` starts proxy + ollama, health checks pass
  - Happy path: E2E curl with PII — response is correctly deanonymized
  - Happy path: CI pipeline runs tests, clippy, fmt on a sample PR
  - Edge case: docker compose up with no GPU — ollama runs on CPU (slower but works)
  - Edge case: docker compose down cleanly (no orphan processes)
  - Error path: Ollama model not found — health check fails, proxy doesn't start

  **Verification:** `docker compose up` succeeds. E2E test passes. CI workflow runs green.

## System-Wide Impact

- **Interaction graph:** Client → Proxy handler → [Regex + Ollama + SQLite] → Upstream provider.
  No callbacks, observers, or middleware beyond the Axum handler. Clean request/response cycle.
- **Error propagation:** All internal errors map to HTTP status codes (400, 413, 415, 429,
  500, 502, 503, 504). No silent failures except deanonymization when LLM paraphrases
  placeholders (logged as warning).
- **State lifecycle risks:** SQLite session mappings have TTL. Audit logs are append-only.
  No caches to invalidate. No distributed state.
- **API surface parity:** Phase 1 supports Anthropic API format only. Phase 2 adds OpenAI.
  The proxy is transparent: it preserves all request/response structure, only modifying
  the prompt content field.
- **Integration coverage:** E2E docker compose test covers the full stack. Unit tests cover
  individual components. The gap is the deanonymization reliability (LLM may paraphrase
  placeholders — known, logged, deferred to Phase 2 model-assisted fallback).
- **Unchanged invariants:** The upstream API contract is not modified. The proxy adds
  headers (X-Gateway-Privacy-Score, X-Gateway-Session, X-Gateway-Deep-Scan) but does
  not remove or alter existing headers.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| MTBS/anonymizer doesn't hit 90% explicit recall | Benchmark in Week 1-2. Fallback: convert AnonymizerSLM to GGUF, or try Presidio-style NER |
| Qwen3.5-27B doesn't hit 70% implicit recall | Week 4 kill gate. Fallback: try Llama 3.x, Mistral. If all fail, pivot product to explicit-only. |
| Ollama structured output bug worsens | Using prompt-based JSON, not format parameter. Independent of bug. |
| Ollama removes/renames MTBS/anonymizer | Pin model version. Maintain local GGUF backup. |
| cc-gateway breaking change | Standalone is default. cc-gateway is optional compose add-on. |
| 8-week timeline for full scope | Week 1-2 gates (model loads, eval works). If blocked, descope TUI and doctor to Phase 1.5. |
| Deanonymization silent failure (LLM paraphrases) | Logged as warning. Phase 2 adds model-assisted fallback. Phase 1 accepts this known limitation. |

## Sources & References

- **Origin document:** [CEO Plan](~/.gstack/projects/gateway/ceo-plans/2026-04-09-privacy-gateway.md)
- **Eng review:** [Plan file](/home/louis/.claude/plans/radiant-drifting-sundae.md)
- **Design doc:** [Office Hours v2](~/.gstack/projects/gateway/louis-unknown-design-20260406-114102.md)
- Related: [CloakPipe](https://cloakpipe.co/), [AnonymizerSLM](https://huggingface.co/blog/pratyushrt/anonymizerslm)
- Related: [Ollama Issue #15260](https://github.com/ollama/ollama/issues/15260)
- Related: [LOPSIDED arXiv 2510.27016](https://arxiv.org/abs/2510.27016)
