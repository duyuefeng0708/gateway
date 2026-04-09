---
title: "feat: Privacy Gateway Phase 2 — Production Hardening + Platform Features"
type: feat
status: active
date: 2026-04-09
origin: ~/.gstack/projects/gateway/ceo-plans/2026-04-09-privacy-gateway.md
---

# Privacy Gateway Phase 2 — Production Hardening + Platform Features

## Overview

Harden the Phase 1 proxy for production use and add platform features. Key deliverables:
streaming SSE deanonymization, OpenAI API compatibility, Privacy-as-a-Service API endpoints,
YAML-based custom PII rules, smart model routing via privacy score, Prometheus metrics,
and a one-line install script. Target: 50+ concurrent users with acceptable latency.

## Problem Frame

Phase 1 ships a working anonymization proxy but with limitations that block production use:
non-streaming responses add visible latency, only Anthropic API format is supported, no
observability beyond logs, and no way for enterprises to define domain-specific PII patterns.
Phase 2 closes these gaps while adding platform features (Privacy API, routing) that
differentiate from CloakPipe.

(see origin: CEO plan, Phase 2 section)

## Requirements Trace

- R1. Streaming SSE: deanonymize response tokens as they arrive, not after full buffer
- R2. OpenAI API compatibility: detect and handle both Anthropic and OpenAI request/response formats
- R3. Privacy API: POST /v1/anonymize and POST /v1/deanonymize as standalone endpoints
- R4. Custom PII rules: YAML files loaded at startup, matched alongside model detection
- R5. Smart routing: route requests to different upstream providers based on privacy score
- R6. Prometheus metrics: request count, latency histograms, PII detection rates, error counts
- R7. Prompt enhancement: optional second model call to improve prompt quality (separate from PII)
- R8. One-line install: `curl | sh` installer that detects OS, pulls binary + model
- R9. Connection pooling and graceful degradation under load
- R10. Performance gate: 50+ concurrent users at acceptable latency (< 500ms proxy overhead excluding model inference)

## Scope Boundaries

- Phase 2 only (Weeks 9-14)
- No eBPF (Phase 3)
- No enterprise management UI (Phase 4)
- No multi-provider routing UI, routing is config-file based
- vLLM integration is a stretch goal, not a hard requirement (Ollama may suffice)
- Prompt enhancement is the lowest priority feature, can be deferred if time is tight

## Context & Research

### Relevant Code and Patterns

- `crates/gateway-proxy/src/handler.rs` — Current non-streaming handler. Must be refactored for streaming.
- `crates/gateway-anonymizer/src/tiered.rs` — TieredDetector. Plugin rules merge into this pipeline.
- `crates/gateway-anonymizer/src/placeholder.rs` — substitute/restore. Streaming restore needs a new streaming variant.
- `crates/gateway-common/src/config.rs` — GatewayConfig. New env vars for routing, plugins, metrics.
- `crates/gateway-common/src/types.rs` — PrivacyScore with classification (LOW/MEDIUM/HIGH). Used by routing.
- `ollama-rs` has `stream` feature already enabled in workspace Cargo.toml.

### Institutional Learnings

- **Ollama structured output bug (#15260):** Prompt-based JSON, not format parameter. Still applies.
- **axum-reverse-proxy rejected:** Custom handler pattern continues for Phase 2.
- **Streaming SSE buffering strategy** defined in CEO plan: buffer on `[`, flush on `]` match or 32-char/500ms timeout.

## Key Technical Decisions

- **Streaming via Axum's streaming response + tokio channels:** The handler writes SSE chunks to a channel sender. A background task reads upstream SSE, deanonymizes token-by-token using the sliding buffer, and sends deanonymized chunks to the channel. The Axum response reads from the channel receiver.

- **OpenAI detection by request path:** `/v1/chat/completions` = OpenAI format. `/v1/messages` = Anthropic format. The handler dispatches to format-specific extractors/rebuilders. Core anonymization logic stays format-agnostic.

- **Privacy API as additional Axum routes, same server:** No separate service. `/v1/anonymize` and `/v1/deanonymize` are new routes on the existing Axum server. They reuse the same detector and session store. Simpler deployment.

- **Plugin rules as a new PiiDetector implementation:** `RuleDetector` loads YAML files at startup, compiles regex patterns and keyword lists. It implements PiiDetector and is composed into TieredDetector alongside regex and model detectors.

- **Routing via config file, not database:** `routing.yaml` maps privacy score bands to upstream URLs. Loaded at startup. No runtime changes without restart (Phase 4 adds dynamic routing via management UI).

- **Prometheus via `metrics` + `axum-prometheus` crates:** Standard approach for Rust services. `/metrics` endpoint.

## Open Questions

### Resolved During Planning

- **Where do Privacy API routes live?** Same Axum server, new route handlers in a `privacy_api.rs` module.
- **How does streaming deanonymization interact with sessions?** Session placeholders are loaded once at request start (before streaming begins). The streaming deanonymizer holds the placeholder map in memory during the stream.
- **Does OpenAI compatibility affect PII detection?** No. The format-specific layer extracts raw text from messages. The anonymization pipeline receives raw text regardless of API format.

### Deferred to Implementation

- Exact `routing.yaml` schema (depends on how many upstream providers to support initially)
- vLLM HTTP API differences from Ollama (investigate during implementation)
- Prompt enhancement system prompt design (depends on model behavior)
- Install script OS detection heuristics (macOS vs Linux vs WSL)

## Implementation Units

### Production Hardening

- [ ] **Unit 1: Prometheus Metrics + Connection Pooling**

  **Goal:** Add observability and optimize HTTP client for concurrent load.

  **Requirements:** R6, R9, R10

  **Dependencies:** None (independent of other units)

  **Files:**
  - Modify: `Cargo.toml` (add metrics, axum-prometheus deps)
  - Modify: `crates/gateway-proxy/Cargo.toml`
  - Create: `crates/gateway-proxy/src/metrics.rs`
  - Modify: `crates/gateway-proxy/src/main.rs` (add /metrics route, init metrics)
  - Modify: `crates/gateway-proxy/src/handler.rs` (instrument with counters/histograms)
  - Test: `crates/gateway-proxy/tests/metrics_test.rs`

  **Approach:**
  - Add `metrics` and `metrics-exporter-prometheus` crates to workspace
  - Define counters: `gateway_requests_total` (by status, method), `gateway_pii_detected_total` (by type), `gateway_errors_total` (by error kind)
  - Define histograms: `gateway_request_duration_seconds` (total), `gateway_model_inference_seconds`, `gateway_upstream_duration_seconds`
  - Define gauges: `gateway_active_connections`, `gateway_session_count`
  - `/metrics` route returns Prometheus text format
  - reqwest Client: increase pool_max_idle_per_host to 32, set pool_idle_timeout to 90s
  - Add tracing spans for request lifecycle phases

  **Patterns to follow:**
  - Existing handler.rs structure for adding metric instrumentation
  - Standard Prometheus naming conventions

  **Test scenarios:**
  - Happy path: `/metrics` endpoint returns valid Prometheus text format with expected metric names
  - Happy path: Request counter increments after a proxied request
  - Happy path: PII detection counter increments by type
  - Integration: Send 5 requests, verify histogram has 5 observations

  **Verification:** `/metrics` returns data. `cargo test -p gateway-proxy` passes.

### API Expansion

- [ ] **Unit 2: OpenAI API Compatibility**

  **Goal:** Handle both Anthropic and OpenAI request/response formats transparently.

  **Requirements:** R2

  **Dependencies:** None

  **Files:**
  - Create: `crates/gateway-proxy/src/format.rs` (API format detection and conversion)
  - Modify: `crates/gateway-proxy/src/handler.rs` (use format module for extraction/rebuild)
  - Modify: `crates/gateway-proxy/src/lib.rs` (add format module)
  - Modify: `crates/gateway-common/src/config.rs` (GATEWAY_UPSTREAM_OPENAI env var)
  - Test: `crates/gateway-proxy/tests/format_test.rs`

  **Approach:**
  - Detect API format by request path: `/v1/chat/completions` = OpenAI, `/v1/messages` = Anthropic
  - Define trait `ApiFormat` with methods: `extract_messages(body) -> Vec<MessageContent>`, `rebuild_body(body, anonymized_messages) -> Bytes`, `extract_response_content(body) -> String`
  - `AnthropicFormat` and `OpenAiFormat` implementations
  - Handler uses format-agnostic message extraction, anonymizes, then format-specific rebuild
  - Config adds `GATEWAY_UPSTREAM_OPENAI` (default: `https://api.openai.com`) alongside existing Anthropic upstream

  **Patterns to follow:**
  - Existing handler.rs message extraction logic (move to AnthropicFormat)

  **Test scenarios:**
  - Happy path: Anthropic format request `/v1/messages` with PII → anonymized correctly
  - Happy path: OpenAI format request `/v1/chat/completions` with PII → anonymized correctly
  - Happy path: OpenAI response format deanonymized correctly
  - Edge case: Unknown path → fallback to Anthropic format (backward compat)
  - Edge case: OpenAI multi-turn messages (system + user + assistant array)
  - Error path: Malformed OpenAI body → 400

  **Verification:** Existing Anthropic tests still pass. New OpenAI tests pass.

- [ ] **Unit 3: Privacy-as-a-Service API**

  **Goal:** Standalone anonymization endpoints that other systems can call directly.

  **Requirements:** R3

  **Dependencies:** None

  **Files:**
  - Create: `crates/gateway-proxy/src/privacy_api.rs`
  - Modify: `crates/gateway-proxy/src/main.rs` (add routes)
  - Modify: `crates/gateway-proxy/src/lib.rs`
  - Test: `crates/gateway-proxy/tests/privacy_api_test.rs`

  **Approach:**
  - `POST /v1/anonymize`: accepts `{"text": "...", "session_id": "optional"}`, returns `{"anonymized": "...", "session_id": "...", "score": 85, "spans": [...]}`
  - `POST /v1/deanonymize`: accepts `{"text": "...", "session_id": "..."}`, returns `{"restored": "..."}`
  - Both reuse existing detector, placeholder, and session store
  - No upstream forwarding (these are utility endpoints)
  - Session ID is optional for anonymize (auto-generated if missing), required for deanonymize

  **Patterns to follow:**
  - Existing handler.rs for AppState access and error handling

  **Test scenarios:**
  - Happy path: Anonymize text with PII → returns anonymized text + spans + score
  - Happy path: Deanonymize with valid session → restores original
  - Happy path: Anonymize then deanonymize round-trip
  - Edge case: Anonymize with no PII → returns original text, score 100
  - Edge case: Deanonymize with unknown session → 404
  - Error path: Missing session_id on deanonymize → 400

  **Verification:** Privacy API endpoints work independently of the proxy flow.

### Streaming

- [ ] **Unit 4: Streaming SSE Deanonymization**

  **Goal:** Stream responses back to the client in real-time, deanonymizing placeholder tokens as they arrive.

  **Requirements:** R1

  **Dependencies:** Unit 2 (OpenAI format, since both Anthropic and OpenAI use SSE)

  **Files:**
  - Create: `crates/gateway-anonymizer/src/streaming.rs`
  - Modify: `crates/gateway-anonymizer/src/lib.rs`
  - Modify: `crates/gateway-proxy/src/handler.rs` (add streaming path)
  - Modify: `crates/gateway-common/src/config.rs` (GATEWAY_STREAMING env var)
  - Test: `crates/gateway-anonymizer/tests/streaming_test.rs`
  - Test: `crates/gateway-proxy/tests/streaming_test.rs`

  **Approach:**
  - Client sends `"stream": true` in request body → proxy detects and enables streaming
  - Request path unchanged: full body buffered, anonymized, forwarded with `stream: true`
  - Response path: proxy reads SSE chunks from upstream, feeds each to StreamingDeanonymizer
  - StreamingDeanonymizer holds placeholder map + a token buffer
  - Buffer logic: on `[`, start buffering. On `]` within 32 chars, check if buffer matches placeholder pattern. If match, replace and flush. If buffer exceeds 32 chars or 500ms timeout, flush as-is.
  - Axum returns `Sse<impl Stream<Item = Event>>` using tokio channel
  - Non-streaming requests continue to use the existing buffered path (backward compat)
  - Config: `GATEWAY_STREAMING=true` (default true in Phase 2)

  **Patterns to follow:**
  - Existing placeholder::restore for the matching regex pattern
  - Axum SSE example patterns
  - ollama-rs stream feature for SSE parsing patterns

  **Test scenarios:**
  - Happy path: SSE stream with no placeholders → chunks pass through unchanged
  - Happy path: SSE stream with complete placeholder in one chunk → deanonymized in-place
  - Happy path: SSE stream with placeholder split across chunks `[PER` + `SON_abc123]` → buffered, then deanonymized
  - Edge case: Buffer exceeds 32 chars without `]` → flushed as-is
  - Edge case: Buffer timeout (500ms) → flushed as-is
  - Edge case: Nested brackets `[[` → outer buffer flushed immediately
  - Edge case: Non-ASCII in buffer → flushed immediately
  - Edge case: `stream: false` in request → uses buffered path (existing behavior)
  - Error path: Upstream SSE connection drops mid-stream → stream ends cleanly with error event

  **Verification:** Send a streaming request, verify tokens arrive incrementally with placeholders deanonymized.

### Intelligence

- [ ] **Unit 5: Custom PII Rules (YAML Plugin System)**

  **Goal:** Let users define domain-specific PII patterns via YAML files that run alongside model detection.

  **Requirements:** R4

  **Dependencies:** None

  **Files:**
  - Create: `crates/gateway-anonymizer/src/rules.rs`
  - Modify: `crates/gateway-anonymizer/src/lib.rs`
  - Modify: `crates/gateway-anonymizer/src/tiered.rs` (add RuleDetector to composition)
  - Modify: `crates/gateway-common/src/config.rs` (GATEWAY_RULES_PATH env var)
  - Modify: `Cargo.toml` (add serde_yaml workspace dep)
  - Create: `examples/rules/sample.yaml`
  - Test: `crates/gateway-anonymizer/tests/rules_test.rs`

  **Approach:**
  - YAML schema: list of rules, each with `name`, `type` (PII category), `patterns` (list of regex), `keywords` (list of exact strings), `confidence` (default 0.9)
  - RuleDetector loads YAML at startup, compiles regex patterns
  - Implements PiiDetector trait: scans text for all rule patterns + keywords
  - TieredDetector gains an optional `rules: Option<RuleDetector>` field
  - Rules run in parallel with regex pre-scan (both are fast, sub-millisecond)
  - Span merging already handles dedup between rule results and model results

  **Patterns to follow:**
  - RegexDetector pattern for scan_pattern method
  - TieredDetector composition pattern

  **Test scenarios:**
  - Happy path: YAML with regex rule → detects matching text as PII
  - Happy path: YAML with keyword rule → detects exact keyword match
  - Happy path: Multiple rules in one file, all applied
  - Edge case: Empty rules file → no additional detections
  - Edge case: Invalid regex in YAML → skip that rule, log warning, don't crash
  - Edge case: Rule with same span as model detection → deduped by merge_spans
  - Error path: YAML file not found → log warning, continue without rules
  - Error path: Malformed YAML → log warning, continue without rules

  **Verification:** Custom rules detect domain-specific PII that regex and model would miss.

- [ ] **Unit 6: Smart Model Routing**

  **Goal:** Route requests to different upstream providers based on privacy score.

  **Requirements:** R5

  **Dependencies:** Unit 2 (OpenAI format, for multi-provider routing)

  **Files:**
  - Create: `crates/gateway-proxy/src/routing.rs`
  - Create: `routing.yaml` (default config)
  - Modify: `crates/gateway-proxy/src/handler.rs` (use router for upstream selection)
  - Modify: `crates/gateway-proxy/src/state.rs` (add Router to AppState)
  - Modify: `crates/gateway-common/src/config.rs` (GATEWAY_ROUTING_CONFIG env var)
  - Test: `crates/gateway-proxy/tests/routing_test.rs`

  **Approach:**
  - `routing.yaml` schema: list of routes, each with `score_range` (e.g., `0-49`, `50-89`, `90-100`), `upstream_url`, `api_format` (anthropic/openai), `api_key_env`
  - Router loads config at startup, validates score ranges don't overlap
  - After PII detection + score computation, router selects upstream based on score
  - If no routing config: use default GATEWAY_UPSTREAM (backward compat)
  - Handler calls router.select(score) to get upstream URL + format

  **Patterns to follow:**
  - Existing config parsing pattern for YAML loading

  **Test scenarios:**
  - Happy path: Score 95 → routes to direct (LOW band)
  - Happy path: Score 40 → routes to primary with full anonymization (HIGH band)
  - Happy path: No routing config → uses default upstream (backward compat)
  - Edge case: Score exactly on boundary (50) → matches MEDIUM band
  - Edge case: Overlapping score ranges in config → reject at startup with clear error
  - Error path: Routing config file not found → use default upstream, log warning

  **Verification:** Different privacy scores route to different upstreams.

### Infrastructure

- [ ] **Unit 7: One-Line Install Script**

  **Goal:** `curl -sSf https://gateway.dev/install | sh` installs the gateway binary and pulls the model.

  **Requirements:** R8

  **Dependencies:** Unit 1 (needs the Docker/binary artifacts to exist)

  **Files:**
  - Create: `scripts/install.sh`
  - Modify: `README.md` (add install instructions)
  - Test: Manual testing (shell scripts don't unit test well)

  **Approach:**
  - Detect OS (Linux, macOS, WSL)
  - Detect architecture (amd64, arm64)
  - Check for Docker (required for Ollama sidecar)
  - Download pre-built binary from GitHub Releases (or fall back to Docker image)
  - Pull Ollama model: `docker pull ollama/ollama && docker run ... ollama pull MTBS/anonymizer`
  - Create default config directory and env file
  - Print getting-started instructions
  - macOS: configure system proxy via `networksetup` (optional, prompted)
  - Linux: print `HTTPS_PROXY` export command

  **Patterns to follow:**
  - Tailscale installer, rustup installer for UX patterns

  **Test scenarios:**
  - Happy path: Script detects Linux amd64, downloads binary, pulls model
  - Edge case: Docker not installed → clear error message with install instructions
  - Edge case: No GPU → warn that inference will be slow on CPU

  **Verification:** Run script on a clean Linux VM, verify gateway starts.

- [ ] **Unit 8: Prompt Enhancement (Stretch)**

  **Goal:** Optional second model call that improves prompt quality before forwarding.

  **Requirements:** R7

  **Dependencies:** Unit 4 (streaming, since enhancement modifies the request path)

  **Files:**
  - Create: `crates/gateway-anonymizer/src/enhance.rs`
  - Modify: `crates/gateway-anonymizer/src/lib.rs`
  - Modify: `crates/gateway-proxy/src/handler.rs` (add enhancement step after anonymization)
  - Modify: `crates/gateway-common/src/config.rs` (GATEWAY_ENHANCE env var)
  - Test: `crates/gateway-anonymizer/tests/enhance_test.rs`

  **Execution note:** This is the lowest priority unit. Defer if time is tight.

  **Approach:**
  - Prompt enhancer calls a second Ollama model (can be the same 27B model)
  - System prompt instructs model to improve clarity, structure, and context of the anonymized prompt
  - Runs AFTER PII anonymization (so the model never sees raw PII)
  - Returns improved prompt text, which replaces the anonymized text before forwarding
  - Config: `GATEWAY_ENHANCE=true|false` (default false)
  - Adds latency: another model call (2-5s). Only recommended for deep-scan mode users who already accept latency.

  **Test scenarios:**
  - Happy path: Enhancement enabled, prompt is improved (mock model returns enhanced text)
  - Happy path: Enhancement disabled → prompt passes through unchanged
  - Edge case: Enhancement model unavailable → skip enhancement, use original, log warning
  - Edge case: Enhancement returns empty text → use original prompt

  **Verification:** Enhanced prompts pass through the full pipeline without breaking anonymization.

## System-Wide Impact

- **Interaction graph:** Streaming adds a tokio channel between handler and response. Privacy API adds new Axum routes. Routing adds upstream selection. Plugin rules add to the detection pipeline. All changes flow through the existing AppState/handler architecture.
- **Error propagation:** Streaming errors (upstream disconnect) must cleanly close the SSE stream. Plugin rule errors are non-fatal (log + skip). Routing errors fall back to default upstream.
- **State lifecycle:** Streaming requires session placeholders to be loaded before the stream starts and held in memory for the stream duration. Plugin rules are loaded once at startup (no hot-reload in Phase 2).
- **API surface parity:** Both Anthropic and OpenAI formats must support streaming and non-streaming. Privacy API works with raw text (format-agnostic).
- **Unchanged invariants:** The fail-closed iron rule still holds. All Phase 1 tests must continue to pass. The audit trail format is unchanged. The privacy score computation is unchanged.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Streaming deanonymization edge cases (split tokens, timeouts) | Extensive test suite with fuzzy inputs. Fallback to buffered mode on error. |
| OpenAI format differences across versions | Support v1/chat/completions only. Document supported versions. |
| Plugin YAML parsing errors at startup | Non-fatal: log warning, continue without rules. |
| Performance under 50+ concurrent users | Benchmark with `wrk` or `oha`. Connection pooling + metrics to identify bottlenecks. |
| vLLM API differences from Ollama | Defer vLLM to Phase 2.5 if Ollama performs adequately. |
| Prompt enhancement quality | Lowest priority unit. Ship without it if quality is poor. |

## Phased Delivery

### Phase 2a (Weeks 9-11): Production hardening + API expansion
- Unit 1: Metrics + connection pooling
- Unit 2: OpenAI compatibility
- Unit 3: Privacy API
- Unit 5: Custom PII rules

### Phase 2b (Weeks 12-14): Streaming + intelligence
- Unit 4: Streaming SSE deanonymization
- Unit 6: Smart routing
- Unit 7: Install script
- Unit 8: Prompt enhancement (stretch)

## Sources & References

- **Origin document:** [CEO Plan](~/.gstack/projects/gateway/ceo-plans/2026-04-09-privacy-gateway.md)
- **Phase 1 plan:** [docs/plans/2026-04-09-001-feat-privacy-gateway-phase1-plan.md](docs/plans/2026-04-09-001-feat-privacy-gateway-phase1-plan.md)
- Related: Axum SSE streaming examples
- Related: Prometheus Rust metrics crates
