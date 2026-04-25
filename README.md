# Privacy Gateway

A Rust reverse proxy that anonymizes PII in LLM API requests using tiered local model detection, forwards sanitized prompts to cloud providers, and deanonymizes responses -- so you get full-quality AI output without exposing private data.

## Architecture

```
                        ┌──────────────────────────────┐
                        │       Privacy Gateway        │
                        │                              │
  Client ──HTTPS──▶     │  Axum Handler                │
                        │    ├─ Regex pre-scan         │     ┌─────────────┐
                        │    ├─ 4B fast model ─────────│────▶│   Ollama    │
                        │    ├─ 27B deep model (auto) ─│────▶│  (sidecar)  │
                        │    ├─ UUID placeholders       │     └─────────────┘
                        │    ├─ SQLite session store    │
                        │    ├─ Privacy score           │
                        │    └─ Hash-chained audit log  │
                        │                              │
                        │  Forward (anonymized) ───────│────▶ Upstream LLM API
                        │  Return  (deanonymized) ◀────│────  (Anthropic, etc.)
                        └──────────────────────────────┘
```

**Detection tiers:**
- **Regex** -- emails, SSNs, phone numbers, API keys (sub-millisecond)
- **4B fast model** -- explicit PII via `gemma4:e4b` on Ollama (sub-second)
- **27B deep model** -- implicit PII via `gemma4:26b` reasoning (opt-in, see [Scan modes](#scan-modes))

## Quick Start

**One-line install** (downloads binary, starts Ollama, pulls PII model):

```bash
curl -sSf https://gateway.dev/install | sh
```

The installer pulls only the 4B fast model (`gemma4:e4b`) by default. To also pull the 18GB deep model for implicit-PII coverage, pass `--with-deep` (or set `GATEWAY_INSTALL_DEEP=1`). Most laptop users should stick with the default -- see [Laptop vs GPU](#laptop-vs-gpu).

Or run manually with Docker Compose:

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-...

# Start the gateway + Ollama sidecar. Defaults to scan_mode=fast:
# regex + gemma4:e4b only, ~3s per request, implicit PII is NOT caught.
docker compose up -d

# Wait for warm-up to complete. /ready flips to 200 once the fast model
# is loaded and the warm-up probe has succeeded once.
until curl -fsS http://localhost:8443/ready >/dev/null; do sleep 2; done

# Send a request through the proxy
curl -X POST http://localhost:8443/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":256,"messages":[{"role":"user","content":"My name is Alice and I live in Portland."}]}'

# Confirm anonymization actually ran
curl -sS http://localhost:8443/metrics | grep gateway_detector_tier_used
# Expect: gateway_detector_tier_used{tier="fast"} 1
```

### Use with Claude Code

Claude Code respects two env vars that let you route all traffic through
the gateway without changing any application code:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8443
export ANTHROPIC_API_KEY=sk-...   # your real Anthropic key

# Normal Claude Code workflows now flow through the gateway.
# The gateway strips PII before forwarding to api.anthropic.com and
# restores placeholders in the streamed response before Claude Code
# sees it. Claude Code never observes the raw PII and the model never
# observes the placeholders.
claude

# In another terminal, watch the tier metric increment on each turn:
watch -n 1 'curl -sS http://localhost:8443/metrics | grep gateway_detector_tier_used'
```

Unset the vars (`unset ANTHROPIC_BASE_URL`) to bypass the gateway.

### End-to-end demo: observe a placeholder round-trip

The `/v1/anonymize` and `/v1/deanonymize` endpoints let you see the
substitution without a full model call. Useful as a smoke test or to
show a teammate what the gateway actually does:

```bash
# 1. Anonymize — returns session_id, placeholders, and privacy score.
ANON=$(curl -sS -X POST http://localhost:8443/v1/anonymize \
  -H 'Content-Type: application/json' \
  -d '{"text":"My name is Alice Chen and my email is alice@acme.com."}')
echo "$ANON" | jq .

# 2. Grab the anonymized text + session id.
SESSION=$(echo "$ANON" | jq -r .session_id)
ANON_TEXT=$(echo "$ANON" | jq -r .anonymized)
echo "anonymized: $ANON_TEXT"
# anonymized: My name is [PERSON_abcd1234] and my email is [EMAIL_ef567890].

# 3. Deanonymize — restores the original text using session placeholders.
curl -sS -X POST http://localhost:8443/v1/deanonymize \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\",\"text\":\"$ANON_TEXT\"}" | jq .
# {"text": "My name is Alice Chen and my email is alice@acme.com."}
```

This is the same mechanism that runs invisibly around every Claude Code
request -- except that in the proxied path the `anonymized` text is what
api.anthropic.com sees, and the `deanonymize` step runs on the response
stream before it reaches your terminal.

## Scan modes

Tiered detection is controlled by `GATEWAY_SCAN_MODE`:

| Mode | Pipeline | Latency (laptop CPU) | Latency (H100) | When to use |
|---|---|---|---|---|
| `fast` *(default)* | regex + `gemma4:e4b` | ~3s/request | ~3s/request | Interactive use; misses implicit PII |
| `auto` | regex + `gemma4:e4b`, escalates to `gemma4:26b` on uncertainty | ~86s/request when escalated | ~17s/request when escalated | Best accuracy/latency tradeoff on GPU |
| `deep` | regex + `gemma4:26b` on every request | ~86s/request | ~17s/request | Maximum recall; GPU only |

Silent fallback is the accepted posture: if the deep tier fails or times out, the gateway emits a metric and returns fast-tier spans instead of erroring. Raise `GATEWAY_DETECTION_TIMEOUT` (default 8s) if you want deep results to actually land on a laptop.

## Laptop vs GPU

On a laptop with no GPU, **keep `GATEWAY_SCAN_MODE=fast`** (the default). The deep tier's 27B model runs at CPU speed and will not return before `GATEWAY_DETECTION_TIMEOUT` (8s) expires -- detections will silently fall back to fast-only spans.

To experiment with implicit PII detection on a laptop:

```bash
export GATEWAY_SCAN_MODE=auto
export GATEWAY_DETECTION_TIMEOUT=120
```

Expect **~86s per message** with the deep tier actually firing. This is not for interactive use; it is only for one-off evaluation. On an H100 the same pipeline lands at ~17s per message, which matches the marketing claims.

## Observability and alerts

The proxy exposes Prometheus metrics for tiered-detection behaviour. The one you must alert on is the silent-fallback signal:

```
gateway_deep_tier_attempted_total - gateway_deep_tier_succeeded_total
```

If this value is growing, deep-tier detections are failing (timeout, model not loaded, Ollama unreachable) and the gateway is silently falling back to fast-only spans. Implicit PII is being missed. Common causes: the 18GB deep model wasn't pulled (`install.sh` without `--with-deep`), `GATEWAY_DETECTION_TIMEOUT` is too low for the hardware, or Ollama is under load.

Run `gateway doctor` to verify that the configured models are actually loaded in Ollama -- when `scan_mode` is `auto` or `deep`, the deep-model check is included; in `fast` mode it is skipped.

### Liveness and readiness

The proxy exposes `GET /ready`:

* **503 `warming`** — listener is bound but the startup warm-up probe has not yet succeeded. Safe to route traffic through (fast tier still works) but deep-tier calls are likely to silent-fallback until the model is loaded.
* **200 `ok`** — warm-up probe succeeded. Normal operating state.

`docker-compose.yml` wires this endpoint into the `gateway-proxy` service's healthcheck. `gateway-ebpf` waits for `gateway-proxy` to reach `service_healthy` before installing its cgroup hooks, so transparent interception never starts against a cold proxy. A one-shot `gateway-ollama-pull` sidecar pre-pulls `$GATEWAY_FAST_MODEL` (and `$GATEWAY_DEEP_MODEL` when `scan_mode` is `auto` or `deep`) before the proxy depends-on fires, so `docker compose up` is a genuine end-to-end boot rather than a race against model download.

To run with cc-gateway as the upstream instead of Anthropic directly:

```bash
docker compose -f docker-compose.full.yml up
```

## Receipts and tamper-evidence

Every successful proxy request produces a **tamper-evident record** of what the gateway did with it. The gateway returns the record's id via the `x-gateway-receipt` response header; the full record is retrievable at `GET /v1/receipts/{id}`.

A receipt looks like:

```json
{
  "request_id": "4c1f8a52-3b...",
  "timestamp": "2026-04-25T14:33:01Z",
  "client_requested_model": "claude-sonnet-4-20250514",
  "upstream_requested_model": "claude-sonnet-4-20250514",
  "detector_fast_model": "gemma4:e4b",
  "prompt_hmac": "abf3e2...",
  "hmac_key_id": "primary",
  "response_hash_status": "pending",
  "anchor_status": "anchored",
  "rekor_uuid": "24296...",
  "log_index": 12345678,
  "hash_recipe": "audit-v2-canonical-json",
  "hash": "sha256...",
  "prev_hash": "sha256...",
  "signing_key_id": "primary",
  "signature_alg": "ed25519"
}
```

Each entry's `hash` is computed over canonical-JSON of every field except `hash` itself, and the chain of `prev_hash` pointers links every entry back to the proxy's first record. Periodically (every `GATEWAY_REKOR_ANCHOR_INTERVAL`, default 15 min) the gateway publishes a Merkle root over recent chain heads to [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) — once `anchor_status` flips to `anchored`, anyone can confirm the entry was integrated into the public log.

### What receipts prove

* The bytes the gateway forwarded to the upstream produced exactly the digest stored in `prompt_hmac`, under the key identified by `hmac_key_id`. (Keyed digest defeats confirmation attacks against bare hashes.)
* The chain of receipts is internally consistent — no entry can be inserted, removed, or modified after the fact without breaking the chain.
* Anchored entries were integrated into Rekor's public log at `integrated_time`. A third party can verify with `rekor-cli get --uuid <rekor_uuid>`.

### What receipts do NOT prove

* That **PII removal was correct**. The receipt records *that* anonymization happened and how many spans were detected; it does not certify the spans were complete or accurate. The 100+ prompt benchmark in `eval/` is where coverage is measured.
* That the **upstream model was genuine**. The gateway sees what the upstream API returns; it has no way to attest that Anthropic's response actually came from Claude vs a swapped backend. The canary fingerprint in PR-B (separate roadmap item) addresses this probabilistically.
* That the **response was delivered to the client unchanged**. A hostile reverse proxy between gateway and client could rewrite the body. Receipts are proof of what the gateway *recorded*, not what the client received.

In other words, receipts are **tamper-evident audit records anchored to a public log**, not attestations of semantic truth. Treat them accordingly.

### Verifying a receipt

Save the receipt to a file:

```bash
curl -sS http://localhost:8443/v1/receipts/$RECEIPT_ID > receipt.json
```

Run the offline verifier:

```bash
gateway verify ./receipt.json
# Verifying receipt for request_id: 4c1f8a52-3b...
#   Hash recipe: audit-v2-canonical-json
#   Chain prev:  abc12345...90abcdef
#   Chain hash:  def67890...12fedcba
#   Hash recompute:           OK
#   HMAC key id (primary):    OK
#   Anchor status:            Anchored
#   Rekor uuid:               24296fb24b...
#   Verify on Rekor with:     rekor-cli get --uuid 24296fb24b...
#
# RECEIPT VERIFIED.
# Note: this confirms the gateway's chain is internally consistent.
# It does NOT prove PII removal, model authenticity, or response integrity.
```

Anyone with the receipt and the gateway operator's HMAC key id can run this. The Rekor inclusion proof can be checked independently with [`rekor-cli`](https://github.com/sigstore/rekor) — no trust in the gateway operator required.

### Operator setup

The receipt subsystem requires three new environment variables:

| Variable | Required | Description |
|---|---|---|
| `GATEWAY_HMAC_KEY` (hex) or `GATEWAY_HMAC_KEY_FILE` | yes | At least 32 bytes of high-entropy random data. Used to compute prompt/response digests. Rotate by setting a new key + new id; old receipts continue to validate against archived keys. |
| `GATEWAY_HMAC_KEY_ID` | no (default `primary`) | Stable identifier for the HMAC key, embedded in every receipt. |
| `GATEWAY_SIGNING_KEY` (hex 32-byte seed) or `GATEWAY_SIGNING_KEY_FILE` (PEM) | yes | Ed25519 private key that signs the Merkle root submitted to Rekor. |
| `GATEWAY_SIGNING_KEY_ID` | no (default `primary`) | Stable identifier for the signing key. |
| `GATEWAY_REKOR_URL` | no (default `https://rekor.sigstore.dev`) | Rekor instance to anchor against. |
| `GATEWAY_REKOR_ANCHOR_INTERVAL` | no (default `900` sec / 15 min) | Seconds between anchor cycles. Drops Rekor load by ~100x vs per-request anchoring. |

Generate a fresh pair locally:

```bash
# 32-byte HMAC key (hex)
openssl rand -hex 32

# 32-byte Ed25519 seed (hex)
openssl rand -hex 32
```

### Observability for receipts

Three new Prometheus metrics surface the receipt pipeline:

```
gateway_audit_backpressure_total          counter   # 503-ed audit submissions
gateway_transparency_publish_failed_total counter   # Rekor anchor failures
gateway_transparency_last_publish_age_seconds gauge  # staleness
```

Operators should alert on `gateway_transparency_last_publish_age_seconds` exceeding ~3x the configured anchor interval. Persistent failures usually mean Rekor public-good is degraded; the local chain stays valid in the meantime.

## Configuration

All settings are configured via environment variables.

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_LISTEN` | `127.0.0.1:8443` | Listen address |
| `GATEWAY_UPSTREAM` | `https://api.anthropic.com` | Upstream LLM API URL |
| `GATEWAY_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `GATEWAY_FAST_MODEL` | `gemma4:e4b` | 4B fast PII detection model (Ollama tag) |
| `GATEWAY_DEEP_MODEL` | `gemma4:26b` | 27B deep PII detection model (Ollama tag) |
| `GATEWAY_SCAN_MODE` | `fast` | Detection mode: `fast`, `deep`, or `auto` (see [Scan modes](#scan-modes)) |
| `GATEWAY_DETECTION_TIMEOUT` | `8` | Per-request PII detection budget, seconds. Raise to ~120 for laptop deep mode. |
| `GATEWAY_UPSTREAM_TIMEOUT` | `60` | Upstream HTTP client timeout, seconds |
| `GATEWAY_DETECTION_CONCURRENCY` | `2` | Max concurrent in-flight detections per request |
| `GATEWAY_DB_PATH` | `./data/sessions.db` | SQLite database path |
| `GATEWAY_SESSION_TTL` | `24h` | Session mapping time-to-live |
| `GATEWAY_AUDIT_PATH` | `./data/audit/` | Audit log directory |
| `GATEWAY_AUDIT_RETENTION` | `30` | Audit log retention in days |
| `GATEWAY_LOG_LEVEL` | `info` | Log level (trace, debug, info, warn, error) |
| `GATEWAY_SHOW_SCORE` | `true` | Include privacy score in response headers |
| `ANTHROPIC_API_KEY` | *(required\*)* | Anthropic API key for upstream |
| `OPENAI_API_KEY` | *(required\*)* | OpenAI API key for upstream |

\* At least one of `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` must be set.

## Development

```bash
# Build the full workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Run with clippy lints
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt --check
```

### Workspace Crates

| Crate | Purpose |
|---|---|
| `gateway-common` | Shared types, config, errors |
| `gateway-anonymizer` | PII detection, placeholders, session store, audit |
| `gateway-proxy` | Axum HTTP proxy server (binary: `gateway-proxy`) |
| `gateway-cli` | CLI tools: `gateway doctor`, `gateway demo` |
| `gateway-ebpf-loader` | Userspace eBPF loader for transparent interception |
| `gateway-ebpf-programs` | eBPF kernel programs (cgroup/connect4 redirect) |

## eBPF Transparent Interception

The gateway can transparently intercept outbound LLM API connections using Linux eBPF, so applications connect to cloud LLM endpoints as usual but traffic is silently redirected through the privacy proxy.

### Requirements

- **Linux 5.15+** (for cgroup/connect4 BPF program support)
- Docker with `--privileged` or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`
- cgroup v2 mounted at `/sys/fs/cgroup`

### How It Works

The eBPF loader resolves configured LLM endpoint hostnames (e.g. `api.anthropic.com`, `api.openai.com`) to their IP addresses, then loads a cgroup/connect4 eBPF program that intercepts outbound TCP connections. When an application connects to a matched IP:port, the eBPF program rewrites the destination to `127.0.0.1:<proxy_port>`, routing the connection through the privacy gateway.

DNS is re-resolved every 60 seconds (configurable) to handle IP changes.

### Quick Start with Docker Compose

```bash
# Start the full stack including eBPF transparent interception
docker compose up
```

The `gateway-ebpf` service starts automatically alongside `gateway-proxy`. It requires privileged mode for eBPF program loading.

### Configuration

Endpoints to intercept are configured in `endpoints.yaml` at the project root:

```yaml
endpoints:
  - host: api.anthropic.com
    port: 443
  - host: api.openai.com
    port: 443
proxy_port: 8443
dns_refresh_interval: 60
```

### Adding Custom Endpoints

To redirect additional LLM providers through the privacy gateway, add entries to `endpoints.yaml`:

```yaml
endpoints:
  - host: api.anthropic.com
    port: 443
  - host: api.openai.com
    port: 443
  - host: generativelanguage.googleapis.com
    port: 443
  - host: api.cohere.com
    port: 443
```

Then restart the eBPF service:

```bash
docker compose restart gateway-ebpf
```

### Dry Run

To validate the configuration and DNS resolution without loading eBPF programs:

```bash
cargo run -p gateway-ebpf-loader -- --config endpoints.yaml --dry-run
```

### Running Locally

```bash
export ANTHROPIC_API_KEY=sk-...
cargo run -p gateway-proxy
```

The proxy listens on `127.0.0.1:8443` by default. Requires a running Ollama instance.

## License

Apache-2.0
