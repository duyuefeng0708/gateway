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
- **4B fast model** -- explicit PII via MTBS/anonymizer on Ollama (sub-second)
- **27B deep model** -- implicit PII via Qwen 3.5 reasoning (2-8s, auto-escalation)

## Quick Start

**One-line install** (downloads binary, starts Ollama, pulls PII model):

```bash
curl -sSf https://gateway.dev/install | sh
```

Or run manually with Docker Compose:

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-...

# Start the gateway + Ollama sidecar
docker compose up

# Send a request through the proxy
curl -X POST http://localhost:8443/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":256,"messages":[{"role":"user","content":"My name is Alice and I live in Portland."}]}'
```

To run with cc-gateway as the upstream instead of Anthropic directly:

```bash
docker compose -f docker-compose.full.yml up
```

## Configuration

All settings are configured via environment variables.

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_LISTEN` | `127.0.0.1:8443` | Listen address |
| `GATEWAY_UPSTREAM` | `https://api.anthropic.com` | Upstream LLM API URL |
| `GATEWAY_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `GATEWAY_FAST_MODEL` | `MTBS/anonymizer` | 4B fast PII detection model |
| `GATEWAY_DEEP_MODEL` | `qwen3.5-27b-claude-distilled` | 27B deep PII detection model |
| `GATEWAY_SCAN_MODE` | `fast` | Detection mode: `fast`, `deep`, or `auto` |
| `GATEWAY_DB_PATH` | `./data/sessions.db` | SQLite database path |
| `GATEWAY_SESSION_TTL` | `24h` | Session mapping time-to-live |
| `GATEWAY_AUDIT_PATH` | `./data/audit/` | Audit log directory |
| `GATEWAY_AUDIT_RETENTION` | `30` | Audit log retention in days |
| `GATEWAY_LOG_LEVEL` | `info` | Log level (trace, debug, info, warn, error) |
| `GATEWAY_SHOW_SCORE` | `true` | Include privacy score in response headers |
| `ANTHROPIC_API_KEY` | *(required)* | Anthropic API key for upstream |

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
