---
title: "feat: Fix P0 SSE bug, merge Phase 2, build eBPF Phase 3"
type: feat
status: active
date: 2026-04-10
origin: ~/.gstack/projects/gateway/ceo-plans/2026-04-09-privacy-gateway.md
---

# Fix P0 SSE Bug + Merge Phase 2 + eBPF Phase 3

## Overview

Three work items in sequence:
1. Fix the P0 SSE chunk-splitting bug in handler.rs (TCP frames split SSE lines, leaking raw placeholders)
2. Merge feat/phase2-production-hardening to main
3. Build Phase 3: eBPF transparent interception using Aya framework in Rust

No model serving or GPU-dependent work (user has no GPU).

## Problem Frame

**P0 Bug:** TCP delivers bytes at arbitrary boundaries. The streaming handler splits on `\n`
assuming complete SSE lines per chunk. A `data: {"delta":"[PERSON_abc12345]"}` line split across
two TCP frames causes the first chunk to fail JSON parse, passing the raw placeholder (with PII
mapping) to the client. This violates the fail-closed iron rule.

**Phase 3:** The CEO plan defines eBPF transparent interception as the Layer 1 network privacy
component. Using cgroup/connect4 + cgroup/getsockopt programs (Aya framework in Rust), outbound
connections to LLM API endpoints are transparently redirected to the local proxy. Applications
never know the proxy exists. Linux 5.15+ only.

(see origin: CEO plan, Phase 3 section; code review P0 finding handler.rs:349)

## Requirements Trace

- R1. SSE chunks must be line-buffered before parsing (no partial JSON lines)
- R2. `from_utf8_lossy` replaced with proper UTF-8 boundary handling
- R3. Phase 2 merged to main cleanly
- R4. eBPF cgroup/connect4 redirects outbound TCP to configurable LLM endpoints
- R5. eBPF cgroup/getsockopt preserves original destination for proxy
- R6. Selective: only LLM-bound traffic redirected, everything else direct
- R7. eBPF programs in Rust via Aya framework (not C)
- R8. Configurable endpoint list (api.anthropic.com, api.openai.com, custom)
- R9. eBPF loader runs as privileged container (CAP_BPF, CAP_NET_ADMIN)
- R10. Tested on kernel 5.15+ (Ubuntu 22.04+)
- R11. docker-compose updated for 3+ container stack
- R12. Fallback: if eBPF fails to load, clear error message, no silent bypass

## Scope Boundaries

- No model serving, no Ollama integration testing (no GPU)
- No macOS/Windows eBPF (Linux only, as defined in CEO plan)
- No image/audio/non-text anonymization (text-only per Phase 1-2)
- No enterprise management UI (Phase 4)
- eBPF programs handle IPv4 only for Phase 3 (IPv6 is a future item)

## Context & Research

### Relevant Code and Patterns

- `crates/gateway-proxy/src/handler.rs:340-400` — Current SSE streaming code with the P0 bug
- `crates/gateway-anonymizer/src/streaming.rs` — StreamingDeanonymizer (works correctly, the bug is in the chunk-to-line layer above it)
- `crates/gateway-proxy/src/main.rs` — Server setup, will need eBPF integration
- `docker-compose.yml` — Current 2-container setup, needs eBPF container added

### External References

- [Aya eBPF framework](https://github.com/aya-rs/aya) — Pure Rust eBPF library
- [Aya cgroup_sock_addr docs](https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.cgroup_sock_addr.html)
- [Transparent proxy with eBPF and Go](https://medium.com/all-things-ebpf/building-a-transparent-proxy-with-ebpf-50a012237e76) — Reference for cgroup/connect4 + getsockopt pattern
- [dae project](https://github.com/daeuniverse/dae) — MIT licensed eBPF proxy, reference for LLM endpoint redirection
- [iximiuz eBPF egress proxy tutorial](https://labs.iximiuz.com/tutorials/ebpf-envoy-egress-dc77ccd7)

## Key Technical Decisions

- **SSE line buffering via accumulator:** Instead of splitting TCP chunks on `\n`, accumulate bytes into a line buffer. Emit complete SSE lines (ending in `\n\n`) to the deanonymizer. This handles arbitrary TCP framing. The accumulator lives alongside the StreamingDeanonymizer in the streaming response path.

- **UTF-8 boundary handling:** Replace `from_utf8_lossy` with a UTF-8 accumulator that holds incomplete multi-byte sequences across chunks. Only process complete UTF-8 characters.

- **Aya over C eBPF:** The entire project is Rust. Aya keeps the eBPF programs in the same language, same build system, same CI. No C toolchain needed. Aya's `cgroup_sock_addr` macro provides the connect4 hook directly.

- **Endpoint list as eBPF map:** The list of LLM API endpoint IPs is stored in a BPF_MAP_TYPE_HASH map. The userspace loader resolves DNS for configured hostnames and populates the map. The kernel program checks the map on each connect4 call. This allows runtime updates without reloading the eBPF program.

- **Separate crate for eBPF:** New `crates/gateway-ebpf/` with two sub-crates: `gateway-ebpf-programs/` (no_std, eBPF target) and `gateway-ebpf-loader/` (userspace loader binary). This follows Aya's recommended project structure.

## Open Questions

### Resolved During Planning

- **How does the proxy know the original destination?** cgroup/getsockopt program stores the original (IP, port) in a BPF map keyed by socket cookie. The proxy reads it via getsockopt(SO_ORIGINAL_DST) or from a shared BPF map.
- **What happens if DNS for endpoints changes?** The loader periodically re-resolves DNS (every 60s) and updates the BPF map. New connections use new IPs; existing connections are unaffected.
- **Does eBPF work in Docker?** Yes, with CAP_BPF + CAP_NET_ADMIN + host PID namespace. The eBPF programs attach to the host's cgroup, not the container's.

### Deferred to Implementation

- Exact Aya API for cgroup/getsockopt attachment (verify current Aya version supports it)
- BPF map key/value structure for endpoint list (depends on Aya's map API)
- DNS resolution library choice (trust-dns, hickory-dns, or std::net)
- Systemd integration for non-Docker deployments

## Implementation Units

### Part A: P0 Fix + Merge

- [ ] **Unit 1: Fix SSE chunk-splitting P0**

  **Goal:** Buffer SSE lines across TCP chunk boundaries so partial JSON is never parsed.

  **Requirements:** R1, R2

  **Dependencies:** None

  **Files:**
  - Create: `crates/gateway-proxy/src/sse_buffer.rs`
  - Modify: `crates/gateway-proxy/src/handler.rs` (replace chunk splitting with SseLineBuffer)
  - Modify: `crates/gateway-proxy/src/lib.rs`
  - Test: `crates/gateway-proxy/tests/sse_buffer_test.rs`

  **Approach:**
  - `SseLineBuffer` struct: holds a `Vec<u8>` accumulator
  - `push_bytes(&mut self, chunk: &[u8]) -> Vec<String>`: appends bytes, scans for `\n\n` (SSE event boundary), emits complete events, retains partial data
  - Handles UTF-8 boundaries: tracks incomplete multi-byte sequences at chunk edges, only converts complete UTF-8 to String
  - In handler.rs: replace `String::from_utf8_lossy(&chunk)` + `text.split('\n')` with `SseLineBuffer::push_bytes(&chunk)` which yields complete SSE events
  - The deanonymizer and JSON parsing logic remains unchanged, it just receives guaranteed-complete SSE lines now

  **Patterns to follow:**
  - Existing streaming.rs StreamingDeanonymizer for the accumulator pattern

  **Test scenarios:**
  - Happy path: Complete SSE event in one chunk → emitted immediately
  - Happy path: Two complete events in one chunk → both emitted
  - Edge case: SSE event split across two chunks (`data: {"del` + `ta":"text"}\n\n`) → buffered, emitted on second chunk
  - Edge case: UTF-8 multi-byte char split at chunk boundary → correctly reconstructed
  - Edge case: Empty chunk → no output, no error
  - Edge case: Chunk ending mid-UTF-8 sequence → held until next chunk completes it
  - Edge case: Very large event (>64KB) → still works (no arbitrary size limit)
  - Integration: Mock SSE upstream splits a placeholder-containing event across 3 chunks → client receives correct deanonymized event

  **Verification:** The existing streaming tests pass. New tests verify chunk-split handling. No raw placeholders leak when events are split.

- [ ] **Unit 2: Merge Phase 2 to main**

  **Goal:** Land all Phase 2 work on main.

  **Requirements:** R3

  **Dependencies:** Unit 1 (fix must land first)

  **Files:**
  - No code changes. Git merge operation.

  **Approach:**
  - Verify all 235+ tests pass on the branch
  - `git checkout main && git merge feat/phase2-production-hardening`
  - Verify tests pass on main after merge

  **Verification:** `cargo test --workspace` passes on main. `git log --oneline` shows Phase 2 commits.

### Part B: eBPF Phase 3

- [ ] **Unit 3: eBPF crate scaffold + Aya setup**

  **Goal:** Create the eBPF workspace crates with Aya dependencies and build infrastructure.

  **Requirements:** R7

  **Dependencies:** Unit 2 (merged main)

  **Files:**
  - Create: `crates/gateway-ebpf-programs/Cargo.toml` (no_std, eBPF target)
  - Create: `crates/gateway-ebpf-programs/src/main.rs` (minimal cgroup/connect4 skeleton)
  - Create: `crates/gateway-ebpf-loader/Cargo.toml`
  - Create: `crates/gateway-ebpf-loader/src/main.rs` (loader skeleton)
  - Modify: `Cargo.toml` (add new workspace members)
  - Create: `.cargo/config.toml` (eBPF target configuration for bpfel-unknown-none)

  **Approach:**
  - eBPF programs crate: `#![no_std]`, `#![no_main]`, target `bpfel-unknown-none`
  - Uses `aya-ebpf` crate for kernel-side BPF helpers
  - Loader crate: normal Rust binary, uses `aya` crate for loading/attaching programs
  - Workspace Cargo.toml adds both as members but excludes eBPF programs from default workspace build (needs special target)
  - Build: `cargo xtask build-ebpf` or direct `cargo build --target bpfel-unknown-none -p gateway-ebpf-programs`

  **Patterns to follow:**
  - [Aya project template](https://github.com/aya-rs/aya-template)

  **Test scenarios:**
  - Happy path: eBPF programs crate compiles for bpfel-unknown-none target
  - Happy path: Loader crate compiles for host target
  - Edge case: Default `cargo build --workspace` does not try to build eBPF programs (excluded from default members)

  **Verification:** Both crates compile. CI does not break.

- [ ] **Unit 4: cgroup/connect4 redirect program**

  **Goal:** eBPF program that intercepts outbound TCP connect() calls and redirects LLM endpoint connections to the local proxy.

  **Requirements:** R4, R6, R8

  **Dependencies:** Unit 3

  **Files:**
  - Modify: `crates/gateway-ebpf-programs/src/main.rs` (connect4 program)
  - Create: `crates/gateway-ebpf-programs/src/maps.rs` (shared BPF maps)

  **Approach:**
  - `#[cgroup_sock_addr(connect4)]` function: on each connect() syscall
  - Check destination IP:port against ENDPOINTS_MAP (BPF_MAP_TYPE_HASH)
  - If match: store original (IP, port) in ORIG_DST_MAP keyed by socket cookie, rewrite destination to 127.0.0.1:PROXY_PORT
  - If no match: allow connection unmodified (return 1)
  - ENDPOINTS_MAP: key = (u32 IP, u16 port), value = u8 (1 = redirect)
  - ORIG_DST_MAP: key = u64 (socket cookie), value = (u32 orig_ip, u16 orig_port)
  - PROXY_PORT stored in a BPF_MAP_TYPE_ARRAY (single element, set by loader)

  **Test scenarios:**
  - Happy path: Connection to api.anthropic.com:443 → redirected to 127.0.0.1:8443
  - Happy path: Connection to google.com:443 → NOT redirected (not in endpoint map)
  - Happy path: Original destination stored in ORIG_DST_MAP for proxy to retrieve
  - Edge case: Endpoint map empty → no redirections
  - Edge case: Multiple concurrent connections → each gets its own ORIG_DST_MAP entry

  **Verification:** eBPF program compiles. Logic verified by code inspection (kernel-level testing requires privileged environment).

- [ ] **Unit 5: Userspace loader + DNS resolver**

  **Goal:** Binary that loads eBPF programs, resolves LLM endpoint DNS, populates BPF maps, and manages program lifecycle.

  **Requirements:** R8, R9, R12

  **Dependencies:** Unit 4

  **Files:**
  - Modify: `crates/gateway-ebpf-loader/src/main.rs`
  - Create: `crates/gateway-ebpf-loader/src/config.rs` (endpoint config)
  - Create: `crates/gateway-ebpf-loader/src/dns.rs` (periodic DNS resolution)
  - Test: `crates/gateway-ebpf-loader/tests/config_test.rs`

  **Approach:**
  - Config: YAML file listing LLM endpoints (hostname:port pairs)
    ```yaml
    endpoints:
      - host: api.anthropic.com
        port: 443
      - host: api.openai.com
        port: 443
    proxy_port: 8443
    dns_refresh_interval: 60
    ```
  - Loader: read config, resolve DNS for each endpoint, load eBPF program bytes, attach to cgroup, populate ENDPOINTS_MAP with resolved IPs
  - DNS refresh: spawn a background task that re-resolves every N seconds, updates the map atomically
  - Graceful shutdown: on SIGTERM/SIGINT, detach eBPF programs and clean up maps
  - Error handling: if eBPF load fails (wrong kernel, no CAP_BPF), print clear error and exit non-zero. Never silently fall back to no-redirect.
  - CLI: `gateway-ebpf-loader --config endpoints.yaml [--cgroup-path /sys/fs/cgroup]`

  **Patterns to follow:**
  - Existing gateway-common config.rs for env/config parsing patterns
  - Aya examples for program loading and map interaction

  **Test scenarios:**
  - Happy path: Config YAML parses with multiple endpoints
  - Happy path: DNS resolution for api.anthropic.com returns IP addresses
  - Edge case: Empty endpoints list → loader runs but no redirections
  - Edge case: DNS resolution fails for one endpoint → skip it, log warning, resolve others
  - Edge case: Config file not found → clear error message
  - Error path: eBPF load fails (simulated) → error message mentions kernel version and capabilities

  **Verification:** Loader binary compiles and runs `--help`. Config parsing tests pass.

- [ ] **Unit 6: Docker integration + compose update**

  **Goal:** eBPF loader as a privileged container in docker-compose.

  **Requirements:** R9, R10, R11

  **Dependencies:** Unit 5

  **Files:**
  - Create: `crates/gateway-ebpf-loader/Dockerfile`
  - Modify: `docker-compose.yml` (add gateway-ebpf service)
  - Create: `endpoints.yaml` (default LLM endpoint config)
  - Modify: `README.md` (add eBPF section)

  **Approach:**
  - eBPF loader Dockerfile: build the loader binary + pre-compiled eBPF program object
  - Docker compose service:
    ```yaml
    gateway-ebpf:
      build: crates/gateway-ebpf-loader
      privileged: true
      pid: host
      network_mode: host
      cap_add: [BPF, NET_ADMIN, SYS_ADMIN]
      volumes:
        - /sys/fs/bpf:/sys/fs/bpf
        - ./endpoints.yaml:/etc/gateway/endpoints.yaml
      depends_on:
        gateway-proxy: { condition: service_started }
    ```
  - The eBPF container needs host PID and network namespace to attach to host cgroup
  - Default endpoints.yaml includes api.anthropic.com:443 and api.openai.com:443
  - README updated with eBPF section explaining Linux requirements, kernel version, and how to enable/disable

  **Test scenarios:**
  - Happy path: docker-compose.yml is valid YAML with the new service
  - Happy path: Dockerfile builds (if Docker is available)
  - Edge case: docker compose up without privileged mode → clear error from eBPF loader

  **Verification:** docker-compose.yml parses. README has eBPF section.

## System-Wide Impact

- **Interaction graph:** eBPF operates at kernel level, below the Axum proxy. The proxy handler is unchanged. eBPF redirects TCP connections before they leave the host. The proxy receives redirected connections on its existing listen port.
- **Error propagation:** eBPF load failure → loader exits non-zero → docker-compose marks service unhealthy. The proxy continues working (manual proxy config still works). No silent failure.
- **State lifecycle:** BPF maps are kernel-resident, cleaned up when the loader detaches. No persistent state beyond the cgroup attachment.
- **Unchanged invariants:** All existing proxy behavior (anonymization, scoring, audit, streaming, routing) is completely unchanged. eBPF only affects how connections arrive at the proxy, not what happens after.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Aya cgroup_sock_addr may not support getsockopt on current version | Check Aya docs during implementation. Fallback: store orig_dst in BPF map only (no getsockopt program). |
| eBPF testing requires privileged environment | Unit tests cover config/parsing. eBPF program logic verified by code inspection. E2E testing requires a Linux VM with CAP_BPF. |
| Kernel version differences | Target 5.15+ (Ubuntu 22.04). Document minimum kernel version. CI tests run on Ubuntu 22.04 runner. |
| Docker privileged mode security implications | Document in README. eBPF container runs as a separate service with minimal filesystem access. |
| DNS resolution adds latency to loader startup | Resolve in parallel for all endpoints. Cache results. Startup is a one-time cost. |

## Sources & References

- **Origin:** [CEO Plan](~/.gstack/projects/gateway/ceo-plans/2026-04-09-privacy-gateway.md) Phase 3
- **Code review P0:** handler.rs:349 SSE chunk-splitting finding
- [Aya eBPF framework](https://github.com/aya-rs/aya)
- [Aya cgroup_sock_addr](https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.cgroup_sock_addr.html)
- [Transparent proxy with eBPF](https://medium.com/all-things-ebpf/building-a-transparent-proxy-with-ebpf-50a012237e76)
- [dae eBPF proxy](https://github.com/daeuniverse/dae)
