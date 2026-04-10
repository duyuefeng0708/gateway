---
title: "fix: Resolve eBPF loader tech debt (DNS race, blocking IO, IPv6, Docker caps)"
type: fix
status: active
date: 2026-04-10
---

# Fix eBPF Loader Tech Debt

## Overview

Four fixes from code review findings: DNS refresh race condition in map updates, blocking
DNS in async runtime, missing IPv6 connect6 program, and overly broad Docker privileges.

## Requirements Trace

- R1. DNS map refresh must not leave the ENDPOINTS map empty during updates (P1)
- R2. DNS resolution must not block the tokio runtime (P1)
- R3. IPv6 connections to LLM endpoints must be redirected (P2)
- R4. Docker container must use minimal capabilities, not `privileged: true` (P2)

## Scope Boundaries

- Loader and eBPF programs only. No proxy or anonymizer changes.
- IPv6 connect6 is additive (new eBPF program). Does not change connect4 behavior.

## Context & Research

### Relevant Code

- `crates/gateway-ebpf-loader/src/main.rs` — `update_endpoint_map` function (DNS race), eBPF loading
- `crates/gateway-ebpf-loader/src/dns.rs` — `resolve_endpoints` (blocking IO)
- `crates/gateway-ebpf-programs/src/main.rs` — connect4 program (add connect6 alongside)
- `docker-compose.yml` — `gateway-ebpf` service with `privileged: true`

## Key Technical Decisions

- **Insert-before-delete for map refresh:** Compute the set difference (new IPs vs old IPs). Insert new entries first, then delete entries no longer in the resolved set. The map is never empty during the transition.
- **`tokio::task::spawn_blocking` for DNS:** Wrap `to_socket_addrs()` in `spawn_blocking` since it's a blocking syscall. Same pattern used by `rusqlite` in the session store.
- **connect6 as a separate eBPF function:** Same program file, same maps, separate `#[cgroup_sock_addr(connect6)]` function. Shares ENDPOINTS and ORIG_DST maps with connect4.
- **Keep explicit caps, drop privileged:** `BPF`, `NET_ADMIN`, `SYS_ADMIN` are sufficient for eBPF loading and cgroup attachment.

## Implementation Units

- [ ] **Unit 1: Fix DNS refresh race (insert-before-delete)**

  **Goal:** Eliminate the window where ENDPOINTS map is empty during DNS refresh.

  **Requirements:** R1

  **Dependencies:** None

  **Files:**
  - Modify: `crates/gateway-ebpf-loader/src/main.rs` (update_endpoint_map function)
  - Test: `crates/gateway-ebpf-loader/tests/config_test.rs`

  **Approach:**
  - Change `update_endpoint_map` to: (1) collect current map keys, (2) insert all new resolved IPs, (3) compute stale = old_keys - new_keys, (4) delete only stale entries
  - Requires reading existing map entries. Use aya's `HashMap::keys()` iterator.
  - If keys() is not available in aya 0.13, maintain an in-memory `HashSet<EndpointKey>` of what was last inserted and diff against it.

  **Patterns to follow:**
  - Existing `populate_endpoint_map` function structure

  **Test scenarios:**
  - Happy path: Refresh with same IPs → no deletes, no inserts (idempotent)
  - Happy path: Refresh with new IP added → inserted without removing existing
  - Happy path: Refresh with IP removed → only removed after new entries present
  - Edge case: DNS returns empty → keep existing entries, log warning, do NOT clear map

  **Verification:** Map is never empty during a refresh cycle.

- [ ] **Unit 2: Non-blocking DNS resolution**

  **Goal:** Prevent DNS resolution from blocking tokio worker threads.

  **Requirements:** R2

  **Dependencies:** None

  **Files:**
  - Modify: `crates/gateway-ebpf-loader/src/dns.rs` (resolve_endpoints, resolve_host)
  - Test: `crates/gateway-ebpf-loader/tests/config_test.rs`

  **Approach:**
  - Make `resolve_endpoints` async
  - Wrap each `resolve_host` call in `tokio::task::spawn_blocking`
  - Or use `tokio::net::lookup_host` which is natively async (preferred if available)
  - Update the DNS refresh loop in main.rs to call the now-async function

  **Patterns to follow:**
  - `crates/gateway-anonymizer/src/session.rs` uses `spawn_blocking` for rusqlite calls

  **Test scenarios:**
  - Happy path: Async resolution of localhost returns results
  - Happy path: Multiple endpoints resolved concurrently
  - Error path: Unresolvable host → skipped with warning (existing behavior preserved)

  **Verification:** DNS resolution does not block the tokio runtime. Existing DNS tests pass.

- [ ] **Unit 3: IPv6 connect6 eBPF program**

  **Goal:** Redirect IPv6 connections to LLM endpoints through the proxy.

  **Requirements:** R3

  **Dependencies:** None

  **Files:**
  - Modify: `crates/gateway-ebpf-programs/src/main.rs` (add connect6 function + IPv6 maps)
  - Modify: `crates/gateway-ebpf-loader/src/main.rs` (attach connect6, populate IPv6 map)
  - Modify: `crates/gateway-ebpf-loader/src/dns.rs` (stop filtering out IPv6 addresses)

  **Approach:**
  - Add `EndpointKey6` struct: `#[repr(C)] { ip6: [u32; 4], port: u16, _pad: u16 }` (20 bytes)
  - Add `ENDPOINTS6` HashMap and `ORIG_DST6` HashMap for IPv6
  - `#[cgroup_sock_addr(connect6)]` function: same logic as connect4 but reads `user_ip6`
  - Redirect to `::1` (IPv6 localhost) with proxy port
  - DNS resolver: stop filtering `SocketAddr::V6`, return both v4 and v6 results
  - Loader: populate both ENDPOINTS (v4) and ENDPOINTS6 (v6) maps
  - Loader: attach both connect4 and connect6 programs to cgroup

  **Patterns to follow:**
  - Existing connect4 program structure and EndpointKey layout

  **Test scenarios:**
  - Happy path: eBPF program compiles with connect6 function (release build)
  - Happy path: DNS resolver returns both IPv4 and IPv6 addresses
  - Happy path: Loader config test still passes with mixed v4/v6 endpoints
  - Edge case: Endpoint resolves to IPv6 only → only ENDPOINTS6 populated
  - Edge case: Endpoint resolves to IPv4 only → only ENDPOINTS populated (unchanged behavior)

  **Verification:** eBPF program compiles for bpfel-unknown-none with both connect4 and connect6. DNS resolver returns IPv6 addresses.

- [ ] **Unit 4: Remove privileged: true from Docker compose**

  **Goal:** Use minimal capabilities instead of full privileged mode.

  **Requirements:** R4

  **Dependencies:** None

  **Files:**
  - Modify: `docker-compose.yml`

  **Approach:**
  - Remove `privileged: true` from the `gateway-ebpf` service
  - Keep `cap_add: [BPF, NET_ADMIN, SYS_ADMIN]`
  - Keep `pid: host` and `network_mode: host` (required for cgroup attachment)
  - Add `security_opt: [apparmor:unconfined]` if needed for eBPF on Ubuntu (test during implementation)

  **Test scenarios:**
  - Happy path: docker-compose.yml is valid YAML
  - Happy path: Service definition has explicit caps but no `privileged: true`

  **Verification:** `docker compose config` validates. Service retains eBPF-required capabilities.

## System-Wide Impact

- **Unchanged invariants:** Proxy behavior, anonymization pipeline, all non-eBPF code unchanged. connect4 behavior unchanged (IPv6 is additive).
- **Error propagation:** DNS refresh failure with empty results now preserves existing map entries instead of clearing them.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| aya HashMap::keys() may not be available | Fallback: maintain in-memory HashSet of inserted keys |
| connect6 adds kernel program complexity | Same pattern as connect4, minimal new logic |
| Removing privileged may break on some kernels | Keep SYS_ADMIN cap. Test on current kernel 6.14. |

## Sources & References

- Code review findings from Phase 3 eBPF review
- `crates/gateway-anonymizer/src/session.rs` — spawn_blocking pattern
- `crates/gateway-ebpf-programs/src/main.rs` — connect4 pattern for connect6
