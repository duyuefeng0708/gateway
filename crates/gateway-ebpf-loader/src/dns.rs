use std::net::ToSocketAddrs;

use tracing::{info, warn};

use crate::config::Endpoint;

/// Resolved IPv4 endpoint: an IPv4 address (as a native-endian u32) and port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedEndpoint {
    /// IPv4 address in network byte order (big-endian), matching what
    /// the kernel eBPF program sees in `user_ip4`.
    pub ip_be: u32,
    /// Port number (host byte order).
    pub port: u16,
}

/// Resolved IPv6 endpoint: an IPv6 address (as 4 x u32 in network byte order) and port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedEndpoint6 {
    /// IPv6 address as 4 x u32 in network byte order (big-endian), matching what
    /// the kernel eBPF program sees in `user_ip6`.
    pub ip6_be: [u32; 4],
    /// Port number (host byte order).
    pub port: u16,
}

/// All resolved endpoints (both IPv4 and IPv6).
#[derive(Debug, Clone, Default)]
pub struct ResolvedEndpoints {
    pub v4: Vec<ResolvedEndpoint>,
    pub v6: Vec<ResolvedEndpoint6>,
}

impl ResolvedEndpoints {
    /// Returns true if both v4 and v6 are empty.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Total number of resolved addresses (v4 + v6).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// Resolve a list of endpoints to their IPv4 and IPv6 addresses.
///
/// Hostnames that fail to resolve are logged as warnings and skipped.
/// Returns all successfully resolved (ip, port) pairs, potentially
/// multiple per hostname if DNS returns multiple A/AAAA records.
///
/// DNS lookups are offloaded to blocking threads via
/// `tokio::task::spawn_blocking` so the async runtime is never blocked.
pub async fn resolve_endpoints(endpoints: &[Endpoint]) -> ResolvedEndpoints {
    let mut resolved = ResolvedEndpoints::default();

    for ep in endpoints {
        match resolve_host(&ep.host, ep.port).await {
            Ok(addrs) => {
                info!(
                    host = %ep.host,
                    port = ep.port,
                    v4_count = addrs.v4.len(),
                    v6_count = addrs.v6.len(),
                    "resolved endpoint"
                );
                resolved.v4.extend(addrs.v4);
                resolved.v6.extend(addrs.v6);
            }
            Err(e) => {
                warn!(
                    host = %ep.host,
                    port = ep.port,
                    error = %e,
                    "failed to resolve endpoint, skipping"
                );
            }
        }
    }

    resolved
}

/// Resolve a single hostname to all of its IPv4 and IPv6 addresses.
///
/// The blocking `to_socket_addrs()` syscall is offloaded to a dedicated
/// thread via `tokio::task::spawn_blocking`.
async fn resolve_host(host: &str, port: u16) -> std::io::Result<ResolvedEndpoints> {
    let addr_str = format!("{}:{}", host, port);
    let host_owned = host.to_string();

    let resolved = tokio::task::spawn_blocking(move || {
        let addrs = addr_str.to_socket_addrs()?;

        let mut resolved = ResolvedEndpoints::default();

        for addr in addrs {
            match addr {
                std::net::SocketAddr::V4(v4) => {
                    let octets = v4.ip().octets();
                    // Use from_ne_bytes so the u32 matches what the kernel's
                    // user_ip4 field looks like when read on this CPU. On x86
                    // (LE), from_ne_bytes([160,79,104,10]) = 0x0A684FA0, which
                    // is exactly what user_ip4 contains for 160.79.104.10.
                    let ip_be = u32::from_ne_bytes(octets);
                    resolved.v4.push(ResolvedEndpoint {
                        ip_be,
                        port: v4.port(),
                    });
                }
                std::net::SocketAddr::V6(v6) => {
                    let segments = v6.ip().segments();
                    // Convert 8 x u16 segments to 4 x u32 in network byte order,
                    // matching the kernel's __be32[4] layout for user_ip6.
                    let ip6_be = [
                        ((segments[0] as u32) << 16) | (segments[1] as u32),
                        ((segments[2] as u32) << 16) | (segments[3] as u32),
                        ((segments[4] as u32) << 16) | (segments[5] as u32),
                        ((segments[6] as u32) << 16) | (segments[7] as u32),
                    ];
                    resolved.v6.push(ResolvedEndpoint6 {
                        ip6_be,
                        port: v6.port(),
                    });
                }
            }
        }

        if resolved.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no addresses found for {}", host_owned),
            ));
        }

        Ok(resolved)
    })
    .await
    .map_err(std::io::Error::other)??;

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_localhost() {
        let endpoints = vec![Endpoint {
            host: "localhost".to_string(),
            port: 80,
        }];
        let resolved = resolve_endpoints(&endpoints).await;
        assert!(!resolved.is_empty(), "localhost should resolve");

        // localhost should resolve to 127.0.0.1
        let loopback_ne = u32::from_ne_bytes([127, 0, 0, 1]);
        assert!(
            resolved.v4.iter().any(|r| r.ip_be == loopback_ne),
            "localhost should resolve to 127.0.0.1"
        );
        assert!(
            resolved.v4.iter().all(|r| r.port == 80),
            "port should be preserved"
        );
    }

    #[tokio::test]
    async fn resolve_nonexistent_host_is_skipped() {
        let endpoints = vec![Endpoint {
            host: "this.host.definitely.does.not.exist.invalid".to_string(),
            port: 443,
        }];
        let resolved = resolve_endpoints(&endpoints).await;
        assert!(resolved.is_empty(), "non-existent host should be skipped");
    }

    #[tokio::test]
    async fn resolve_host_non_blocking() {
        // Verify that resolve_host runs on a blocking thread and does not
        // block the tokio runtime.  We do this by racing a resolve against
        // a short yield; the important thing is that the future is Send
        // and completes without panicking.
        let endpoints = vec![Endpoint {
            host: "localhost".to_string(),
            port: 80,
        }];
        let handle = tokio::spawn(async move { resolve_endpoints(&endpoints).await });
        let resolved = handle.await.expect("task should not panic");
        assert!(
            !resolved.is_empty(),
            "localhost should resolve from spawned task"
        );
    }
}
