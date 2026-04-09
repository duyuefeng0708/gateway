use std::net::ToSocketAddrs;

use tracing::{info, warn};

use crate::config::Endpoint;

/// Resolved endpoint: an IPv4 address (as a native-endian u32) and port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    /// IPv4 address in network byte order (big-endian), matching what
    /// the kernel eBPF program sees in `user_ip4`.
    pub ip_be: u32,
    /// Port number (host byte order).
    pub port: u16,
}

/// Resolve a list of endpoints to their IPv4 addresses.
///
/// Hostnames that fail to resolve are logged as warnings and skipped.
/// Returns all successfully resolved (ip, port) pairs, potentially
/// multiple per hostname if DNS returns multiple A records.
pub fn resolve_endpoints(endpoints: &[Endpoint]) -> Vec<ResolvedEndpoint> {
    let mut resolved = Vec::new();

    for ep in endpoints {
        match resolve_host(&ep.host, ep.port) {
            Ok(addrs) => {
                info!(
                    host = %ep.host,
                    port = ep.port,
                    count = addrs.len(),
                    "resolved endpoint"
                );
                resolved.extend(addrs);
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

/// Resolve a single hostname to all of its IPv4 addresses.
fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<ResolvedEndpoint>> {
    let addr_str = format!("{}:{}", host, port);
    let addrs = addr_str.to_socket_addrs()?;

    let resolved: Vec<ResolvedEndpoint> = addrs
        .filter_map(|addr| match addr {
            std::net::SocketAddr::V4(v4) => {
                let octets = v4.ip().octets();
                let ip_be = u32::from_be_bytes(octets);
                Some(ResolvedEndpoint {
                    ip_be,
                    port: v4.port(),
                })
            }
            // Skip IPv6 addresses; eBPF connect4 only handles IPv4.
            std::net::SocketAddr::V6(_) => None,
        })
        .collect();

    if resolved.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no IPv4 addresses found for {}", host),
        ));
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_localhost() {
        let endpoints = vec![Endpoint {
            host: "localhost".to_string(),
            port: 80,
        }];
        let resolved = resolve_endpoints(&endpoints);
        assert!(!resolved.is_empty(), "localhost should resolve");

        // localhost should resolve to 127.0.0.1
        let loopback_be = u32::from_be_bytes([127, 0, 0, 1]);
        assert!(
            resolved.iter().any(|r| r.ip_be == loopback_be),
            "localhost should resolve to 127.0.0.1"
        );
        assert!(
            resolved.iter().all(|r| r.port == 80),
            "port should be preserved"
        );
    }

    #[test]
    fn resolve_nonexistent_host_is_skipped() {
        let endpoints = vec![Endpoint {
            host: "this.host.definitely.does.not.exist.invalid".to_string(),
            port: 443,
        }];
        let resolved = resolve_endpoints(&endpoints);
        assert!(
            resolved.is_empty(),
            "non-existent host should be skipped"
        );
    }
}
