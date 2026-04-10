//! Library interface for gateway-ebpf-loader.
//!
//! Re-exports the config and DNS modules so they can be used from
//! integration tests and other crates.

pub mod config;
pub mod dns;

// Re-export key types at the crate root for convenience.
pub use config::{Endpoint, LoaderConfig};
pub use dns::{resolve_endpoints, ResolvedEndpoint, ResolvedEndpoint6, ResolvedEndpoints};
