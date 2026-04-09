//! Userspace eBPF loader for the Privacy Gateway.
//!
//! Loads a pre-compiled eBPF connect4 program, attaches it to a cgroup,
//! and populates BPF maps with resolved LLM endpoint IPs so that
//! outbound connections are transparently redirected to the local proxy.

mod config;
mod dns;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use config::LoaderConfig;
use dns::{resolve_endpoints, ResolvedEndpoint};

/// Privacy Gateway eBPF loader.
///
/// Loads a BPF connect4 program that transparently redirects LLM API
/// traffic through the local privacy proxy.
#[derive(Parser, Debug)]
#[command(name = "gateway-ebpf-loader", version, about)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(long, short)]
    config: PathBuf,

    /// Path to the cgroup to attach the eBPF program to.
    /// Overrides the value in the config file.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_path: Option<String>,

    /// Path to the compiled eBPF object file.
    /// If not specified, looks for gateway_ebpf_programs.o in standard locations.
    #[arg(long)]
    bpf_object: Option<PathBuf>,

    /// Validate configuration and DNS resolution without loading eBPF programs.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load configuration.
    info!(path = %cli.config.display(), "loading configuration");
    let mut config = LoaderConfig::from_file(&cli.config)?;

    // CLI cgroup_path overrides config.
    if let Some(ref cgroup) = cli.cgroup_path {
        config.cgroup_path = cgroup.clone();
    }

    info!(
        endpoints = config.endpoints.len(),
        proxy_port = config.proxy_port,
        cgroup_path = %config.cgroup_path,
        dns_refresh = config.dns_refresh_interval,
        "configuration loaded"
    );

    // Initial DNS resolution.
    let resolved = resolve_endpoints(&config.endpoints);
    if resolved.is_empty() {
        bail!(
            "no endpoints could be resolved; check your DNS and endpoint configuration"
        );
    }
    info!(count = resolved.len(), "resolved endpoint IPs");
    for ep in &resolved {
        let octets = ep.ip_be.to_be_bytes();
        info!(
            ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
            port = ep.port,
            "endpoint IP"
        );
    }

    if cli.dry_run {
        info!("dry-run mode: configuration and DNS validated successfully");
        print_dry_run_summary(&config, &resolved);
        return Ok(());
    }

    // Load and attach eBPF programs.
    info!("loading eBPF programs");
    let bpf = load_ebpf(&cli, &config, &resolved)?;

    // Set up graceful shutdown.
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();

    // Spawn signal handler.
    tokio::spawn(async move {
        let ctrl_c = signal::ctrl_c();
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => {
                info!("received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
            }
        }

        shutdown_clone.notify_one();
    });

    // Spawn DNS refresh task.
    let refresh_config = config.clone();
    let refresh_shutdown = shutdown.clone();
    let bpf_handle = Arc::new(tokio::sync::Mutex::new(bpf));
    let bpf_for_refresh = bpf_handle.clone();

    tokio::spawn(async move {
        let interval = Duration::from_secs(refresh_config.dns_refresh_interval);
        let mut tick = tokio::time::interval(interval);
        tick.tick().await; // Skip the first immediate tick.

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    info!("refreshing DNS for endpoints");
                    let new_resolved = resolve_endpoints(&refresh_config.endpoints);
                    if new_resolved.is_empty() {
                        warn!("DNS refresh returned no results, keeping existing entries");
                        continue;
                    }
                    info!(count = new_resolved.len(), "DNS refresh complete");

                    // Update the BPF maps with new IPs.
                    let mut bpf_guard = bpf_for_refresh.lock().await;
                    if let Err(e) = update_endpoint_map(&mut bpf_guard, &new_resolved) {
                        error!(error = %e, "failed to update endpoint map");
                    }
                }
                _ = refresh_shutdown.notified() => {
                    info!("DNS refresh task shutting down");
                    break;
                }
            }
        }
    });

    // Wait for shutdown signal.
    shutdown.notified().await;

    // Cleanup: aya drops and detaches programs when Ebpf is dropped.
    info!("detaching eBPF programs");
    drop(bpf_handle);

    info!("shutdown complete");
    Ok(())
}

/// Print a summary for dry-run mode.
fn print_dry_run_summary(config: &LoaderConfig, resolved: &[ResolvedEndpoint]) {
    println!("\n=== Dry Run Summary ===\n");
    println!("Proxy port:    {}", config.proxy_port);
    println!("Cgroup path:   {}", config.cgroup_path);
    println!("DNS refresh:   {}s", config.dns_refresh_interval);
    println!("Endpoints:     {}", config.endpoints.len());
    println!("Resolved IPs:  {}", resolved.len());
    println!();
    for ep in resolved {
        let octets = ep.ip_be.to_be_bytes();
        println!(
            "  {}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], ep.port
        );
    }
    println!("\nAll checks passed. Ready to load eBPF programs.");
}

// ---------------------------------------------------------------------------
// eBPF loading and map management
//
// These functions use the `aya` crate to load the pre-compiled eBPF object,
// attach the connect4 program to the target cgroup, and populate the
// ENDPOINTS and PROXY_PORT BPF maps.
// ---------------------------------------------------------------------------

/// BPF map key for the ENDPOINTS hash map.
///
/// Must match the layout used by the eBPF kernel program: `(u32, u16)`.
/// We use a `#[repr(C)]` struct so it implements `Pod` for aya.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointKey {
    ip: u32,
    port: u16,
    // Padding to align to the struct size the kernel sees for (u32, u16).
    _pad: u16,
}

// SAFETY: EndpointKey is #[repr(C)], contains only Copy types, and has
// no padding that could contain uninitialized bytes (we explicitly include
// the padding field).
unsafe impl aya::Pod for EndpointKey {}

impl EndpointKey {
    fn new(ip_be: u32, port_be: u16) -> Self {
        Self {
            ip: ip_be,
            port: port_be,
            _pad: 0,
        }
    }
}

/// Wrapper around the aya Ebpf handle for lifecycle management.
struct BpfState {
    #[allow(dead_code)]
    bpf: aya::Ebpf,
}

/// Locate the eBPF object file.
fn find_bpf_object(cli: &Cli) -> Result<PathBuf> {
    // Explicit path takes precedence.
    if let Some(ref path) = cli.bpf_object {
        if path.exists() {
            return Ok(path.clone());
        }
        bail!("specified eBPF object not found: {}", path.display());
    }

    // Search standard locations.
    let candidates = [
        PathBuf::from("/usr/lib/gateway/gateway_ebpf_programs.o"),
        PathBuf::from("/usr/local/lib/gateway/gateway_ebpf_programs.o"),
        PathBuf::from("./target/bpfel-unknown-none/release/gateway-ebpf-programs"),
        PathBuf::from("./gateway_ebpf_programs.o"),
    ];

    for path in &candidates {
        if path.exists() {
            info!(path = %path.display(), "found eBPF object");
            return Ok(path.clone());
        }
    }

    bail!(
        "could not find eBPF object file. Searched: {:?}. \
         Use --bpf-object to specify the path explicitly.",
        candidates
    )
}

/// Load the eBPF program, attach it, and populate maps.
fn load_ebpf(cli: &Cli, config: &LoaderConfig, resolved: &[ResolvedEndpoint]) -> Result<BpfState> {
    let obj_path = find_bpf_object(cli)?;
    info!(path = %obj_path.display(), "loading eBPF object");

    let mut bpf = aya::Ebpf::load_file(&obj_path)
        .map_err(|e| {
            // Provide helpful diagnostics for common failures.
            let hint = if e.to_string().contains("Operation not permitted") {
                "\n\nHint: Loading eBPF programs requires CAP_BPF (or root). \
                 Try running with: sudo gateway-ebpf-loader ..."
            } else if e.to_string().contains("Invalid argument") {
                "\n\nHint: The eBPF program may require a newer kernel. \
                 Linux 5.15+ is recommended."
            } else {
                ""
            };
            anyhow::anyhow!("failed to load eBPF program: {}{}", e, hint)
        })?;

    // Initialize aya-log forwarding to tracing (best-effort).
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        warn!(error = %e, "failed to init eBPF logger (non-fatal)");
    }

    // Populate the PROXY_PORT map.
    let mut proxy_port_map: aya::maps::Array<_, u16> = aya::maps::Array::try_from(
        bpf.map_mut("PROXY_PORT")
            .context("PROXY_PORT map not found in eBPF object")?,
    )?;
    proxy_port_map
        .set(0, config.proxy_port, 0)
        .context("failed to set PROXY_PORT")?;
    info!(port = config.proxy_port, "set PROXY_PORT map");

    // Populate the ENDPOINTS map.
    populate_endpoint_map(&mut bpf, resolved)?;

    // Attach the connect4 program to the cgroup.
    use aya::programs::{CgroupAttachMode, CgroupSockAddr};
    let prog: &mut CgroupSockAddr = bpf
        .program_mut("connect4_redirect")
        .context("connect4_redirect program not found in eBPF object")?
        .try_into()
        .context("program is not a CgroupSockAddr type")?;

    let cgroup_path = std::path::Path::new(&config.cgroup_path);
    let cgroup_fd = std::fs::File::open(cgroup_path)
        .with_context(|| format!("failed to open cgroup: {}", config.cgroup_path))?;

    prog.load().context("failed to load connect4 program")?;
    prog.attach(&cgroup_fd, CgroupAttachMode::Single)
        .context("failed to attach connect4 program to cgroup")?;

    info!(cgroup = %config.cgroup_path, "attached connect4_redirect to cgroup");

    Ok(BpfState { bpf })
}

/// Populate the ENDPOINTS BPF hash map with resolved IPs.
fn populate_endpoint_map(bpf: &mut aya::Ebpf, resolved: &[ResolvedEndpoint]) -> Result<()> {
    let mut endpoints_map: aya::maps::HashMap<_, EndpointKey, u8> =
        aya::maps::HashMap::try_from(
            bpf.map_mut("ENDPOINTS")
                .context("ENDPOINTS map not found in eBPF object")?,
        )?;

    for ep in resolved {
        // Port in the map key must be in network byte order to match
        // what the kernel eBPF program sees.
        let key = EndpointKey::new(ep.ip_be, ep.port.to_be());
        endpoints_map
            .insert(key, 1, 0)
            .with_context(|| format!("failed to insert endpoint {:?}", ep))?;
    }

    info!(count = resolved.len(), "populated ENDPOINTS map");
    Ok(())
}

/// Update the ENDPOINTS map with a fresh set of resolved IPs.
/// Clears existing entries and repopulates.
fn update_endpoint_map(state: &mut BpfState, resolved: &[ResolvedEndpoint]) -> Result<()> {
    // Collect existing keys to remove them.
    let endpoints_map: aya::maps::HashMap<_, EndpointKey, u8> =
        aya::maps::HashMap::try_from(
            state
                .bpf
                .map_mut("ENDPOINTS")
                .context("ENDPOINTS map not found")?,
        )?;

    let existing_keys: Vec<EndpointKey> =
        endpoints_map.keys().filter_map(|k| k.ok()).collect();
    drop(endpoints_map);

    let mut endpoints_map: aya::maps::HashMap<_, EndpointKey, u8> =
        aya::maps::HashMap::try_from(
            state
                .bpf
                .map_mut("ENDPOINTS")
                .context("ENDPOINTS map not found")?,
        )?;

    for key in existing_keys {
        let _ = endpoints_map.remove(&key);
    }

    // Repopulate with new resolved addresses.
    for ep in resolved {
        let key = EndpointKey::new(ep.ip_be, ep.port.to_be());
        endpoints_map
            .insert(key, 1, 0)
            .with_context(|| format!("failed to insert endpoint {:?}", ep))?;
    }

    info!(count = resolved.len(), "updated ENDPOINTS map");
    Ok(())
}
