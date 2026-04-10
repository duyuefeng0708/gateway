//! Userspace eBPF loader for the Privacy Gateway.
//!
//! Loads pre-compiled eBPF connect4 and connect6 programs, attaches them to a
//! cgroup, and populates BPF maps with resolved LLM endpoint IPs so that
//! outbound connections are transparently redirected to the local proxy.

mod config;
mod dns;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use config::LoaderConfig;
use dns::{resolve_endpoints, ResolvedEndpoint, ResolvedEndpoint6, ResolvedEndpoints};

/// Privacy Gateway eBPF loader.
///
/// Loads BPF connect4 and connect6 programs that transparently redirect
/// LLM API traffic through the local privacy proxy.
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
    let resolved = resolve_endpoints(&config.endpoints).await;
    if resolved.is_empty() {
        bail!(
            "no endpoints could be resolved; check your DNS and endpoint configuration"
        );
    }
    info!(
        v4_count = resolved.v4.len(),
        v6_count = resolved.v6.len(),
        "resolved endpoint IPs"
    );
    for ep in &resolved.v4 {
        let octets = ep.ip_be.to_ne_bytes();
        info!(
            ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
            port = ep.port,
            "endpoint IPv4"
        );
    }
    for ep in &resolved.v6 {
        info!(
            ip6 = format!("{:08x}:{:08x}:{:08x}:{:08x}", ep.ip6_be[0], ep.ip6_be[1], ep.ip6_be[2], ep.ip6_be[3]),
            port = ep.port,
            "endpoint IPv6"
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
    //
    // We maintain in-memory sets of tuples that mirror what is currently in
    // the BPF ENDPOINTS and ENDPOINTS6 maps.  This lets us compute stale
    // entries without iterating the BPF maps.
    let refresh_config = config.clone();
    let refresh_shutdown = shutdown.clone();
    let bpf_handle = Arc::new(tokio::sync::Mutex::new(bpf));
    let bpf_for_refresh = bpf_handle.clone();

    // Seed the tracking sets from the initial resolution.
    let initial_known_v4: HashSet<(u32, u16)> = resolved
        .v4
        .iter()
        .map(|ep| (ep.ip_be, ep.port))
        .collect();
    let initial_known_v6: HashSet<([u32; 4], u16)> = resolved
        .v6
        .iter()
        .map(|ep| (ep.ip6_be, ep.port))
        .collect();

    tokio::spawn(async move {
        let interval = Duration::from_secs(refresh_config.dns_refresh_interval);
        let mut tick = tokio::time::interval(interval);
        tick.tick().await; // Skip the first immediate tick.

        let mut known_v4 = initial_known_v4;
        let mut known_v6 = initial_known_v6;

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    info!("refreshing DNS for endpoints");
                    let new_resolved = resolve_endpoints(&refresh_config.endpoints).await;
                    if new_resolved.is_empty() {
                        warn!("DNS refresh returned no results, keeping existing entries");
                        continue;
                    }
                    info!(
                        v4_count = new_resolved.v4.len(),
                        v6_count = new_resolved.v6.len(),
                        "DNS refresh complete"
                    );

                    // Update the BPF maps with insert-before-delete.
                    let mut bpf_guard = bpf_for_refresh.lock().await;
                    if let Err(e) = update_endpoint_maps(
                        &mut bpf_guard,
                        &new_resolved,
                        &mut known_v4,
                        &mut known_v6,
                    ) {
                        error!(error = %e, "failed to update endpoint maps");
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
fn print_dry_run_summary(config: &LoaderConfig, resolved: &ResolvedEndpoints) {
    println!("\n=== Dry Run Summary ===\n");
    println!("Proxy port:    {}", config.proxy_port);
    println!("Cgroup path:   {}", config.cgroup_path);
    println!("DNS refresh:   {}s", config.dns_refresh_interval);
    println!("Endpoints:     {}", config.endpoints.len());
    println!("Resolved IPv4: {}", resolved.v4.len());
    println!("Resolved IPv6: {}", resolved.v6.len());
    println!();
    for ep in &resolved.v4 {
        let octets = ep.ip_be.to_ne_bytes();
        println!(
            "  {}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], ep.port
        );
    }
    for ep in &resolved.v6 {
        println!(
            "  [{:08x}:{:08x}:{:08x}:{:08x}]:{}",
            ep.ip6_be[0], ep.ip6_be[1], ep.ip6_be[2], ep.ip6_be[3], ep.port
        );
    }
    println!("\nAll checks passed. Ready to load eBPF programs.");
}

// ---------------------------------------------------------------------------
// eBPF loading and map management
//
// These functions use the `aya` crate to load the pre-compiled eBPF object,
// attach the connect4 and connect6 programs to the target cgroup, and
// populate the ENDPOINTS, ENDPOINTS6, and PROXY_PORT BPF maps.
// ---------------------------------------------------------------------------

/// BPF map key for the ENDPOINTS hash map (IPv4).
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

/// BPF map key for the ENDPOINTS6 hash map (IPv6).
///
/// Must match the layout used by the eBPF kernel program: `([u32; 4], u16)`.
/// We use a `#[repr(C)]` struct so it implements `Pod` for aya.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Endpoint6Key {
    ip6: [u32; 4],
    port: u16,
    // Padding to align to the struct size the kernel sees for ([u32;4], u16).
    _pad: u16,
}

// SAFETY: Endpoint6Key is #[repr(C)], contains only Copy types, and has
// no padding that could contain uninitialized bytes (we explicitly include
// the padding field).
unsafe impl aya::Pod for Endpoint6Key {}

impl Endpoint6Key {
    fn new(ip6_be: [u32; 4], port_be: u16) -> Self {
        Self {
            ip6: ip6_be,
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

/// Load the eBPF programs, attach them, and populate maps.
fn load_ebpf(cli: &Cli, config: &LoaderConfig, resolved: &ResolvedEndpoints) -> Result<BpfState> {
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

    // Populate the ENDPOINTS map (IPv4).
    populate_endpoint_map(&mut bpf, &resolved.v4)?;

    // Populate the ENDPOINTS6 map (IPv6).
    populate_endpoint6_map(&mut bpf, &resolved.v6)?;

    let cgroup_path = std::path::Path::new(&config.cgroup_path);
    let cgroup_fd = std::fs::File::open(cgroup_path)
        .with_context(|| format!("failed to open cgroup: {}", config.cgroup_path))?;

    // Attach the connect4 program to the cgroup.
    use aya::programs::{CgroupAttachMode, CgroupSockAddr};
    let prog: &mut CgroupSockAddr = bpf
        .program_mut("connect4_redirect")
        .context("connect4_redirect program not found in eBPF object")?
        .try_into()
        .context("program is not a CgroupSockAddr type")?;

    prog.load().context("failed to load connect4 program")?;
    prog.attach(&cgroup_fd, CgroupAttachMode::Single)
        .context("failed to attach connect4 program to cgroup")?;

    info!(cgroup = %config.cgroup_path, "attached connect4_redirect to cgroup");

    // Attach the connect6 program to the cgroup (best-effort, non-fatal).
    // The BPF verifier on some kernels rejects direct user_ip6 access in
    // cgroup/connect6 programs. If connect6 fails to load, IPv4 interception
    // still works — only IPv6 connections bypass the redirect.
    match bpf.program_mut("connect6_redirect") {
        Some(prog6_any) => {
            let result: Result<()> = (|| {
                let prog6: &mut CgroupSockAddr = prog6_any
                    .try_into()
                    .context("connect6 program is not a CgroupSockAddr type")?;
                prog6.load().context("failed to load connect6 program")?;
                prog6
                    .attach(&cgroup_fd, CgroupAttachMode::Single)
                    .context("failed to attach connect6 program to cgroup")?;
                info!(cgroup = %config.cgroup_path, "attached connect6_redirect to cgroup");
                Ok(())
            })();
            if let Err(e) = result {
                warn!("connect6 failed to load (non-fatal, IPv4 still active): {e:#}");
            }
        }
        None => {
            warn!("connect6_redirect program not found in eBPF object, IPv6 interception disabled");
        }
    }

    Ok(BpfState { bpf })
}

/// Populate the ENDPOINTS BPF hash map with resolved IPv4 addresses.
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

/// Populate the ENDPOINTS6 BPF hash map with resolved IPv6 addresses.
fn populate_endpoint6_map(bpf: &mut aya::Ebpf, resolved: &[ResolvedEndpoint6]) -> Result<()> {
    if resolved.is_empty() {
        return Ok(());
    }

    let map = match bpf.map_mut("ENDPOINTS6") {
        Some(m) => m,
        None => {
            warn!("ENDPOINTS6 map not found in eBPF object, skipping IPv6 population");
            return Ok(());
        }
    };

    let mut endpoints_map: aya::maps::HashMap<_, Endpoint6Key, u8> =
        aya::maps::HashMap::try_from(map)?;

    for ep in resolved {
        let key = Endpoint6Key::new(ep.ip6_be, ep.port.to_be());
        endpoints_map
            .insert(key, 1, 0)
            .with_context(|| format!("failed to insert IPv6 endpoint {:?}", ep))?;
    }

    info!(count = resolved.len(), "populated ENDPOINTS6 map");
    Ok(())
}

/// Update both the IPv4 ENDPOINTS and IPv6 ENDPOINTS6 maps with a fresh
/// set of resolved IPs.
///
/// Uses insert-before-delete to avoid a window where the maps are empty:
///   1. Insert all new entries (duplicates are idempotent with BPF_ANY).
///   2. Compute stale entries (old minus new) and delete only those.
///   3. Update the in-memory tracking sets.
fn update_endpoint_maps(
    state: &mut BpfState,
    resolved: &ResolvedEndpoints,
    known_v4: &mut HashSet<(u32, u16)>,
    known_v6: &mut HashSet<([u32; 4], u16)>,
) -> Result<()> {
    // --- IPv4 ENDPOINTS map ---
    update_endpoint_map_v4(state, &resolved.v4, known_v4)?;

    // --- IPv6 ENDPOINTS6 map (best-effort; map may not exist) ---
    if !resolved.v6.is_empty() || !known_v6.is_empty() {
        if let Err(e) = update_endpoint_map_v6(state, &resolved.v6, known_v6) {
            warn!(error = %e, "failed to update ENDPOINTS6 map (IPv6 interception may be unavailable)");
        }
    }

    Ok(())
}

/// Update the IPv4 ENDPOINTS map with insert-before-delete.
fn update_endpoint_map_v4(
    state: &mut BpfState,
    resolved: &[ResolvedEndpoint],
    known_entries: &mut HashSet<(u32, u16)>,
) -> Result<()> {
    let mut endpoints_map: aya::maps::HashMap<_, EndpointKey, u8> =
        aya::maps::HashMap::try_from(
            state
                .bpf
                .map_mut("ENDPOINTS")
                .context("ENDPOINTS map not found")?,
        )?;

    // Build the new set of (ip_be, port) tuples.
    let new_set: HashSet<(u32, u16)> = resolved
        .iter()
        .map(|ep| (ep.ip_be, ep.port))
        .collect();

    // Step 1: Insert all new entries.  BPF_ANY (flags=0 in aya) means
    // existing keys are overwritten silently, so duplicates are fine.
    for ep in resolved {
        let key = EndpointKey::new(ep.ip_be, ep.port.to_be());
        endpoints_map
            .insert(key, 1, 0)
            .with_context(|| format!("failed to insert endpoint {:?}", ep))?;
    }

    // Step 2: Delete stale entries (present in known_entries but not in new_set).
    let stale: Vec<(u32, u16)> = known_entries.difference(&new_set).copied().collect();
    for (ip_be, port) in &stale {
        let key = EndpointKey::new(*ip_be, port.to_be());
        if let Err(e) = endpoints_map.remove(&key) {
            warn!(
                ip_be = ip_be,
                port = port,
                error = %e,
                "failed to remove stale IPv4 endpoint (may already be absent)"
            );
        }
    }

    if !stale.is_empty() {
        info!(removed = stale.len(), "removed stale IPv4 endpoints");
    }

    // Step 3: Update the tracking set.
    *known_entries = new_set;

    info!(count = resolved.len(), "updated ENDPOINTS map");
    Ok(())
}

/// Update the IPv6 ENDPOINTS6 map with insert-before-delete.
fn update_endpoint_map_v6(
    state: &mut BpfState,
    resolved: &[ResolvedEndpoint6],
    known_entries: &mut HashSet<([u32; 4], u16)>,
) -> Result<()> {
    let mut endpoints_map: aya::maps::HashMap<_, Endpoint6Key, u8> =
        aya::maps::HashMap::try_from(
            state
                .bpf
                .map_mut("ENDPOINTS6")
                .context("ENDPOINTS6 map not found")?,
        )?;

    // Build the new set.
    let new_set: HashSet<([u32; 4], u16)> = resolved
        .iter()
        .map(|ep| (ep.ip6_be, ep.port))
        .collect();

    // Step 1: Insert all new entries.
    for ep in resolved {
        let key = Endpoint6Key::new(ep.ip6_be, ep.port.to_be());
        endpoints_map
            .insert(key, 1, 0)
            .with_context(|| format!("failed to insert IPv6 endpoint {:?}", ep))?;
    }

    // Step 2: Delete stale entries.
    let stale: Vec<([u32; 4], u16)> = known_entries.difference(&new_set).copied().collect();
    for (ip6_be, port) in &stale {
        let key = Endpoint6Key::new(*ip6_be, port.to_be());
        if let Err(e) = endpoints_map.remove(&key) {
            warn!(
                port = port,
                error = %e,
                "failed to remove stale IPv6 endpoint (may already be absent)"
            );
        }
    }

    if !stale.is_empty() {
        info!(removed = stale.len(), "removed stale IPv6 endpoints");
    }

    // Step 3: Update the tracking set.
    *known_entries = new_set;

    info!(count = resolved.len(), "updated ENDPOINTS6 map");
    Ok(())
}
