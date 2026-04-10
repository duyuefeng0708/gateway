#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::{Array, HashMap},
    programs::SockAddrContext,
    helpers::bpf_get_socket_cookie,
};

// Shared key struct for endpoint map. Must match the loader's EndpointKey
// exactly: #[repr(C)], 8 bytes total (4-byte IP + 2-byte port + 2-byte pad).
//
// IP and port are in network byte order (big-endian).
#[repr(C)]
#[derive(Clone, Copy)]
struct EndpointKey {
    ip: u32,
    port: u16,
    _pad: u16,
}

// Shared value struct for original destination tracking.
#[repr(C)]
#[derive(Clone, Copy)]
struct OrigDst {
    ip: u32,
    port: u16,
    _pad: u16,
}

// Shared key struct for IPv6 endpoint map. Must match the loader's EndpointKey6
// exactly: #[repr(C)], 20 bytes total (16-byte IPv6 + 2-byte port + 2-byte pad).
//
// IP and port are in network byte order (big-endian).
#[repr(C)]
#[derive(Clone, Copy)]
struct EndpointKey6 {
    ip6: [u32; 4],
    port: u16,
    _pad: u16,
}

// Shared value struct for IPv6 original destination tracking.
#[repr(C)]
#[derive(Clone, Copy)]
struct OrigDst6 {
    ip6: [u32; 4],
    port: u16,
    _pad: u16,
}

/// Map of LLM endpoint IPs to redirect.
/// Key: EndpointKey (ip + port, network byte order), Value: u8 (1 = redirect)
#[map]
static ENDPOINTS: HashMap<EndpointKey, u8> = HashMap::with_max_entries(256, 0);

/// Stores original destination before redirect.
/// Key: u64 (socket cookie, unique per socket), Value: OrigDst
#[map]
static ORIG_DST: HashMap<u64, OrigDst> = HashMap::with_max_entries(65536, 0);

/// Map of IPv6 LLM endpoint IPs to redirect.
/// Key: EndpointKey6 (ip6 + port, network byte order), Value: u8 (1 = redirect)
#[map]
static ENDPOINTS6: HashMap<EndpointKey6, u8> = HashMap::with_max_entries(256, 0);

/// Stores original IPv6 destination before redirect.
/// Key: u64 (socket cookie, unique per socket), Value: OrigDst6
#[map]
static ORIG_DST6: HashMap<u64, OrigDst6> = HashMap::with_max_entries(65536, 0);

/// Single-element array holding the proxy port in host byte order.
#[map]
static PROXY_PORT: Array<u16> = Array::with_max_entries(1, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4_redirect(ctx: SockAddrContext) -> i32 {
    match try_connect4_redirect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Allow connection on error (fail-open for network stability)
    }
}

fn try_connect4_redirect(ctx: &SockAddrContext) -> Result<i32, i64> {
    // user_ip4: network byte order u32
    let dst_ip = unsafe { (*ctx.sock_addr).user_ip4 };

    // user_port: network byte order u32. The port is stored in the upper 16
    // bits when read as a host-endian u32 on little-endian systems.
    let dst_port_raw = unsafe { (*ctx.sock_addr).user_port };
    let dst_port_ne = (dst_port_raw >> 16) as u16;

    // Build the lookup key. Both IP and port are in network byte order.
    let key = EndpointKey {
        ip: dst_ip,
        port: dst_port_ne,
        _pad: 0,
    };

    // Check if this destination is in our endpoint map.
    if unsafe { ENDPOINTS.get(&key) }.is_some() {
        // Get the proxy port (stored in host byte order by the loader).
        let proxy_port = match PROXY_PORT.get(0) {
            Some(p) => *p,
            None => return Ok(1),
        };

        // Get unique socket cookie for per-connection ORIG_DST key.
        let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };

        // Store original destination for the proxy to retrieve later.
        let orig = OrigDst {
            ip: dst_ip,
            port: dst_port_ne,
            _pad: 0,
        };
        ORIG_DST.insert(&cookie, &orig, 0)?;

        // Redirect to 127.0.0.1:proxy_port
        unsafe {
            // 127.0.0.1 in network byte order
            (*ctx.sock_addr).user_ip4 = 0x7F000001_u32.to_be();
            // Port in the u32 network-order format
            let port_be = proxy_port.to_be();
            (*ctx.sock_addr).user_port = (port_be as u32) << 16;
        }
    }

    Ok(1) // 1 = allow in cgroup/connect4
}

#[cgroup_sock_addr(connect6)]
pub fn connect6_redirect(ctx: SockAddrContext) -> i32 {
    match try_connect6_redirect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Allow connection on error (fail-open for network stability)
    }
}

fn try_connect6_redirect(ctx: &SockAddrContext) -> Result<i32, i64> {
    // user_ip6: network byte order [u32; 4]
    let dst_ip6 = unsafe { (*ctx.sock_addr).user_ip6 };

    // user_port: network byte order u32. The port is stored in the upper 16
    // bits when read as a host-endian u32 on little-endian systems.
    let dst_port_raw = unsafe { (*ctx.sock_addr).user_port };
    let dst_port_ne = (dst_port_raw >> 16) as u16;

    // Build the lookup key. Both IP and port are in network byte order.
    let key = EndpointKey6 {
        ip6: dst_ip6,
        port: dst_port_ne,
        _pad: 0,
    };

    // Check if this destination is in our IPv6 endpoint map.
    if unsafe { ENDPOINTS6.get(&key) }.is_some() {
        // Get the proxy port (stored in host byte order by the loader).
        let proxy_port = match PROXY_PORT.get(0) {
            Some(p) => *p,
            None => return Ok(1),
        };

        // Get unique socket cookie for per-connection ORIG_DST6 key.
        let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };

        // Store original destination for the proxy to retrieve later.
        let orig = OrigDst6 {
            ip6: dst_ip6,
            port: dst_port_ne,
            _pad: 0,
        };
        ORIG_DST6.insert(&cookie, &orig, 0)?;

        // Redirect to [::1]:proxy_port
        unsafe {
            // ::1 in network byte order
            (*ctx.sock_addr).user_ip6 = [0, 0, 0, 1_u32.to_be()];
            // Port in the u32 network-order format
            let port_be = proxy_port.to_be();
            (*ctx.sock_addr).user_port = (port_be as u32) << 16;
        }
    }

    Ok(1) // 1 = allow in cgroup/connect6
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
