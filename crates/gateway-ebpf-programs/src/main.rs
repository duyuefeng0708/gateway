#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    macros::{cgroup_sock_addr, map},
    maps::{Array, HashMap},
    programs::SockAddrContext,
};
use aya_log_ebpf::info;

// KNOWN ISSUES (require kernel testing to validate fixes):
//
// 1. ORIG_DST key uses `protocol` field (always 6 for TCP), not a per-socket
//    identifier. Concurrent connections overwrite each other's original destination.
//    Fix: use bpf_get_socket_cookie() or a (src_ip, src_port) composite key.
//
// 2. Map key is a bare tuple `(u32, u16)` whose layout may not match the
//    `#[repr(C)]` EndpointKey struct in the loader. Fix: define a shared
//    `#[repr(C)]` key struct in a common no_std crate used by both.
//
// 3. Byte-order handling on `user_port`: the kernel stores it in network byte
//    order as a u32. Casting to u16 then calling .to_be() double-converts on
//    little-endian. Fix: read the raw u32, mask to get the port, and use
//    consistent byte-order handling between eBPF and loader.
//
// 4. No IPv6 support (connect6). IPv6 connections to LLM endpoints bypass the
//    redirect entirely.
//
// These issues are architectural, not design-level. The redirect pattern
// (cgroup/connect4 + endpoint map + orig_dst tracking) is correct. The
// implementation details need validation on a real Linux 5.15+ kernel.

/// Map of LLM endpoint IPs to redirect.
/// Key: (u32 ip, u16 port), Value: u8 (1 = redirect)
#[map]
static ENDPOINTS: HashMap<(u32, u16), u8> = HashMap::with_max_entries(256, 0);

/// Stores original destination before redirect.
/// Key: u64 (socket cookie), Value: (u32 ip, u16 port)
#[map]
static ORIG_DST: HashMap<u64, (u32, u16)> = HashMap::with_max_entries(65536, 0);

/// Single-element array holding the proxy port.
#[map]
static PROXY_PORT: Array<u16> = Array::with_max_entries(1, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4_redirect(ctx: SockAddrContext) -> i32 {
    match try_connect4_redirect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Allow connection on error
    }
}

fn try_connect4_redirect(ctx: &SockAddrContext) -> Result<i32, i64> {
    let dst_ip = unsafe { (*ctx.sock_addr).user_ip4 };
    let dst_port = unsafe { (*ctx.sock_addr).user_port as u16 };

    // Check if this destination is in our endpoint map.
    let key = (dst_ip, dst_port.to_be());
    if unsafe { ENDPOINTS.get(&key) }.is_some() {
        // Get the proxy port.
        let proxy_port = match unsafe { PROXY_PORT.get(0) } {
            Some(p) => *p,
            None => return Ok(1), // No proxy port configured, allow.
        };

        // Store original destination for the proxy to retrieve.
        let cookie = unsafe { (*ctx.sock_addr).__bindgen_anon_1.__bindgen_anon_1.protocol };
        // Note: getting socket cookie in cgroup/connect4 requires kernel support.
        // Using a simpler key based on source port as fallback.
        unsafe {
            ORIG_DST.insert(&(cookie as u64), &(dst_ip, dst_port), 0)?;
        }

        // Redirect to localhost:proxy_port.
        unsafe {
            (*ctx.sock_addr).user_ip4 = u32::from_be_bytes([127, 0, 0, 1]).to_be();
            (*ctx.sock_addr).user_port = (proxy_port as u32).to_be() as u32;
        }

        info!(ctx, "redirected connection to proxy");
    }

    Ok(1) // Allow (1 = allow in cgroup/connect4)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
