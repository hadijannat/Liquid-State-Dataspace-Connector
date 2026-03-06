#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

/// Rate limit map: contract_id (u32) -> max_packets (u64)
#[map]
static RATE_LIMIT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Packet counter map: contract_id (u32) -> current_count (u64)
#[map]
static PACKET_COUNT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Expiry map: contract_id (u32) -> unix_timestamp (i64)
#[map]
static EXPIRY_MAP: HashMap<u32, i64> = HashMap::with_max_entries(256, 0);

/// Active contracts map: contract_id (u32) -> active (u32, 1=yes, 0=no)
#[map]
static ACTIVE_MAP: HashMap<u32, u32> = HashMap::with_max_entries(256, 0);

#[xdp]
pub fn lsdc_xdp(ctx: XdpContext) -> u32 {
    match try_lsdc_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lsdc_xdp(ctx: XdpContext) -> Result<u32, u32> {
    // For Sprint 0, we enforce a simple contract-based rate limit.
    // The user-space loader populates ACTIVE_MAP with the contract ID
    // and RATE_LIMIT_MAP with the max packet count.

    // Check if any contract is active (contract_id = 1 for MVP)
    let contract_id: u32 = 1;

    let active = unsafe { ACTIVE_MAP.get(&contract_id) };
    if active.is_none() || *active.unwrap() == 0 {
        // No active enforcement — pass all traffic
        return Ok(xdp_action::XDP_PASS);
    }

    // Check rate limit
    if let Some(max_packets) = unsafe { RATE_LIMIT_MAP.get(&contract_id) } {
        let count = unsafe { PACKET_COUNT_MAP.get(&contract_id) }
            .copied()
            .unwrap_or(0);

        if count >= *max_packets {
            // Rate limit exceeded — drop packet
            info!(&ctx, "LSDC: rate limit exceeded, dropping packet");
            return Ok(xdp_action::XDP_DROP);
        }

        // Increment counter
        let new_count = count + 1;
        unsafe {
            let _ = PACKET_COUNT_MAP.insert(&contract_id, &new_count, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
