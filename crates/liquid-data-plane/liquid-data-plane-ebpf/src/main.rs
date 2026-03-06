#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

const ACTIVE_AGREEMENT_KEY: u32 = 0;

/// Config map storing the single active agreement for this interface.
#[map]
static ACTIVE_AGREEMENT_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/// Rate limit map: agreement_id (u32) -> max_packets (u64)
#[map]
static RATE_LIMIT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Packet counter map: agreement_id (u32) -> current_count (u64)
#[map]
static PACKET_COUNT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

#[xdp]
pub fn lsdc_xdp(ctx: XdpContext) -> u32 {
    match try_lsdc_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lsdc_xdp(ctx: XdpContext) -> Result<u32, u32> {
    let Some(agreement_id) = (unsafe { ACTIVE_AGREEMENT_MAP.get(&ACTIVE_AGREEMENT_KEY) }).copied() else {
        // No active enforcement — pass all traffic
        return Ok(xdp_action::XDP_PASS);
    };

    // Check rate limit
    if let Some(max_packets) = unsafe { RATE_LIMIT_MAP.get(&agreement_id) } {
        let count = unsafe { PACKET_COUNT_MAP.get(&agreement_id) }
            .copied()
            .unwrap_or(0);

        if count >= *max_packets {
            // Rate limit exceeded — drop packet
            return Ok(xdp_action::XDP_DROP);
        }

        // Increment counter
        let new_count = count + 1;
        unsafe {
            let _ = PACKET_COUNT_MAP.insert(&agreement_id, &new_count, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
