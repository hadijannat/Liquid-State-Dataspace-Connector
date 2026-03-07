#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;

#[map]
static SELECTOR_AGREEMENT_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static PACKET_LIMIT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static BYTE_LIMIT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static PACKET_COUNT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static BYTE_COUNT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn lsdc_xdp(ctx: XdpContext) -> u32 {
    match try_lsdc_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lsdc_xdp(ctx: XdpContext) -> Result<u32, u32> {
    let Some(selector_key) = parse_selector_key(&ctx)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    let Some(agreement_id) = unsafe { SELECTOR_AGREEMENT_MAP.get(&selector_key) }.copied() else {
        return Ok(xdp_action::XDP_PASS);
    };

    let packet_length = (ctx.data_end() - ctx.data()) as u64;
    let max_packets = unsafe { PACKET_LIMIT_MAP.get(&agreement_id) }
        .copied()
        .unwrap_or(u64::MAX);
    let max_bytes = unsafe { BYTE_LIMIT_MAP.get(&agreement_id) }
        .copied()
        .unwrap_or(u64::MAX);

    let packet_count = unsafe { PACKET_COUNT_MAP.get(&agreement_id) }
        .copied()
        .unwrap_or(0);
    let byte_count = unsafe { BYTE_COUNT_MAP.get(&agreement_id) }
        .copied()
        .unwrap_or(0);

    if packet_count >= max_packets || byte_count.saturating_add(packet_length) > max_bytes {
        return Ok(xdp_action::XDP_DROP);
    }

    let next_packets = packet_count + 1;
    let next_bytes = byte_count + packet_length;

    unsafe {
        let _ = PACKET_COUNT_MAP.insert(&agreement_id, &next_packets, 0);
        let _ = BYTE_COUNT_MAP.insert(&agreement_id, &next_bytes, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

fn parse_selector_key(ctx: &XdpContext) -> Result<Option<u32>, u32> {
    let start = ctx.data();
    let first = unsafe { ptr_at::<u8>(ctx, 0)? };
    let version = unsafe { *first } >> 4;
    let ip_offset = if version == 4 || version == 6 { 0 } else { 14 };

    let version_ihl = unsafe { *ptr_at::<u8>(ctx, ip_offset)? };
    if version_ihl >> 4 != 4 {
        return Ok(None);
    }

    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    let protocol = unsafe { *ptr_at::<u8>(ctx, ip_offset + 9)? };
    if protocol != 6 && protocol != 17 {
        return Ok(None);
    }

    let port_ptr = unsafe { ptr_at::<u16>(ctx, ip_offset + ihl + 2)? };
    let dst_port = u16::from_be(unsafe { *port_ptr });
    let selector_key = ((protocol as u32) << 16) | dst_port as u32;
    let _ = start;
    Ok(Some(selector_key))
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(1);
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
