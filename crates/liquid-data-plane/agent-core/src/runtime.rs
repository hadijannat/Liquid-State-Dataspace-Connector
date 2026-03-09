use chrono::{DateTime, Utc};
use lsdc_common::execution::TransportSelector;
use lsdc_ports::ResolvedTransportGuard;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(crate) struct State {
    pub(crate) tracked: HashMap<String, TrackedEnforcement>,
    pub(crate) interfaces: HashMap<String, InterfaceRuntime>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataPlaneMode {
    Kernel,
    Simulated,
}

pub(crate) struct InterfaceRuntime {
    pub(crate) active_handles: HashSet<String>,
    #[cfg(target_os = "linux")]
    pub(crate) attachment: Option<LinuxAttachment>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleState {
    Active,
    Expired,
    Revoked,
    Error(String),
}

#[allow(dead_code)]
pub(crate) struct TrackedEnforcement {
    pub(crate) interface: String,
    pub(crate) enforcement_key: u32,
    pub(crate) selector_key: u32,
    pub(crate) transport_selector: TransportSelector,
    pub(crate) resolved_transport: ResolvedTransportGuard,
    pub(crate) max_packets: Option<u64>,
    pub(crate) max_bytes: Option<u64>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) state: LifecycleState,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxAttachment {
    pub(crate) ebpf: aya::Ebpf,
    pub(crate) link_id: Option<aya::programs::xdp::XdpLinkId>,
}
