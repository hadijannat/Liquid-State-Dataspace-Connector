use chrono::{DateTime, Utc};
use lsdc_common::dsp::TransportProtocol;
use lsdc_common::execution::TransportSelector;
use lsdc_ports::{EnforcementIdentity, ResolvedTransportGuard};
use serde::{Deserialize, Serialize};

pub const SELECTOR_AGREEMENT_MAP: &str = "SELECTOR_AGREEMENT_MAP";
pub const PACKET_LIMIT_MAP: &str = "PACKET_LIMIT_MAP";
pub const BYTE_LIMIT_MAP: &str = "BYTE_LIMIT_MAP";
pub const PACKET_COUNT_MAP: &str = "PACKET_COUNT_MAP";
pub const BYTE_COUNT_MAP: &str = "BYTE_COUNT_MAP";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledPolicy {
    pub agreement_id: String,
    pub enforcement_key: u32,
    pub transport_selector: TransportSelector,
    pub selector_key: u32,
    pub max_packets: Option<u64>,
    pub max_bytes: Option<u64>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CompiledPolicy {
    pub fn session_port(&self) -> u16 {
        self.transport_selector.port
    }

    pub fn resolved_transport(&self) -> ResolvedTransportGuard {
        ResolvedTransportGuard {
            selector: self.transport_selector.clone(),
            enforcement: EnforcementIdentity {
                agreement_id: self.agreement_id.clone(),
                enforcement_key: self.enforcement_key,
            },
            packet_cap: self.max_packets,
            byte_cap: self.max_bytes,
            expires_at: self.expires_at,
        }
    }
}

pub fn selector_key(selector: &TransportSelector) -> u32 {
    ((protocol_id(selector.protocol) as u32) << 16) | selector.port as u32
}

fn protocol_id(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
    }
}
