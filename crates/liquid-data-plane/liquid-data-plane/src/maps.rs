use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const SESSION_AGREEMENT_MAP: &str = "SESSION_AGREEMENT_MAP";
pub const PACKET_LIMIT_MAP: &str = "PACKET_LIMIT_MAP";
pub const BYTE_LIMIT_MAP: &str = "BYTE_LIMIT_MAP";
pub const PACKET_COUNT_MAP: &str = "PACKET_COUNT_MAP";
pub const BYTE_COUNT_MAP: &str = "BYTE_COUNT_MAP";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledPolicy {
    pub agreement_id: String,
    pub enforcement_key: u32,
    pub session_port: u16,
    pub max_packets: Option<u64>,
    pub max_bytes: Option<u64>,
    pub expires_at: Option<DateTime<Utc>>,
}
