use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const ACTIVE_AGREEMENT_MAP: &str = "ACTIVE_AGREEMENT_MAP";
pub const RATE_LIMIT_MAP: &str = "RATE_LIMIT_MAP";
pub const PACKET_COUNT_MAP: &str = "PACKET_COUNT_MAP";
pub const ACTIVE_AGREEMENT_KEY: u32 = 0;

/// The reduced, executable Sprint 0 enforcement plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledPolicy {
    pub agreement_id: String,
    pub enforcement_key: u32,
    pub max_packets: u64,
    pub expires_at: Option<DateTime<Utc>>,
}
