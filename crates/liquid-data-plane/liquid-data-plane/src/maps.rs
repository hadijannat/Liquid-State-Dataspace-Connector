use serde::{Deserialize, Serialize};

/// Represents a single entry to be inserted into an eBPF map.
/// These are the "compiled" form of ODRL constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MapEntry {
    /// Insert into RATE_LIMIT_MAP: contract_id -> max_packets
    RateLimit {
        contract_id: u32,
        max_packets: u64,
    },
    /// Insert into RATE_PER_SEC_MAP: contract_id -> max_per_second
    RatePerSecond {
        contract_id: u32,
        max_per_second: u64,
    },
    /// Insert into GEO_FENCE_MAP: ip_prefix -> allowed (1) or blocked (0)
    GeoFence {
        /// Encoded as u32 CIDR blocks for allowed source IPs
        allowed_cidrs: Vec<u32>,
    },
    /// Insert into EXPIRY_MAP: contract_id -> unix_timestamp
    Expiry {
        contract_id: u32,
        expiry_ts: i64,
    },
}

/// The full set of compiled map entries for a single policy agreement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledPolicy {
    pub contract_id: u32,
    pub entries: Vec<MapEntry>,
}
