use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub String);

impl PolicyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAgreement {
    pub id: PolicyId,
    pub provider: String,
    pub consumer: String,
    pub target: String,
    pub permissions: Vec<Permission>,
    pub prohibitions: Vec<Prohibition>,
    pub obligations: Vec<Duty>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub action: Action,
    pub constraints: Vec<Constraint>,
    pub duties: Vec<Duty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prohibition {
    pub action: Action,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duty {
    pub action: Action,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    Use,
    Transfer,
    Stream,
    Read,
    Aggregate,
    Anonymize,
    Delete,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    Count { max: u64 },
    Spatial { allowed_regions: Vec<GeoRegion> },
    Temporal { not_after: DateTime<Utc> },
    Purpose { allowed: Vec<String> },
    RateLimit { max_per_second: u64 },
    Custom { key: String, value: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GeoRegion {
    EU,
    US,
    APAC,
    Custom(String),
}
