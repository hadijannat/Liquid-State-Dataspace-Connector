use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyReleasePolicy {
    pub requires_attestation: bool,
    pub requires_teardown_evidence: bool,
}
