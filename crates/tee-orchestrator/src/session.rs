use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveSessionRecord {
    pub session_id: String,
    pub agreement_id: String,
    pub enclave_id: String,
}
