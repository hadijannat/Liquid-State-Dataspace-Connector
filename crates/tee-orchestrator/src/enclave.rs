use async_trait::async_trait;
use lsdc_common::crypto::{AttestationDocument, ProofOfForgetting};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{EnclaveManager, EnclaveSession};

/// AWS Nitro Enclave-backed TEE manager.
///
/// # Sprint 0 Status
/// All methods return errors. Sprint 1 will integrate with AWS Nitro Enclaves SDK.
#[derive(Default)]
pub struct NitroEnclaveManager;

impl NitroEnclaveManager {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EnclaveManager for NitroEnclaveManager {
    async fn create_enclave(&self, _binary_hash: &[u8; 32]) -> Result<EnclaveSession> {
        Err(LsdcError::Attestation(
            "Nitro Enclave creation not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn attest(&self, _session: &EnclaveSession) -> Result<AttestationDocument> {
        Err(LsdcError::Attestation(
            "Attestation not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn destroy_and_prove(&self, _session: EnclaveSession) -> Result<ProofOfForgetting> {
        Err(LsdcError::Attestation(
            "Proof-of-Forgetting not yet implemented (Sprint 1)".into(),
        ))
    }
}
