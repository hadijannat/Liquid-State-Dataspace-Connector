use async_trait::async_trait;
use lsdc_common::crypto::ProvenanceReceipt;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::odrl::ast::PolicyAgreement;
use lsdc_common::traits::{ProofEngine, TransformSpec};

/// RISC Zero-backed proof engine for generating and verifying
/// zero-knowledge proofs of data transformation compliance.
///
/// # Sprint 0 Status
/// All methods are stubbed. Sprint 1 will integrate risc0-zkvm.
pub struct RiscZeroProofEngine;

impl RiscZeroProofEngine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProofEngine for RiscZeroProofEngine {
    async fn prove_transform(
        &self,
        _input_hash: &[u8; 32],
        _policy: &PolicyAgreement,
        _transform: &TransformSpec,
    ) -> Result<ProvenanceReceipt> {
        Err(LsdcError::ProofGeneration(
            "RISC Zero integration not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn verify_receipt(&self, _receipt: &ProvenanceReceipt) -> Result<bool> {
        Err(LsdcError::ProofGeneration(
            "Receipt verification not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn verify_chain(&self, _chain: &[ProvenanceReceipt]) -> Result<bool> {
        Err(LsdcError::ProofGeneration(
            "Recursive chain verification not yet implemented (Sprint 1)".into(),
        ))
    }
}
