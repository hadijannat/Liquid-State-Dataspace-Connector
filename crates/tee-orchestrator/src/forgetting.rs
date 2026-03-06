use lsdc_common::crypto::ProofOfForgetting;
use lsdc_common::error::{LsdcError, Result};

/// Verify a Proof-of-Forgetting receipt.
pub fn verify_proof_of_forgetting(_proof: &ProofOfForgetting) -> Result<bool> {
    Err(LsdcError::Attestation(
        "Proof-of-Forgetting verification not yet implemented".into(),
    ))
}
