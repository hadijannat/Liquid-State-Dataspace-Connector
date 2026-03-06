use lsdc_common::crypto::AttestationDocument;
use lsdc_common::error::{LsdcError, Result};

/// Verify an attestation document against a trusted root certificate.
///
/// # Sprint 0 Status
/// Stubbed. Sprint 1 will implement AWS Nitro root cert verification.
pub fn verify_attestation(_doc: &AttestationDocument) -> Result<bool> {
    Err(LsdcError::Attestation(
        "Attestation verification not yet implemented".into(),
    ))
}
