use lsdc_common::crypto::{sign_bytes, verify_signature, ProofOfForgetting, Sha256Hash};
use lsdc_common::error::{LsdcError, Result};

pub(crate) const DEFAULT_FORGETTING_SECRET: &str = "lsdc-forgetting-dev-secret";

pub(crate) fn build_proof_of_forgetting(
    attestation: lsdc_common::crypto::AttestationDocument,
    destruction_timestamp: chrono::DateTime<chrono::Utc>,
    data_hash: &Sha256Hash,
) -> Result<ProofOfForgetting> {
    let payload = forgetting_payload_bytes(&attestation, destruction_timestamp, data_hash)?;
    let proof_hash = Sha256Hash::digest_bytes(&payload);
    let signature_hex = sign_bytes(&forgetting_secret(), &payload);

    Ok(ProofOfForgetting {
        attestation,
        destruction_timestamp,
        data_hash: data_hash.clone(),
        proof_hash,
        signature_hex,
    })
}

pub fn verify_proof_of_forgetting(proof: &ProofOfForgetting) -> Result<bool> {
    let payload = forgetting_payload_bytes(
        &proof.attestation,
        proof.destruction_timestamp,
        &proof.data_hash,
    )?;

    Ok(proof.proof_hash == Sha256Hash::digest_bytes(&payload)
        && verify_signature(&forgetting_secret(), &payload, &proof.signature_hex))
}

pub(crate) fn forgetting_secret() -> String {
    std::env::var("LSDC_FORGETTING_SECRET")
        .unwrap_or_else(|_| DEFAULT_FORGETTING_SECRET.to_string())
}

fn forgetting_payload_bytes(
    attestation: &lsdc_common::crypto::AttestationDocument,
    destruction_timestamp: chrono::DateTime<chrono::Utc>,
    data_hash: &Sha256Hash,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": attestation.enclave_id,
        "attestation_hash": attestation.document_hash.to_hex(),
        "destruction_timestamp": destruction_timestamp.to_rfc3339(),
        "data_hash": data_hash.to_hex(),
    }))
    .map_err(LsdcError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::build_attestation_document;

    #[test]
    fn test_build_and_verify_forgetting_proof() {
        let attestation = build_attestation_document(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            chrono::Utc::now(),
        )
        .unwrap();
        let proof = build_proof_of_forgetting(
            attestation,
            chrono::Utc::now(),
            &Sha256Hash::digest_bytes(b"input"),
        )
        .unwrap();

        assert!(verify_proof_of_forgetting(&proof).unwrap());
    }
}
