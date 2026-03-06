use lsdc_common::crypto::{
    sign_bytes, verify_signature, AttestationDocument, Sha256Hash,
};
use lsdc_common::error::{LsdcError, Result};

pub(crate) const DEFAULT_ATTESTATION_SECRET: &str = "lsdc-attestation-dev-secret";

pub(crate) fn build_attestation_document(
    enclave_id: &str,
    platform: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<AttestationDocument> {
    let payload = attestation_payload_bytes(enclave_id, platform, binary_hash, timestamp)?;
    let document_hash = Sha256Hash::digest_bytes(&payload);
    let signature_hex = sign_bytes(&attestation_secret(), &payload);

    Ok(AttestationDocument {
        enclave_id: enclave_id.to_string(),
        platform: platform.to_string(),
        binary_hash: binary_hash.clone(),
        document_hash,
        timestamp,
        attestation_bytes: payload,
        signature_hex,
    })
}

pub fn verify_attestation(doc: &AttestationDocument) -> Result<bool> {
    if !doc.platform.starts_with("aws-nitro") {
        return Ok(false);
    }

    let payload = attestation_payload_bytes(
        &doc.enclave_id,
        &doc.platform,
        &doc.binary_hash,
        doc.timestamp,
    )?;

    Ok(doc.attestation_bytes == payload
        && doc.document_hash == Sha256Hash::digest_bytes(&payload)
        && verify_signature(&attestation_secret(), &payload, &doc.signature_hex))
}

pub(crate) fn attestation_secret() -> String {
    std::env::var("LSDC_ATTESTATION_SECRET")
        .unwrap_or_else(|_| DEFAULT_ATTESTATION_SECRET.to_string())
}

fn attestation_payload_bytes(
    enclave_id: &str,
    platform: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": enclave_id,
        "platform": platform,
        "binary_hash": binary_hash.to_hex(),
        "timestamp": timestamp.to_rfc3339(),
    }))
    .map_err(LsdcError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_verify_attestation() {
        let doc = build_attestation_document(
            "enclave-1",
            "aws-nitro-prototype",
            &Sha256Hash::digest_bytes(b"binary"),
            chrono::Utc::now(),
        )
        .unwrap();

        assert!(verify_attestation(&doc).unwrap());
    }
}
