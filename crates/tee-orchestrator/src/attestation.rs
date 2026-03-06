use lsdc_common::crypto::{
    sign_bytes, verify_signature, AttestationDocument, AttestationMeasurements, Sha256Hash,
};
use lsdc_common::error::{LsdcError, Result};
use std::collections::BTreeMap;

pub(crate) const DEFAULT_ATTESTATION_SECRET: &str = "lsdc-attestation-dev-secret";
const NITRO_PLATFORM_DEV: &str = "aws-nitro-dev";

pub(crate) fn build_attestation_document(
    enclave_id: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<AttestationDocument> {
    let measurements = AttestationMeasurements {
        image_hash: binary_hash.clone(),
        pcrs: BTreeMap::from([
            (0_u16, binary_hash.to_hex()),
            (
                1_u16,
                Sha256Hash::digest_bytes(enclave_id.as_bytes()).to_hex(),
            ),
            (
                2_u16,
                Sha256Hash::digest_bytes(timestamp.to_rfc3339().as_bytes()).to_hex(),
            ),
        ]),
        debug: false,
    };
    let payload = attestation_payload_bytes(
        enclave_id,
        NITRO_PLATFORM_DEV,
        binary_hash,
        &measurements,
        timestamp,
    )?;
    let document_hash = Sha256Hash::digest_bytes(&payload);
    let signature_hex = sign_bytes(&attestation_secret(), &payload);

    Ok(AttestationDocument {
        enclave_id: enclave_id.to_string(),
        platform: NITRO_PLATFORM_DEV.to_string(),
        binary_hash: binary_hash.clone(),
        measurements,
        document_hash,
        timestamp,
        raw_attestation_document: payload,
        certificate_chain_pem: Vec::new(),
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
        &doc.measurements,
        doc.timestamp,
    )?;

    Ok(doc.raw_attestation_document == payload
        && doc.document_hash == Sha256Hash::digest_bytes(&payload)
        && doc.measurements.image_hash == doc.binary_hash
        && !doc.measurements.debug
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
    measurements: &AttestationMeasurements,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": enclave_id,
        "platform": platform,
        "binary_hash": binary_hash.to_hex(),
        "measurements": measurements,
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
            &Sha256Hash::digest_bytes(b"binary"),
            chrono::Utc::now(),
        )
        .unwrap();

        assert!(verify_attestation(&doc).unwrap());
    }
}
