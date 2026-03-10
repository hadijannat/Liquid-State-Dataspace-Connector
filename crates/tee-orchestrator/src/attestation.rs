use lsdc_common::crypto::{
    sign_bytes, verify_signature, AppraisalStatus, AttestationDocument, AttestationEvidence,
    AttestationMeasurements, AttestationResult, Sha256Hash,
};
use lsdc_common::error::{LsdcError, Result};
use lsdc_ports::AttestationVerifier;
use std::collections::BTreeMap;

pub(crate) const DEFAULT_ATTESTATION_SECRET: &str = "lsdc-attestation-dev-secret";
const NITRO_PLATFORM_DEV: &str = "aws-nitro-dev";

#[derive(Debug, Clone)]
pub(crate) struct AttestationBinding<'a> {
    pub challenge_nonce_hex: &'a str,
    pub public_key: Option<&'a [u8]>,
    pub user_data_hash: Option<&'a Sha256Hash>,
}

pub(crate) fn build_attestation_document(
    enclave_id: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<AttestationDocument> {
    build_attestation_document_with_binding(enclave_id, binary_hash, timestamp, None)
}

pub(crate) fn build_attestation_document_with_binding(
    enclave_id: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
    binding: Option<AttestationBinding<'_>>,
) -> Result<AttestationDocument> {
    let nonce = binding
        .as_ref()
        .map(|binding| binding.challenge_nonce_hex.to_string());
    let public_key = binding
        .as_ref()
        .and_then(|binding| binding.public_key.map(|bytes| bytes.to_vec()));
    let user_data_hash = binding
        .as_ref()
        .and_then(|binding| binding.user_data_hash.cloned());
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
        binding.as_ref().map(|binding| binding.challenge_nonce_hex),
        binding.as_ref().and_then(|binding| binding.public_key),
        binding.as_ref().and_then(|binding| binding.user_data_hash),
        timestamp,
    )?;
    let document_hash = Sha256Hash::digest_bytes(&payload);
    let signature_hex = sign_bytes(&attestation_secret(), &payload);

    Ok(AttestationDocument {
        enclave_id: enclave_id.to_string(),
        platform: NITRO_PLATFORM_DEV.to_string(),
        binary_hash: binary_hash.clone(),
        measurements,
        nonce,
        public_key,
        user_data_hash,
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
        doc.nonce.as_deref(),
        doc.public_key.as_deref(),
        doc.user_data_hash.as_ref(),
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
    nonce: Option<&str>,
    public_key: Option<&[u8]>,
    user_data_hash: Option<&Sha256Hash>,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": enclave_id,
        "platform": platform,
        "binary_hash": binary_hash.to_hex(),
        "measurements": measurements,
        "nonce": nonce,
        "public_key": public_key.map(hex::encode),
        "user_data_hash": user_data_hash.map(Sha256Hash::to_hex),
        "timestamp": timestamp.to_rfc3339(),
    }))
    .map_err(LsdcError::from)
}

#[derive(Default)]
pub struct LocalAttestationVerifier;

impl LocalAttestationVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for LocalAttestationVerifier {
    fn appraise_attestation_evidence(
        &self,
        evidence: &AttestationEvidence,
        challenge: Option<&lsdc_common::execution_overlay::ExecutionSessionChallenge>,
    ) -> Result<AttestationResult> {
        let doc = &evidence.document;
        let document_valid = verify_attestation(doc)?;
        let freshness_ok = challenge
            .map(|challenge| challenge.expires_at >= chrono::Utc::now())
            .unwrap_or(true);
        let nonce_matches = challenge
            .map(|challenge| {
                doc.nonce.as_deref() == Some(challenge.challenge_nonce_hex.as_str())
            })
            .unwrap_or(true);
        let appraisal = if document_valid && freshness_ok && nonce_matches {
            AppraisalStatus::Accepted
        } else {
            AppraisalStatus::Rejected
        };

        Ok(AttestationResult {
            profile: evidence.evidence_profile.clone(),
            doc_hash: doc.document_hash.clone(),
            session_id: challenge.map(|challenge| challenge.session_id.to_string()),
            nonce: doc.nonce.clone(),
            image_sha384: doc.binary_hash.to_hex(),
            pcrs: doc
                .measurements
                .pcrs
                .iter()
                .map(|(index, value)| (*index as u8, value.clone()))
                .collect(),
            public_key: doc.public_key.clone(),
            user_data_hash: doc.user_data_hash.clone(),
            cert_chain_verified: document_valid,
            freshness_ok,
            appraisal,
        })
    }
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
