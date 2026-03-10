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

struct AttestationPayload<'a> {
    enclave_id: &'a str,
    platform: &'a str,
    binary_hash: &'a Sha256Hash,
    measurements: &'a AttestationMeasurements,
    nonce: Option<&'a str>,
    public_key: Option<&'a [u8]>,
    user_data_hash: Option<&'a Sha256Hash>,
    timestamp: chrono::DateTime<chrono::Utc>,
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
    let payload = attestation_payload_bytes(&AttestationPayload {
        enclave_id,
        platform: NITRO_PLATFORM_DEV,
        binary_hash,
        measurements: &measurements,
        nonce: binding.as_ref().map(|binding| binding.challenge_nonce_hex),
        public_key: binding.as_ref().and_then(|binding| binding.public_key),
        user_data_hash: binding.as_ref().and_then(|binding| binding.user_data_hash),
        timestamp,
    })?;
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

    let payload = attestation_payload_bytes(&AttestationPayload {
        enclave_id: &doc.enclave_id,
        platform: &doc.platform,
        binary_hash: &doc.binary_hash,
        measurements: &doc.measurements,
        nonce: doc.nonce.as_deref(),
        public_key: doc.public_key.as_deref(),
        user_data_hash: doc.user_data_hash.as_ref(),
        timestamp: doc.timestamp,
    })?;

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

fn attestation_payload_bytes(payload: &AttestationPayload<'_>) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": payload.enclave_id,
        "platform": payload.platform,
        "binary_hash": payload.binary_hash.to_hex(),
        "measurements": payload.measurements,
        "nonce": payload.nonce,
        "public_key": payload.public_key.map(hex::encode),
        "user_data_hash": payload.user_data_hash.map(Sha256Hash::to_hex),
        "timestamp": payload.timestamp.to_rfc3339(),
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
            .map(|challenge| doc.nonce.as_deref() == Some(challenge.challenge_nonce_hex.as_str()))
            .unwrap_or(true);
        let public_key_matches = challenge
            .map(|challenge| {
                challenge.requester_ephemeral_pubkey.is_empty()
                    || doc.public_key.as_deref()
                        == Some(challenge.requester_ephemeral_pubkey.as_slice())
            })
            .unwrap_or(true);
        let user_data_matches = challenge
            .map(|challenge| doc.user_data_hash.as_ref() == Some(&challenge.resolved_selector_hash))
            .unwrap_or(true);
        let appraisal = if document_valid
            && freshness_ok
            && nonce_matches
            && public_key_matches
            && user_data_matches
        {
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
    use lsdc_common::execution_overlay::{
        ExecutionSession, ExecutionSessionChallenge, ExecutionSessionState,
    };

    fn sample_challenge(timestamp: chrono::DateTime<chrono::Utc>) -> ExecutionSessionChallenge {
        let session = ExecutionSession {
            session_id: uuid::Uuid::new_v4(),
            agreement_id: "agreement-1".into(),
            agreement_commitment_hash: Sha256Hash::digest_bytes(b"agreement"),
            capability_descriptor_hash: Sha256Hash::digest_bytes(b"capability"),
            evidence_requirements_hash: Sha256Hash::digest_bytes(b"requirements"),
            resolved_selector_hash: Some(Sha256Hash::digest_bytes(b"selector")),
            requester_ephemeral_pubkey: vec![1, 2, 3, 4],
            state: ExecutionSessionState::Challenged,
            created_at: timestamp,
            expires_at: Some(timestamp + chrono::Duration::minutes(5)),
        };

        ExecutionSessionChallenge::issue(&session, Sha256Hash::digest_bytes(b"selector"), timestamp)
    }

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

    #[test]
    fn test_build_and_appraise_attestation_with_binding() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let doc = build_attestation_document_with_binding(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            timestamp,
            Some(AttestationBinding {
                challenge_nonce_hex: &challenge.challenge_nonce_hex,
                public_key: Some(challenge.requester_ephemeral_pubkey.as_slice()),
                user_data_hash: Some(&challenge.resolved_selector_hash),
            }),
        )
        .unwrap();

        assert!(verify_attestation(&doc).unwrap());
        assert_eq!(
            doc.nonce.as_deref(),
            Some(challenge.challenge_nonce_hex.as_str())
        );
        assert_eq!(
            doc.public_key.as_deref(),
            Some(challenge.requester_ephemeral_pubkey.as_slice())
        );
        assert_eq!(
            doc.user_data_hash.as_ref(),
            Some(&challenge.resolved_selector_hash)
        );

        let result = LocalAttestationVerifier::new()
            .appraise_attestation_evidence(
                &AttestationEvidence {
                    evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
                    document: doc,
                },
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Accepted);
    }

    #[test]
    fn test_appraisal_rejects_attestation_binding_mismatch() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let wrong_selector_hash = Sha256Hash::digest_bytes(b"wrong-selector");
        let doc = build_attestation_document_with_binding(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            timestamp,
            Some(AttestationBinding {
                challenge_nonce_hex: &challenge.challenge_nonce_hex,
                public_key: Some(&[9, 9, 9, 9]),
                user_data_hash: Some(&wrong_selector_hash),
            }),
        )
        .unwrap();

        let result = LocalAttestationVerifier::new()
            .appraise_attestation_evidence(
                &AttestationEvidence {
                    evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
                    document: doc,
                },
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Rejected);
    }
}
