use crate::forgetting::build_key_erasure_evidence;
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{DataKeySpec, KeyEncryptionMechanism, RecipientInfo};
use lsdc_common::crypto::{AppraisalStatus, AttestationEvidence, AttestationResult};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution_overlay::ExecutionSessionChallenge;
use lsdc_ports::{EphemeralDataKey, EphemeralKeyHandle, KeyBroker, KeyReleasePolicy};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateDataKeyRequest {
    pub kms_key_id: String,
    pub attestation_document: Vec<u8>,
    pub encryption_context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateDataKeyResponse {
    pub key_id: String,
    pub ciphertext_for_recipient: Vec<u8>,
}

#[async_trait]
pub trait KmsDataKeyClient: Send + Sync {
    async fn generate_data_key(
        &self,
        request: GenerateDataKeyRequest,
    ) -> Result<GenerateDataKeyResponse>;
}

pub struct AwsSdkKmsDataKeyClient {
    client: aws_sdk_kms::Client,
}

impl AwsSdkKmsDataKeyClient {
    pub fn new(client: aws_sdk_kms::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl KmsDataKeyClient for AwsSdkKmsDataKeyClient {
    async fn generate_data_key(
        &self,
        request: GenerateDataKeyRequest,
    ) -> Result<GenerateDataKeyResponse> {
        let recipient = RecipientInfo::builder()
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .attestation_document(Blob::new(request.attestation_document))
            .build();
        let mut operation = self
            .client
            .generate_data_key()
            .key_id(request.kms_key_id)
            .key_spec(DataKeySpec::Aes256)
            .recipient(recipient);
        for (key, value) in request.encryption_context {
            operation = operation.encryption_context(key, value);
        }

        let output = operation
            .send()
            .await
            .map_err(|err| LsdcError::Attestation(format!("aws kms generate_data_key failed: {err}")))?;
        let ciphertext_for_recipient = output
            .ciphertext_for_recipient()
            .map(|blob| blob.as_ref().to_vec())
            .ok_or_else(|| {
                LsdcError::Attestation(
                    "aws kms generate_data_key did not return ciphertext_for_recipient".into(),
                )
            })?;

        Ok(GenerateDataKeyResponse {
            key_id: output
                .key_id()
                .map(str::to_string)
                .unwrap_or_else(|| "kms-attested-data-key".into()),
            ciphertext_for_recipient,
        })
    }
}

pub struct AwsKmsKeyBroker {
    kms_key_id: String,
    client: Arc<dyn KmsDataKeyClient>,
    released_keys: Mutex<HashSet<String>>,
}

impl AwsKmsKeyBroker {
    pub fn new(kms_key_id: impl Into<String>, client: Arc<dyn KmsDataKeyClient>) -> Self {
        Self {
            kms_key_id: kms_key_id.into(),
            client,
            released_keys: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl KeyBroker for AwsKmsKeyBroker {
    async fn release_key(
        &self,
        policy: &KeyReleasePolicy,
        attestation_evidence: &AttestationEvidence,
        attestation_result: &AttestationResult,
        session: &ExecutionSessionChallenge,
    ) -> Result<EphemeralDataKey> {
        if policy.profile.as_deref() != Some("kms-attested") {
            return Err(LsdcError::PolicyCompile(
                "aws kms key broker requires keyReleaseProfile = kms-attested".into(),
            ));
        }
        if attestation_result.appraisal != AppraisalStatus::Accepted {
            return Err(LsdcError::Attestation(
                "aws kms key release requires accepted attestation appraisal".into(),
            ));
        }
        if !attestation_result.freshness_ok {
            return Err(LsdcError::Attestation(
                "aws kms key release requires fresh attestation evidence".into(),
            ));
        }
        if attestation_result.nonce.as_deref() != Some(session.challenge_nonce_hex.as_str()) {
            return Err(LsdcError::Attestation(
                "aws kms key release requires a challenge-bound nonce".into(),
            ));
        }
        if !session.requester_ephemeral_pubkey.is_empty()
            && attestation_result.public_key.as_deref()
                != Some(session.requester_ephemeral_pubkey.as_slice())
        {
            return Err(LsdcError::Attestation(
                "aws kms key release requester key binding mismatch".into(),
            ));
        }
        if attestation_result.user_data_hash.as_ref() != Some(&session.resolved_selector_hash) {
            return Err(LsdcError::Attestation(
                "aws kms key release selector hash binding mismatch".into(),
            ));
        }
        if attestation_evidence.document.raw_attestation_document.is_empty() {
            return Err(LsdcError::Attestation(
                "aws kms key release requires a raw nitro attestation document".into(),
            ));
        }

        let request = GenerateDataKeyRequest {
            kms_key_id: self.kms_key_id.clone(),
            attestation_document: attestation_evidence.document.raw_attestation_document.clone(),
            encryption_context: BTreeMap::from([
                ("agreement_id".into(), policy.agreement_id.clone()),
                ("session_id".into(), session.session_id.to_string()),
                (
                    "capability_descriptor_hash".into(),
                    policy.capability_descriptor_hash.to_hex(),
                ),
                ("selector_hash".into(), session.resolved_selector_hash.to_hex()),
            ]),
        };
        let response = self.client.generate_data_key(request).await?;
        self.released_keys
            .lock()
            .map_err(|_| LsdcError::Attestation("released key broker state is poisoned".into()))?
            .insert(response.key_id.clone());

        Ok(EphemeralDataKey {
            key_id: response.key_id,
            wrapped_key: response.ciphertext_for_recipient,
        })
    }

    fn attest_erasure(&self, handle: EphemeralKeyHandle) -> Result<lsdc_common::crypto::KeyErasureEvidence> {
        let released = self
            .released_keys
            .lock()
            .map_err(|_| LsdcError::Attestation("released key broker state is poisoned".into()))?
            .remove(&handle.key_id);
        if !released {
            return Err(LsdcError::Attestation(
                "cannot emit key erasure evidence before a key release succeeds".into(),
            ));
        }

        let mut evidence = build_key_erasure_evidence(
            &handle.session_id,
            &handle.attestation_result_hash,
            chrono::Utc::now(),
            handle.evidence_class,
        )?;
        evidence.released_key_id = handle.key_id;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsdc_common::crypto::{AppraisalStatus, AttestationDocument, AttestationMeasurements, EvidenceClass, Sha256Hash};

    struct FakeKmsClient {
        response: Mutex<Option<GenerateDataKeyResponse>>,
        requests: Mutex<Vec<GenerateDataKeyRequest>>,
    }

    impl FakeKmsClient {
        fn succeed(response: GenerateDataKeyResponse) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<GenerateDataKeyRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl KmsDataKeyClient for FakeKmsClient {
        async fn generate_data_key(
            &self,
            request: GenerateDataKeyRequest,
        ) -> Result<GenerateDataKeyResponse> {
            self.requests.lock().unwrap().push(request);
            self.response
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| LsdcError::Attestation("fake kms failure".into()))
        }
    }

    fn sample_policy() -> KeyReleasePolicy {
        KeyReleasePolicy {
            profile: Some("kms-attested".into()),
            deletion_mode: Some("kms_erasure".into()),
            requires_attestation: true,
            requires_teardown_evidence: true,
            agreement_id: "agreement-1".into(),
            capability_descriptor_hash: Sha256Hash::digest_bytes(b"capability"),
        }
    }

    fn sample_challenge() -> ExecutionSessionChallenge {
        ExecutionSessionChallenge {
            challenge_id: uuid::Uuid::new_v4(),
            agreement_hash: Sha256Hash::digest_bytes(b"agreement"),
            session_id: uuid::Uuid::new_v4(),
            challenge_nonce_hex: "aabbcc".into(),
            challenge_nonce_hash: Sha256Hash::digest_bytes(&[0xaa, 0xbb, 0xcc]),
            resolved_selector_hash: Sha256Hash::digest_bytes(b"selector"),
            requester_ephemeral_pubkey: vec![1, 2, 3],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            consumed_at: None,
        }
    }

    fn sample_evidence(challenge: &ExecutionSessionChallenge) -> AttestationEvidence {
        AttestationEvidence {
            evidence_profile: "aws-nitro-live".into(),
            document: AttestationDocument {
                enclave_id: "enc".into(),
                platform: "aws-nitro-live".into(),
                binary_hash: Sha256Hash::digest_bytes(b"binary"),
                measurements: AttestationMeasurements {
                    image_hash: Sha256Hash::digest_bytes(b"binary"),
                    pcrs: BTreeMap::new(),
                    debug: false,
                },
                nonce: Some(challenge.challenge_nonce_hex.clone()),
                public_key: Some(challenge.requester_ephemeral_pubkey.clone()),
                user_data_hash: Some(challenge.resolved_selector_hash.clone()),
                document_hash: Sha256Hash::digest_bytes(b"document"),
                timestamp: chrono::Utc::now(),
                raw_attestation_document: vec![7, 8, 9],
                certificate_chain_pem: Vec::new(),
                signature_hex: String::new(),
            },
        }
    }

    fn sample_result(challenge: &ExecutionSessionChallenge) -> AttestationResult {
        AttestationResult {
            profile: "aws-nitro-live".into(),
            doc_hash: Sha256Hash::digest_bytes(b"document"),
            session_id: Some(challenge.session_id.to_string()),
            nonce: Some(challenge.challenge_nonce_hex.clone()),
            image_sha384: "abcd".into(),
            pcrs: BTreeMap::new(),
            public_key: Some(challenge.requester_ephemeral_pubkey.clone()),
            user_data_hash: Some(challenge.resolved_selector_hash.clone()),
            cert_chain_verified: true,
            freshness_ok: true,
            appraisal: AppraisalStatus::Accepted,
        }
    }

    #[tokio::test]
    async fn test_release_key_uses_attestation_document_and_context() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake.clone());
        let released = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &sample_result(&challenge),
                &challenge,
            )
            .await
            .unwrap();

        assert_eq!(released.key_id, "kms-key");
        assert_eq!(released.wrapped_key, vec![4, 5, 6]);
        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].attestation_document, vec![7, 8, 9]);
        assert_eq!(requests[0].encryption_context["agreement_id"], "agreement-1");
        assert_eq!(
            requests[0].encryption_context["session_id"],
            challenge.session_id.to_string()
        );
        assert_eq!(
            requests[0].encryption_context["selector_hash"],
            challenge.resolved_selector_hash.to_hex()
        );
    }

    #[tokio::test]
    async fn test_release_key_rejects_non_accepted_attestation() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let mut result = sample_result(&challenge);
        result.appraisal = AppraisalStatus::Rejected;

        let err = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("accepted attestation appraisal"));
    }

    #[tokio::test]
    async fn test_attest_erasure_requires_prior_release() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);

        let err = broker
            .attest_erasure(EphemeralKeyHandle {
                key_id: "kms-key".into(),
                session_id: challenge.session_id.to_string(),
                attestation_result_hash: Sha256Hash::digest_bytes(b"result"),
                evidence_class: EvidenceClass::Attested,
            })
            .unwrap_err();

        assert!(err.to_string().contains("before a key release succeeds"));
    }
}
