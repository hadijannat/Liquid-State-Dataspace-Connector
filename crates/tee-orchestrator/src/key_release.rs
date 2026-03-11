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

        let output = operation.send().await.map_err(|err| {
            LsdcError::Attestation(format!("aws kms generate_data_key failed: {err}"))
        })?;
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

fn expected_attestation_public_key_hash_matches(
    challenge: &ExecutionSessionChallenge,
    public_key: Option<&[u8]>,
) -> bool {
    match challenge.expected_attestation_public_key_hash.as_ref() {
        Some(expected_hash) => public_key
            .filter(|public_key| !public_key.is_empty())
            .map(lsdc_common::crypto::Sha256Hash::digest_bytes)
            .as_ref()
            == Some(expected_hash),
        None => true,
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
        if attestation_result
            .public_key
            .as_ref()
            .is_none_or(|public_key| public_key.is_empty())
        {
            return Err(LsdcError::Attestation(
                "aws kms key release requires an attested recipient public key".into(),
            ));
        }
        if !expected_attestation_public_key_hash_matches(
            session,
            attestation_result.public_key.as_deref(),
        ) {
            return Err(LsdcError::Attestation(
                "aws kms key release attested public key pin mismatch".into(),
            ));
        }
        if attestation_result.user_data_hash.as_ref() != Some(&session.resolved_selector_hash) {
            return Err(LsdcError::Attestation(
                "aws kms key release selector hash binding mismatch".into(),
            ));
        }
        if attestation_evidence
            .document
            .raw_attestation_document
            .is_empty()
        {
            return Err(LsdcError::Attestation(
                "aws kms key release requires a raw nitro attestation document".into(),
            ));
        }

        let request = GenerateDataKeyRequest {
            kms_key_id: self.kms_key_id.clone(),
            attestation_document: attestation_evidence
                .document
                .raw_attestation_document
                .clone(),
            encryption_context: BTreeMap::from([
                ("agreement_id".into(), policy.agreement_id.clone()),
                ("session_id".into(), session.session_id.to_string()),
                (
                    "agreement_commitment_hash".into(),
                    policy.agreement_commitment_hash.to_hex(),
                ),
                (
                    "capability_descriptor_hash".into(),
                    policy.capability_descriptor_hash.to_hex(),
                ),
                (
                    "resolved_selector_hash".into(),
                    policy.resolved_selector_hash.to_hex(),
                ),
                (
                    "challenge_nonce_hash".into(),
                    policy.challenge_nonce_hash.to_hex(),
                ),
            ]),
        };
        let response = self.client.generate_data_key(request).await?;
        let released_key_id = format!("{}:{}", response.key_id, session.challenge_id);
        self.released_keys
            .lock()
            .map_err(|_| LsdcError::Attestation("released key broker state is poisoned".into()))?
            .insert(released_key_id.clone());

        Ok(EphemeralDataKey {
            key_id: released_key_id,
            wrapped_key: response.ciphertext_for_recipient,
        })
    }

    fn attest_erasure(
        &self,
        handle: EphemeralKeyHandle,
    ) -> Result<lsdc_common::crypto::KeyErasureEvidence> {
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
    use lsdc_common::crypto::{
        AppraisalStatus, AttestationDocument, AttestationMeasurements, EvidenceClass, Sha256Hash,
    };

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
            agreement_commitment_hash: Sha256Hash::digest_bytes(b"agreement-commitment"),
            capability_descriptor_hash: Sha256Hash::digest_bytes(b"capability"),
            resolved_selector_hash: Sha256Hash::digest_bytes(b"selector"),
            challenge_nonce_hash: Sha256Hash::digest_bytes(&[0xaa, 0xbb, 0xcc]),
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
            expected_attestation_public_key_hash: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            consumed_at: None,
        }
    }

    fn with_expected_attestation_public_key_hash(
        challenge: &ExecutionSessionChallenge,
        public_key: &[u8],
    ) -> ExecutionSessionChallenge {
        let mut pinned = challenge.clone();
        pinned.expected_attestation_public_key_hash = Some(Sha256Hash::digest_bytes(public_key));
        pinned
    }

    fn sample_evidence(challenge: &ExecutionSessionChallenge) -> AttestationEvidence {
        let attested_public_key = vec![7, 8, 9];
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
                public_key: Some(attested_public_key),
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
            public_key: Some(vec![7, 8, 9]),
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

        assert!(released.key_id.starts_with("kms-key:"));
        assert_eq!(released.wrapped_key, vec![4, 5, 6]);
        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].attestation_document, vec![7, 8, 9]);
        assert_eq!(
            requests[0].encryption_context["agreement_id"],
            "agreement-1"
        );
        assert_eq!(
            requests[0].encryption_context["session_id"],
            challenge.session_id.to_string()
        );
        assert_eq!(
            requests[0].encryption_context["agreement_commitment_hash"],
            sample_policy().agreement_commitment_hash.to_hex()
        );
        assert_eq!(
            requests[0].encryption_context["capability_descriptor_hash"],
            sample_policy().capability_descriptor_hash.to_hex()
        );
        assert_eq!(
            requests[0].encryption_context["resolved_selector_hash"],
            sample_policy().resolved_selector_hash.to_hex()
        );
        assert_eq!(
            requests[0].encryption_context["challenge_nonce_hash"],
            sample_policy().challenge_nonce_hash.to_hex()
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
    async fn test_release_key_rejects_missing_recipient_public_key() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let mut result = sample_result(&challenge);
        result.public_key = None;

        let err = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("attested recipient public key"));
    }

    #[tokio::test]
    async fn test_release_key_rejects_stale_attestation() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let mut result = sample_result(&challenge);
        result.freshness_ok = false;

        let err = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("fresh attestation evidence"));
    }

    #[tokio::test]
    async fn test_release_key_rejects_nonce_mismatch() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let mut result = sample_result(&challenge);
        result.nonce = Some("deadbeef".into());

        let err = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("challenge-bound nonce"));
    }

    #[tokio::test]
    async fn test_release_key_rejects_selector_hash_mismatch() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let mut result = sample_result(&challenge);
        result.user_data_hash = Some(Sha256Hash::digest_bytes(b"other-selector"));

        let err = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("selector hash binding mismatch"));
    }

    #[tokio::test]
    async fn test_release_key_rejects_attested_public_key_hash_mismatch() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let pinned_challenge = with_expected_attestation_public_key_hash(&challenge, &[0, 0, 0]);
        let result = sample_result(&challenge);

        let err = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &pinned_challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("attested public key pin mismatch"));
    }

    #[tokio::test]
    async fn test_release_key_accepts_attested_public_key_without_pin() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let result = sample_result(&challenge);

        let released = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &result,
                &challenge,
            )
            .await
            .unwrap();

        assert!(released.key_id.starts_with("kms-key:"));
    }

    #[tokio::test]
    async fn test_release_key_accepts_matching_attested_public_key_pin() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let pinned_challenge = with_expected_attestation_public_key_hash(&challenge, &[7, 8, 9]);

        let released = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge),
                &sample_result(&challenge),
                &pinned_challenge,
            )
            .await
            .unwrap();

        assert!(released.key_id.starts_with("kms-key:"));
    }

    #[tokio::test]
    async fn test_release_key_requires_raw_attestation_document() {
        let challenge = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);
        let mut evidence = sample_evidence(&challenge);
        evidence.document.raw_attestation_document.clear();

        let err = broker
            .release_key(
                &sample_policy(),
                &evidence,
                &sample_result(&challenge),
                &challenge,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("raw nitro attestation document"));
    }

    #[tokio::test]
    async fn test_attest_erasure_tracks_releases_per_challenge() {
        let challenge_a = sample_challenge();
        let challenge_b = sample_challenge();
        let fake = Arc::new(FakeKmsClient::succeed(GenerateDataKeyResponse {
            key_id: "kms-key".into(),
            ciphertext_for_recipient: vec![4, 5, 6],
        }));
        let broker = AwsKmsKeyBroker::new("arn:aws:kms:eu-central-1:123:key/test", fake);

        let released_a = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge_a),
                &sample_result(&challenge_a),
                &challenge_a,
            )
            .await
            .unwrap();
        let released_b = broker
            .release_key(
                &sample_policy(),
                &sample_evidence(&challenge_b),
                &sample_result(&challenge_b),
                &challenge_b,
            )
            .await
            .unwrap();

        assert_ne!(released_a.key_id, released_b.key_id);
        assert_eq!(
            broker
                .attest_erasure(EphemeralKeyHandle {
                    key_id: released_a.key_id.clone(),
                    session_id: challenge_a.session_id.to_string(),
                    attestation_result_hash: Sha256Hash::digest_bytes(b"result-a"),
                    evidence_class: EvidenceClass::Attested,
                })
                .unwrap()
                .released_key_id,
            released_a.key_id
        );
        assert_eq!(
            broker
                .attest_erasure(EphemeralKeyHandle {
                    key_id: released_b.key_id.clone(),
                    session_id: challenge_b.session_id.to_string(),
                    attestation_result_hash: Sha256Hash::digest_bytes(b"result-b"),
                    evidence_class: EvidenceClass::Attested,
                })
                .unwrap()
                .released_key_id,
            released_b.key_id
        );
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
