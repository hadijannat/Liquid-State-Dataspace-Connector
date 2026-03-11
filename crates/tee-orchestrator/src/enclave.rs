use crate::attestation::{
    build_attestation_document, build_attestation_document_with_binding, AttestationBinding,
};
use crate::forgetting::{build_proof_of_forgetting, validate_forgetting_secret};
use async_trait::async_trait;
use lsdc_common::crypto::{
    attestation_result_binding_hash, AttestationDocument, AttestationEvidence, EvidenceClass,
    ExecutionEvidenceBundle, Sha256Hash, TeardownEvidence,
};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::TeeBackend;
use lsdc_common::profile::normalize_policy;
use lsdc_evidence::DevDeletionEvidence;
use lsdc_ports::{
    AttestationVerifier, EnclaveJobRequest, EnclaveJobResult, EnclaveManager, EphemeralKeyHandle,
    KeyBroker, KeyReleasePolicy, ProofEngine,
};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

pub struct NitroEnclaveManager {
    proof_engine: Arc<dyn ProofEngine>,
    attestation_verifier: Arc<dyn AttestationVerifier>,
    key_broker: Option<Arc<dyn KeyBroker>>,
    mode: TeeBackend,
    live_attestation_fixture: Option<NitroLiveAttestationMaterial>,
}

#[derive(Clone)]
pub struct NitroLiveAttestationMaterial {
    pub document: AttestationDocument,
}

impl NitroEnclaveManager {
    pub fn new_dev(
        proof_engine: Arc<dyn ProofEngine>,
        attestation_verifier: Arc<dyn AttestationVerifier>,
    ) -> Result<Self> {
        validate_forgetting_secret()?;
        Ok(Self {
            proof_engine,
            attestation_verifier,
            key_broker: None,
            mode: TeeBackend::NitroDev,
            live_attestation_fixture: None,
        })
    }

    pub fn new_live(
        proof_engine: Arc<dyn ProofEngine>,
        attestation_verifier: Arc<dyn AttestationVerifier>,
        live_attestation_fixture: Option<NitroLiveAttestationMaterial>,
        key_broker: Arc<dyn KeyBroker>,
    ) -> Result<Self> {
        validate_forgetting_secret()?;
        Ok(Self {
            proof_engine,
            attestation_verifier,
            key_broker: Some(key_broker),
            mode: TeeBackend::NitroLive,
            live_attestation_fixture,
        })
    }
}

#[async_trait]
impl EnclaveManager for NitroEnclaveManager {
    fn tee_backend(&self) -> TeeBackend {
        self.mode
    }

    fn attested_key_release_supported(&self) -> bool {
        self.mode == TeeBackend::NitroLive && self.key_broker.is_some()
    }

    fn attested_teardown_supported(&self) -> bool {
        self.attested_key_release_supported()
    }

    fn default_requester_ephemeral_pubkey(&self) -> Vec<u8> {
        Vec::new()
    }

    async fn run_csv_job(&self, request: EnclaveJobRequest) -> Result<EnclaveJobResult> {
        let EnclaveJobRequest {
            agreement,
            input_csv,
            manifest,
            prior_receipt,
            attestation_evidence,
            execution_bindings,
        } = request;
        let manifest_hash = Sha256Hash::digest_bytes(
            serde_json::to_vec(&serde_json::json!({
                "agreement_id": agreement.agreement_id.0.as_str(),
                "policy_hash": agreement.policy_hash.as_str(),
                "manifest": &manifest,
            }))
            .map_err(LsdcError::from)?
            .as_slice(),
        );
        let key_release_policy = derive_key_release_policy(
            &agreement,
            execution_bindings.as_ref(),
            self.mode,
            self.key_broker.is_some(),
        )?;

        let attestation_evidence = match self.mode {
            TeeBackend::NitroDev => {
                let enclave_id = format!("nitro-{}", Uuid::new_v4());
                let binding = execution_bindings
                    .as_ref()
                    .and_then(|bindings| bindings.challenge.as_ref())
                    .map(|challenge| AttestationBinding {
                        challenge_nonce_hex: &challenge.challenge_nonce_hex,
                        public_key: Some(challenge.requester_ephemeral_pubkey.as_slice()),
                        user_data_hash: Some(&challenge.resolved_selector_hash),
                    });
                let attestation = match binding {
                    Some(binding) => build_attestation_document_with_binding(
                        &enclave_id,
                        &manifest_hash,
                        chrono::Utc::now(),
                        Some(binding),
                    )?,
                    None => {
                        build_attestation_document(&enclave_id, &manifest_hash, chrono::Utc::now())?
                    }
                };
                AttestationEvidence {
                    evidence_profile: attestation.platform.clone(),
                    document: attestation,
                }
            }
            TeeBackend::NitroLive => {
                match attestation_evidence {
                    Some(attestation_evidence) => attestation_evidence,
                    None if key_release_policy.is_some() => return Err(LsdcError::Attestation(
                        "kms-attested nitro-live execution requires submitted attestation evidence"
                            .into(),
                    )),
                    None => {
                        let attestation = self
                            .live_attestation_fixture
                            .as_ref()
                            .ok_or_else(|| {
                                LsdcError::Attestation(
                                    "nitro-live execution requires submitted attestation evidence"
                                        .into(),
                                )
                            })?
                            .document
                            .clone();
                        AttestationEvidence {
                            evidence_profile: attestation.platform.clone(),
                            document: attestation,
                        }
                    }
                }
            }
            TeeBackend::None => {
                return Err(LsdcError::Attestation(
                    "nitro enclave manager requires a nitro backend".into(),
                ))
            }
        };
        let attestation = attestation_evidence.document.clone();
        let challenge = execution_bindings
            .as_ref()
            .and_then(|bindings| bindings.challenge.as_ref());
        let attestation_result = self
            .attestation_verifier
            .appraise_attestation_evidence(&attestation_evidence, challenge)?;
        validate_live_attestation_policy(&agreement, self.mode, &attestation_result)?;
        let attestation_result_hash =
            attestation_result_binding_hash(&attestation_result).map_err(LsdcError::from)?;
        let proof_execution_bindings = execution_bindings.as_ref().map(|bindings| {
            let mut bound = bindings.clone();
            bound.attestation_result_hash = Some(attestation_result_hash.clone());
            bound
        });

        let live_erasure_handle = match (
            key_release_policy.as_ref(),
            self.key_broker.as_ref(),
            challenge,
        ) {
            (Some(policy), Some(key_broker), Some(challenge)) => {
                let mut released_key = key_broker
                    .release_key(
                        policy,
                        &attestation_evidence,
                        &attestation_result,
                        challenge,
                    )
                    .await?;
                let handle = EphemeralKeyHandle {
                    key_id: released_key.key_id.clone(),
                    session_id: challenge.session_id.to_string(),
                    attestation_result_hash: attestation_result_hash.clone(),
                    evidence_class: EvidenceClass::Attested,
                };
                released_key.wrapped_key.zeroize();
                Some(handle)
            }
            (Some(_), None, _) => {
                return Err(LsdcError::Attestation(
                    "kms-attested execution requires an aws kms key broker".into(),
                ))
            }
            (Some(_), _, None) => {
                return Err(LsdcError::Attestation(
                    "kms-attested execution requires an active execution challenge".into(),
                ))
            }
            _ => None,
        };

        let proof_result = self
            .proof_engine
            .execute_csv_transform(
                &agreement,
                input_csv.as_slice(),
                &manifest,
                prior_receipt.as_ref(),
                proof_execution_bindings.as_ref(),
            )
            .await?;

        let mut wipe_buffer = input_csv;
        wipe_buffer.zeroize();

        let (proof_of_forgetting, teardown_evidence) = match self.mode {
            TeeBackend::NitroDev => {
                let proof_of_forgetting = build_proof_of_forgetting(
                    attestation.clone(),
                    chrono::Utc::now(),
                    &proof_result.receipt.input_hash,
                )?;
                let dev_deletion_evidence = DevDeletionEvidence::from(&proof_of_forgetting);
                (
                    proof_of_forgetting,
                    Some(TeardownEvidence::DevDeletion(dev_deletion_evidence)),
                )
            }
            TeeBackend::NitroLive => {
                let teardown_evidence = match (self.key_broker.as_ref(), live_erasure_handle) {
                    (Some(key_broker), Some(handle)) => Some(TeardownEvidence::KeyErasure(
                        key_broker.attest_erasure(handle)?,
                    )),
                    _ => None,
                };
                (
                    build_proof_of_forgetting(
                        attestation.clone(),
                        chrono::Utc::now(),
                        &proof_result.receipt.input_hash,
                    )?,
                    teardown_evidence,
                )
            }
            TeeBackend::None => {
                unreachable!("nitro enclave manager does not serve tee_backend=none")
            }
        };
        let teardown_hash = teardown_evidence.as_ref().map(teardown_hash);
        let evidence_root_hash = Sha256Hash::digest_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "receipt_hash": proof_result.receipt.receipt_hash.to_hex(),
                "attestation_result_hash": attestation_result_hash.to_hex(),
                "teardown_hash": teardown_hash.as_ref().map(Sha256Hash::to_hex),
            }))
            .map_err(LsdcError::from)?,
        );
        let audit_bytes = serde_json::to_vec(&serde_json::json!({
            "receipt_hash": proof_result.receipt.receipt_hash.to_hex(),
            "attestation_hash": attestation.document_hash.to_hex(),
            "attestation_result_hash": attestation_result_hash.to_hex(),
            "teardown_hash": teardown_hash.as_ref().map(Sha256Hash::to_hex),
            "output_hash": Sha256Hash::digest_bytes(&proof_result.output_csv).to_hex(),
            "evidence_root_hash": evidence_root_hash.to_hex(),
        }))
        .map_err(LsdcError::from)?;
        let execution_evidence = ExecutionEvidenceBundle {
            attestation_evidence,
            provenance_receipt: proof_result.receipt,
            attestation_result: Some(attestation_result),
            teardown_evidence,
            transparency_receipt_hash: None,
            evidence_root_hash,
            job_audit_hash: Sha256Hash::digest_bytes(&audit_bytes),
        };
        let mut proof_bundle = execution_evidence.clone().into_legacy_proof_bundle();
        proof_bundle.proof_of_forgetting = proof_of_forgetting;

        Ok(EnclaveJobResult {
            output_csv: proof_result.output_csv,
            proof_bundle,
            execution_evidence,
        })
    }
}

fn derive_key_release_policy(
    agreement: &lsdc_common::dsp::ContractAgreement,
    execution_bindings: Option<&lsdc_ports::ExecutionBindings>,
    tee_backend: TeeBackend,
    key_broker_available: bool,
) -> Result<Option<KeyReleasePolicy>> {
    let normalized = normalize_policy(&agreement.odrl_policy)?;
    let mut key_release_profile = None;
    let mut deletion_mode = None;
    for permission in &normalized.permissions {
        for constraint in &permission.constraints {
            match constraint.clause_id.as_str() {
                "keyReleaseProfile" => {
                    key_release_profile = constraint.right_operand.as_str().map(str::to_string);
                }
                "deletionMode" => {
                    deletion_mode = constraint.right_operand.as_str().map(str::to_string);
                }
                _ => {}
            }
        }
    }

    let live_profile_requested = key_release_profile.as_deref() == Some("kms-attested")
        || deletion_mode.as_deref() == Some("kms_erasure");
    match tee_backend {
        TeeBackend::NitroDev => {
            if live_profile_requested {
                return Err(LsdcError::PolicyCompile(
                    "kms-attested key release is executable only on nitro_live with aws_kms".into(),
                ));
            }
            Ok(None)
        }
        TeeBackend::NitroLive => {
            if !live_profile_requested {
                return Ok(None);
            }
            if key_release_profile.as_deref() != Some("kms-attested")
                || deletion_mode.as_deref() != Some("kms_erasure")
            {
                return Err(LsdcError::PolicyCompile(
                    "nitro_live currently requires keyReleaseProfile = kms-attested and deletionMode = kms_erasure together".into(),
                ));
            }
            if !key_broker_available {
                return Err(LsdcError::PolicyCompile(
                    "kms-attested key release requires an aws_kms key broker".into(),
                ));
            }
            let overlay_commitment = execution_bindings
                .map(|bindings| &bindings.overlay_commitment)
                .ok_or_else(|| {
                    LsdcError::PolicyCompile(
                        "kms-attested key release requires execution overlay bindings".into(),
                    )
                })?;

            Ok(Some(KeyReleasePolicy {
                profile: key_release_profile,
                deletion_mode,
                requires_attestation: true,
                requires_teardown_evidence: true,
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: overlay_commitment.agreement_commitment_hash.clone(),
                capability_descriptor_hash: overlay_commitment.capability_descriptor_hash.clone(),
                resolved_selector_hash: execution_bindings
                    .and_then(|bindings| bindings.challenge.as_ref())
                    .map(|challenge| challenge.resolved_selector_hash.clone())
                    .ok_or_else(|| {
                        LsdcError::PolicyCompile(
                            "kms-attested key release requires an active execution challenge"
                                .into(),
                        )
                    })?,
                challenge_nonce_hash: execution_bindings
                    .and_then(|bindings| bindings.challenge.as_ref())
                    .map(|challenge| challenge.challenge_nonce_hash.clone())
                    .ok_or_else(|| {
                        LsdcError::PolicyCompile(
                            "kms-attested key release requires an active execution challenge"
                                .into(),
                        )
                    })?,
            }))
        }
        TeeBackend::None => Err(LsdcError::PolicyCompile(
            "tee backend none cannot satisfy key release policy".into(),
        )),
    }
}

fn validate_live_attestation_policy(
    agreement: &lsdc_common::dsp::ContractAgreement,
    tee_backend: TeeBackend,
    attestation_result: &lsdc_common::crypto::AttestationResult,
) -> Result<()> {
    if tee_backend != TeeBackend::NitroLive {
        return Ok(());
    }

    let normalized = normalize_policy(&agreement.odrl_policy)?;
    for permission in &normalized.permissions {
        for constraint in &permission.constraints {
            if constraint.clause_id != "teeImageSha384" {
                continue;
            }
            let expected = constraint.right_operand.as_str().ok_or_else(|| {
                LsdcError::PolicyCompile(
                    "teeImageSha384 must be expressed as a SHA-384 hex string".into(),
                )
            })?;
            if !expected.eq_ignore_ascii_case(attestation_result.image_sha384.as_str()) {
                return Err(LsdcError::Attestation(
                    "nitro-live attestation image hash does not satisfy teeImageSha384 policy"
                        .into(),
                ));
            }
        }
    }

    Ok(())
}

fn teardown_hash(teardown_evidence: &TeardownEvidence) -> Sha256Hash {
    match teardown_evidence {
        TeardownEvidence::DevDeletion(evidence) => evidence.proof_hash.clone(),
        TeardownEvidence::KeyErasure(evidence) => evidence.evidence_hash.clone(),
        TeardownEvidence::AttestedTeardown(evidence) => evidence.teardown_hash.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forgetting::build_key_erasure_evidence;
    use async_trait::async_trait;
    use lsdc_common::crypto::{
        AppraisalStatus, AttestationMeasurements, AttestationResult, ProvenanceReceipt, Sha256Hash,
        TeardownEvidence,
    };
    use lsdc_common::execution::ProofBackend;
    use lsdc_common::execution_overlay::{
        AdvertisedProfiles, CapabilitySupportLevel, ExecutionCapabilityDescriptor,
        ExecutionEvidenceRequirements, ExecutionOverlayCommitment, ExecutionSession,
        ExecutionSessionChallenge, ExecutionSessionState, ProofCompositionMode, TransparencyMode,
        TruthfulnessMode,
    };
    use lsdc_common::liquid::{
        CsvTransformManifest, LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard,
    };
    use lsdc_common::odrl::ast::PolicyId;
    use lsdc_ports::{
        CompositionContext, EphemeralDataKey, ExecutionBindings, ProofExecutionResult,
    };
    use std::collections::BTreeMap;
    use std::sync::{Mutex, Once};

    fn ensure_test_env() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
        });
    }

    struct NoopProofEngine;

    #[async_trait]
    impl ProofEngine for NoopProofEngine {
        fn proof_backend(&self) -> ProofBackend {
            ProofBackend::None
        }

        async fn execute_csv_transform(
            &self,
            _agreement: &lsdc_common::dsp::ContractAgreement,
            _input_csv: &[u8],
            _manifest: &CsvTransformManifest,
            _prior_receipt: Option<&ProvenanceReceipt>,
            _execution_bindings: Option<&lsdc_ports::ExecutionBindings>,
        ) -> Result<ProofExecutionResult> {
            unreachable!("proof execution is not used in this test")
        }

        async fn verify_receipt(&self, _receipt: &ProvenanceReceipt) -> Result<bool> {
            unreachable!("receipt verification is not used in this test")
        }

        async fn verify_chain(&self, _chain: &[ProvenanceReceipt]) -> Result<bool> {
            unreachable!("chain verification is not used in this test")
        }

        async fn compose_receipts(
            &self,
            _receipts: &[ProvenanceReceipt],
            _ctx: CompositionContext,
        ) -> Result<ProvenanceReceipt> {
            unreachable!("composition is not used in this test")
        }

        async fn verify_receipt_dag(
            &self,
            _dag: &lsdc_common::runtime_model::EvidenceDag,
        ) -> Result<bool> {
            unreachable!("dag verification is not used in this test")
        }
    }

    struct StaticProofEngine;

    #[async_trait]
    impl ProofEngine for StaticProofEngine {
        fn proof_backend(&self) -> ProofBackend {
            ProofBackend::DevReceipt
        }

        async fn execute_csv_transform(
            &self,
            agreement: &lsdc_common::dsp::ContractAgreement,
            input_csv: &[u8],
            manifest: &CsvTransformManifest,
            _prior_receipt: Option<&ProvenanceReceipt>,
            _execution_bindings: Option<&lsdc_ports::ExecutionBindings>,
        ) -> Result<ProofExecutionResult> {
            Ok(ProofExecutionResult {
                output_csv: b"transformed".to_vec(),
                receipt: ProvenanceReceipt {
                    agreement_id: agreement.agreement_id.0.clone(),
                    input_hash: Sha256Hash::digest_bytes(input_csv),
                    output_hash: Sha256Hash::digest_bytes(b"transformed"),
                    policy_hash: Sha256Hash::digest_bytes(agreement.policy_hash.as_bytes()),
                    transform_manifest_hash: Sha256Hash::digest_bytes(
                        &serde_json::to_vec(manifest).unwrap(),
                    ),
                    prior_receipt_hash: None,
                    agreement_commitment_hash: None,
                    session_id: None,
                    challenge_nonce_hash: None,
                    selector_hash: None,
                    attestation_result_hash: None,
                    capability_commitment_hash: None,
                    transparency_statement_hash: None,
                    parent_receipt_hashes: Vec::new(),
                    recursion_depth: 0,
                    receipt_kind: Default::default(),
                    receipt_hash: Sha256Hash::digest_bytes(b"receipt"),
                    proof_backend: ProofBackend::DevReceipt,
                    receipt_format_version: "receipt/v1".into(),
                    proof_method_id: "dev-receipt".into(),
                    receipt_bytes: b"receipt".to_vec(),
                    timestamp: chrono::Utc::now(),
                },
                recursion_used: false,
            })
        }

        async fn verify_receipt(&self, _receipt: &ProvenanceReceipt) -> Result<bool> {
            Ok(true)
        }

        async fn verify_chain(&self, _chain: &[ProvenanceReceipt]) -> Result<bool> {
            Ok(true)
        }

        async fn compose_receipts(
            &self,
            _receipts: &[ProvenanceReceipt],
            _ctx: CompositionContext,
        ) -> Result<ProvenanceReceipt> {
            unreachable!("composition is not used in this test")
        }

        async fn verify_receipt_dag(
            &self,
            _dag: &lsdc_common::runtime_model::EvidenceDag,
        ) -> Result<bool> {
            Ok(true)
        }
    }

    #[derive(Default)]
    struct StaticVerifier;

    impl AttestationVerifier for StaticVerifier {
        fn appraise_attestation_evidence(
            &self,
            evidence: &AttestationEvidence,
            challenge: Option<&lsdc_common::execution_overlay::ExecutionSessionChallenge>,
        ) -> Result<lsdc_common::crypto::AttestationResult> {
            Ok(lsdc_common::crypto::AttestationResult {
                profile: evidence.evidence_profile.clone(),
                doc_hash: evidence.document.document_hash.clone(),
                session_id: challenge.map(|item| item.session_id.to_string()),
                nonce: evidence.document.nonce.clone(),
                image_sha384: evidence.document.binary_hash.to_hex(),
                pcrs: BTreeMap::new(),
                public_key: evidence.document.public_key.clone(),
                user_data_hash: evidence.document.user_data_hash.clone(),
                cert_chain_verified: true,
                freshness_ok: true,
                appraisal: AppraisalStatus::Accepted,
            })
        }
    }

    struct DummyBroker;

    #[async_trait]
    impl KeyBroker for DummyBroker {
        async fn release_key(
            &self,
            _policy: &KeyReleasePolicy,
            _attestation_evidence: &AttestationEvidence,
            _attestation_result: &lsdc_common::crypto::AttestationResult,
            _session: &lsdc_common::execution_overlay::ExecutionSessionChallenge,
        ) -> Result<lsdc_ports::EphemeralDataKey> {
            unreachable!("key release is not used in this test")
        }

        fn attest_erasure(
            &self,
            _handle: lsdc_ports::EphemeralKeyHandle,
        ) -> Result<lsdc_common::crypto::KeyErasureEvidence> {
            unreachable!("teardown is not used in this test")
        }
    }

    #[derive(Default)]
    struct RecordingBroker {
        released_documents: Mutex<Vec<Vec<u8>>>,
        released_sessions: Mutex<Vec<String>>,
        fail_release: bool,
    }

    #[async_trait]
    impl KeyBroker for RecordingBroker {
        async fn release_key(
            &self,
            _policy: &KeyReleasePolicy,
            attestation_evidence: &AttestationEvidence,
            attestation_result: &AttestationResult,
            session: &ExecutionSessionChallenge,
        ) -> Result<EphemeralDataKey> {
            if self.fail_release {
                return Err(LsdcError::Attestation("fake kms release failure".into()));
            }
            assert_eq!(attestation_result.appraisal, AppraisalStatus::Accepted);
            assert_eq!(
                attestation_result.nonce.as_deref(),
                Some(session.challenge_nonce_hex.as_str())
            );
            self.released_documents.lock().unwrap().push(
                attestation_evidence
                    .document
                    .raw_attestation_document
                    .clone(),
            );
            self.released_sessions
                .lock()
                .unwrap()
                .push(session.session_id.to_string());

            Ok(EphemeralDataKey {
                key_id: "kms-key-1".into(),
                wrapped_key: vec![7, 8, 9],
            })
        }

        fn attest_erasure(
            &self,
            handle: lsdc_ports::EphemeralKeyHandle,
        ) -> Result<lsdc_common::crypto::KeyErasureEvidence> {
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

    fn sample_live_agreement() -> lsdc_common::dsp::ContractAgreement {
        lsdc_common::dsp::ContractAgreement {
            agreement_id: PolicyId("agreement-live".into()),
            asset_id: "asset-1".into(),
            provider_id: "did:web:provider".into(),
            consumer_id: "did:web:consumer".into(),
            odrl_policy: serde_json::json!({
                "@context": "https://www.w3.org/ns/odrl.jsonld",
                "permission": [{
                    "action": ["read", "transfer", "anonymize"],
                    "constraint": [
                        { "leftOperand": "purpose", "rightOperand": ["analytics"] },
                        { "leftOperand": "keyReleaseProfile", "operator": "eq", "rightOperand": "kms-attested" },
                        { "leftOperand": "deletionMode", "operator": "eq", "rightOperand": "kms_erasure" }
                    ]
                }]
            }),
            policy_hash: "policy-live".into(),
            evidence_requirements: vec![
                lsdc_common::dsp::EvidenceRequirement::ProvenanceReceipt,
                lsdc_common::dsp::EvidenceRequirement::ProofOfForgetting,
            ],
            liquid_policy: LiquidPolicyIr {
                transport_guard: TransportGuard {
                    allow_read: true,
                    allow_transfer: true,
                    packet_cap: None,
                    byte_cap: None,
                    allowed_regions: vec!["EU".into()],
                    valid_until: None,
                    protocol: lsdc_common::dsp::TransportProtocol::Udp,
                    session_port: Some(31337),
                },
                transform_guard: TransformGuard {
                    allow_anonymize: true,
                    allowed_purposes: vec!["analytics".into()],
                    required_ops: Vec::new(),
                },
                runtime_guard: RuntimeGuard {
                    delete_after_seconds: Some(60),
                    evidence_requirements: vec![
                        lsdc_common::dsp::EvidenceRequirement::ProvenanceReceipt,
                    ],
                    approval_required: false,
                },
            },
        }
    }

    fn sample_live_agreement_with_image(
        expected_image_sha384: &str,
    ) -> lsdc_common::dsp::ContractAgreement {
        let mut agreement = sample_live_agreement();
        agreement.odrl_policy = serde_json::json!({
            "@context": "https://www.w3.org/ns/odrl.jsonld",
            "permission": [{
                "action": ["read", "transfer", "anonymize"],
                "constraint": [
                    { "leftOperand": "purpose", "rightOperand": ["analytics"] },
                    { "leftOperand": "teeImageSha384", "operator": "eq", "rightOperand": expected_image_sha384 },
                    { "leftOperand": "keyReleaseProfile", "operator": "eq", "rightOperand": "kms-attested" },
                    { "leftOperand": "deletionMode", "operator": "eq", "rightOperand": "kms_erasure" }
                ]
            }]
        });
        agreement
    }

    fn sample_fixture_mode_agreement() -> lsdc_common::dsp::ContractAgreement {
        let mut agreement = sample_live_agreement();
        agreement.odrl_policy = serde_json::json!({
            "@context": "https://www.w3.org/ns/odrl.jsonld",
            "permission": [{
                "action": ["read", "transfer", "anonymize"],
                "constraint": [
                    { "leftOperand": "purpose", "rightOperand": ["analytics"] }
                ]
            }]
        });
        agreement
    }

    fn sample_execution_bindings() -> ExecutionBindings {
        let now = chrono::Utc::now();
        let selector_hash = Sha256Hash::digest_bytes(b"selector");
        let capability_descriptor = ExecutionCapabilityDescriptor {
            overlay_version: "lsdc-execution-overlay/v1".into(),
            truthfulness_default: TruthfulnessMode::Strict,
            advertised_profiles: AdvertisedProfiles {
                attestation_profile: "aws-nitro-live".into(),
                proof_profile: "dev-receipt".into(),
                transparency_profile: "local".into(),
                teardown_profile: "kms_erasure".into(),
            },
            support: BTreeMap::from([
                (
                    "attestation.nitro_live_verified".into(),
                    CapabilitySupportLevel::Experimental,
                ),
                (
                    "key_release.kms_attested".into(),
                    CapabilitySupportLevel::Experimental,
                ),
            ]),
        };
        let evidence_requirements = ExecutionEvidenceRequirements {
            challenge_nonce_required: true,
            selector_hash_binding_required: true,
            transparency_registration_mode: TransparencyMode::Required,
            proof_composition_mode: ProofCompositionMode::Dag,
        };
        let overlay_commitment = ExecutionOverlayCommitment::build(
            "agreement-live",
            TruthfulnessMode::Strict,
            Sha256Hash::digest_bytes(b"policy"),
            capability_descriptor,
            evidence_requirements,
        )
        .unwrap();
        let session = ExecutionSession {
            session_id: uuid::Uuid::new_v4(),
            agreement_id: "agreement-live".into(),
            agreement_commitment_hash: overlay_commitment.agreement_commitment_hash.clone(),
            capability_descriptor_hash: overlay_commitment.capability_descriptor_hash.clone(),
            evidence_requirements_hash: overlay_commitment.evidence_requirements_hash.clone(),
            resolved_selector_hash: Some(selector_hash.clone()),
            requester_ephemeral_pubkey: vec![1, 2, 3, 4],
            expected_attestation_public_key_hash: None,
            state: ExecutionSessionState::Challenged,
            created_at: now,
            expires_at: Some(now + chrono::Duration::minutes(5)),
        };
        let challenge = ExecutionSessionChallenge::issue(&session, selector_hash, now);

        ExecutionBindings {
            overlay_commitment,
            session,
            challenge: Some(challenge),
            resolved_transport: None,
            attestation_result_hash: None,
        }
    }

    fn sample_live_attestation_document(
        public_key: Option<Vec<u8>>,
        raw: Vec<u8>,
    ) -> AttestationDocument {
        AttestationDocument {
            enclave_id: "enc-live".into(),
            platform: "aws-nitro-live".into(),
            binary_hash: Sha256Hash::digest_bytes(b"binary"),
            measurements: AttestationMeasurements {
                image_hash: Sha256Hash::digest_bytes(b"binary"),
                pcrs: BTreeMap::from([(0, "deadbeef".into())]),
                debug: false,
            },
            nonce: None,
            public_key,
            user_data_hash: None,
            document_hash: Sha256Hash::digest_bytes(&raw),
            timestamp: chrono::Utc::now(),
            raw_attestation_document: raw,
            certificate_chain_pem: Vec::new(),
            signature_hex: String::new(),
        }
    }

    fn submitted_attestation_evidence(
        challenge: &ExecutionSessionChallenge,
        raw: Vec<u8>,
    ) -> AttestationEvidence {
        let document_hash = Sha256Hash::digest_bytes(&raw);
        AttestationEvidence {
            evidence_profile: "aws-nitro-live".into(),
            document: AttestationDocument {
                enclave_id: "enc-session".into(),
                platform: "aws-nitro-live".into(),
                binary_hash: Sha256Hash::digest_bytes(b"binary"),
                measurements: AttestationMeasurements {
                    image_hash: Sha256Hash::digest_bytes(b"binary"),
                    pcrs: BTreeMap::from([(0, "feedface".into())]),
                    debug: false,
                },
                nonce: Some(challenge.challenge_nonce_hex.clone()),
                public_key: Some(vec![9, 8, 7, 6]),
                user_data_hash: Some(challenge.resolved_selector_hash.clone()),
                document_hash,
                timestamp: chrono::Utc::now(),
                raw_attestation_document: raw,
                certificate_chain_pem: Vec::new(),
                signature_hex: String::new(),
            },
        }
    }

    #[test]
    fn test_new_live_keeps_requester_key_empty_even_with_fixture_material() {
        ensure_test_env();
        let proof_engine = Arc::new(NoopProofEngine);
        let verifier = Arc::new(StaticVerifier);
        let manager = NitroEnclaveManager::new_live(
            proof_engine,
            verifier,
            Some(NitroLiveAttestationMaterial {
                document: sample_live_attestation_document(Some(vec![1, 2, 3, 4]), vec![1, 2, 3]),
            }),
            Arc::new(DummyBroker),
        )
        .unwrap();

        assert!(manager.default_requester_ephemeral_pubkey().is_empty());
    }

    #[test]
    fn test_new_live_allows_fixture_without_public_key() {
        ensure_test_env();
        let proof_engine = Arc::new(NoopProofEngine);
        let verifier = Arc::new(StaticVerifier);
        let live_attestation = NitroLiveAttestationMaterial {
            document: AttestationDocument {
                enclave_id: "enc".into(),
                platform: "aws-nitro-live".into(),
                binary_hash: Sha256Hash::digest_bytes(b"binary"),
                measurements: AttestationMeasurements {
                    image_hash: Sha256Hash::digest_bytes(b"binary"),
                    pcrs: BTreeMap::from([(0, "deadbeef".into())]),
                    debug: false,
                },
                nonce: None,
                public_key: None,
                user_data_hash: None,
                document_hash: Sha256Hash::digest_bytes(b"document"),
                timestamp: chrono::Utc::now(),
                raw_attestation_document: vec![1, 2, 3],
                certificate_chain_pem: Vec::new(),
                signature_hex: String::new(),
            },
        };

        NitroEnclaveManager::new_live(
            proof_engine,
            verifier,
            Some(live_attestation),
            Arc::new(DummyBroker),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_run_live_csv_job_uses_submitted_attestation_and_emits_key_erasure() {
        ensure_test_env();
        let proof_engine = Arc::new(StaticProofEngine);
        let verifier = Arc::new(StaticVerifier);
        let bindings = sample_execution_bindings();
        let challenge = bindings.challenge.clone().unwrap();
        let broker = Arc::new(RecordingBroker::default());
        let manager = NitroEnclaveManager::new_live(
            proof_engine,
            verifier,
            Some(NitroLiveAttestationMaterial {
                document: sample_live_attestation_document(Some(vec![1, 2, 3, 4]), vec![0x99]),
            }),
            broker.clone(),
        )
        .unwrap();
        let submitted_raw_document = vec![0xAA, 0xBB, 0xCC];

        let result = manager
            .run_csv_job(EnclaveJobRequest {
                agreement: sample_live_agreement(),
                input_csv: b"input".to_vec(),
                manifest: CsvTransformManifest {
                    dataset_id: "dataset-1".into(),
                    purpose: "analytics".into(),
                    ops: Vec::new(),
                },
                prior_receipt: None,
                attestation_evidence: Some(submitted_attestation_evidence(
                    &challenge,
                    submitted_raw_document.clone(),
                )),
                execution_bindings: Some(bindings),
            })
            .await
            .unwrap();

        assert_eq!(
            broker.released_documents.lock().unwrap().as_slice(),
            &[submitted_raw_document]
        );
        assert!(matches!(
            result.proof_bundle.teardown_evidence,
            Some(TeardownEvidence::KeyErasure(_))
        ));
        assert!(result.proof_bundle.key_erasure_evidence.is_some());
        assert_eq!(
            result
                .execution_evidence
                .attestation_evidence
                .document
                .raw_attestation_document,
            vec![0xAA, 0xBB, 0xCC]
        );
    }

    #[tokio::test]
    async fn test_run_live_csv_job_requires_submitted_attestation_for_kms_policy() {
        ensure_test_env();
        let proof_engine = Arc::new(StaticProofEngine);
        let verifier = Arc::new(StaticVerifier);
        let bindings = sample_execution_bindings();
        let broker = Arc::new(RecordingBroker::default());
        let manager = NitroEnclaveManager::new_live(
            proof_engine,
            verifier,
            Some(NitroLiveAttestationMaterial {
                document: sample_live_attestation_document(Some(vec![1, 2, 3, 4]), vec![0x99]),
            }),
            broker,
        )
        .unwrap();

        let err = manager
            .run_csv_job(EnclaveJobRequest {
                agreement: sample_live_agreement(),
                input_csv: b"input".to_vec(),
                manifest: CsvTransformManifest {
                    dataset_id: "dataset-1".into(),
                    purpose: "analytics".into(),
                    ops: Vec::new(),
                },
                prior_receipt: None,
                attestation_evidence: None,
                execution_bindings: Some(bindings),
            })
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("requires submitted attestation evidence"));
    }

    #[tokio::test]
    async fn test_run_live_csv_job_allows_fixture_mode_without_kms_policy() {
        ensure_test_env();
        let proof_engine = Arc::new(StaticProofEngine);
        let verifier = Arc::new(StaticVerifier);
        let bindings = sample_execution_bindings();
        let manager = NitroEnclaveManager::new_live(
            proof_engine,
            verifier,
            Some(NitroLiveAttestationMaterial {
                document: sample_live_attestation_document(Some(vec![1, 2, 3, 4]), vec![0x99]),
            }),
            Arc::new(RecordingBroker::default()),
        )
        .unwrap();

        let result = manager
            .run_csv_job(EnclaveJobRequest {
                agreement: sample_fixture_mode_agreement(),
                input_csv: b"input".to_vec(),
                manifest: CsvTransformManifest {
                    dataset_id: "dataset-1".into(),
                    purpose: "analytics".into(),
                    ops: Vec::new(),
                },
                prior_receipt: None,
                attestation_evidence: None,
                execution_bindings: Some(bindings),
            })
            .await
            .expect("fixture mode should remain available for local/demo NitroLive runs");

        assert!(result.proof_bundle.teardown_evidence.is_none());
        assert_eq!(
            result
                .execution_evidence
                .attestation_evidence
                .document
                .raw_attestation_document,
            vec![0x99]
        );
    }

    #[tokio::test]
    async fn test_run_live_csv_job_rejects_tee_image_sha384_policy_mismatch() {
        ensure_test_env();
        let proof_engine = Arc::new(StaticProofEngine);
        let verifier = Arc::new(StaticVerifier);
        let bindings = sample_execution_bindings();
        let challenge = bindings.challenge.clone().unwrap();
        let broker = Arc::new(RecordingBroker::default());
        let manager = NitroEnclaveManager::new_live(
            proof_engine,
            verifier,
            Some(NitroLiveAttestationMaterial {
                document: sample_live_attestation_document(Some(vec![1, 2, 3, 4]), vec![0x99]),
            }),
            broker,
        )
        .unwrap();

        let err = manager
            .run_csv_job(EnclaveJobRequest {
                agreement: sample_live_agreement_with_image(&"ff".repeat(48)),
                input_csv: b"input".to_vec(),
                manifest: CsvTransformManifest {
                    dataset_id: "dataset-1".into(),
                    purpose: "analytics".into(),
                    ops: Vec::new(),
                },
                prior_receipt: None,
                attestation_evidence: Some(submitted_attestation_evidence(
                    &challenge,
                    vec![0xAA, 0xBB, 0xCC],
                )),
                execution_bindings: Some(bindings),
            })
            .await
            .unwrap_err();

        assert!(err.to_string().contains("teeImageSha384"));
    }
}
