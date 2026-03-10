use crate::attestation::{
    build_attestation_document, build_attestation_document_with_binding, AttestationBinding,
    LocalAttestationVerifier,
};
use crate::forgetting::{build_proof_of_forgetting, validate_forgetting_secret};
use async_trait::async_trait;
use lsdc_common::crypto::{
    canonical_json_bytes, AttestationDocument, AttestationEvidence, AttestationMeasurements,
    ExecutionEvidenceBundle, ProofBundle, Sha256Hash, TeardownEvidence,
};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::TeeBackend;
use lsdc_evidence::DevDeletionEvidence;
use lsdc_ports::{
    AttestationVerifier, EnclaveJobRequest, EnclaveJobResult, EnclaveManager, ProofEngine,
};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

pub struct NitroEnclaveManager {
    proof_engine: Arc<dyn ProofEngine>,
    attestation_verifier: Arc<dyn AttestationVerifier>,
    mode: TeeBackend,
    live_attestation: Option<NitroLiveAttestationMaterial>,
}

#[derive(Clone)]
pub struct NitroLiveAttestationMaterial {
    pub enclave_id: String,
    pub expected_image_hash: Sha256Hash,
    pub measurements: AttestationMeasurements,
    pub raw_attestation_document: Vec<u8>,
    pub certificate_chain_pem: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl NitroEnclaveManager {
    pub fn new_dev(proof_engine: Arc<dyn ProofEngine>) -> Result<Self> {
        validate_forgetting_secret()?;
        Ok(Self {
            proof_engine,
            attestation_verifier: Arc::new(LocalAttestationVerifier::new()),
            mode: TeeBackend::NitroDev,
            live_attestation: None,
        })
    }

    pub fn new_live(
        proof_engine: Arc<dyn ProofEngine>,
        live_attestation: NitroLiveAttestationMaterial,
    ) -> Result<Self> {
        validate_forgetting_secret()?;
        validate_live_attestation(&live_attestation)?;
        Ok(Self {
            proof_engine,
            attestation_verifier: Arc::new(LocalAttestationVerifier::new()),
            mode: TeeBackend::NitroLive,
            live_attestation: Some(live_attestation),
        })
    }
}

#[async_trait]
impl EnclaveManager for NitroEnclaveManager {
    fn tee_backend(&self) -> TeeBackend {
        self.mode
    }

    async fn run_csv_job(&self, request: EnclaveJobRequest) -> Result<EnclaveJobResult> {
        let manifest_hash = Sha256Hash::digest_bytes(
            serde_json::to_vec(&serde_json::json!({
                "agreement_id": request.agreement.agreement_id.0,
                "policy_hash": request.agreement.policy_hash,
                "manifest": request.manifest,
            }))
            .map_err(LsdcError::from)?
            .as_slice(),
        );

        let attestation = match self.mode {
            TeeBackend::NitroDev => {
                let enclave_id = format!("nitro-{}", Uuid::new_v4());
                let binding = request
                    .execution_bindings
                    .as_ref()
                    .and_then(|bindings| bindings.challenge.as_ref())
                    .map(|challenge| AttestationBinding {
                        challenge_nonce_hex: &challenge.challenge_nonce_hex,
                        public_key: Some(challenge.requester_ephemeral_pubkey.as_slice()),
                        user_data_hash: Some(&challenge.resolved_selector_hash),
                    });
                match binding {
                    Some(binding) => build_attestation_document_with_binding(
                        &enclave_id,
                        &manifest_hash,
                        chrono::Utc::now(),
                        Some(binding),
                    )?,
                    None => {
                        build_attestation_document(&enclave_id, &manifest_hash, chrono::Utc::now())?
                    }
                }
            }
            TeeBackend::NitroLive => {
                let live_attestation = self.live_attestation.as_ref().ok_or_else(|| {
                    LsdcError::Attestation(
                        "nitro-live mode requires pinned attestation material".into(),
                    )
                })?;
                validate_live_attestation(live_attestation)?
            }
            TeeBackend::None => {
                return Err(LsdcError::Attestation(
                    "nitro enclave manager requires a nitro backend".into(),
                ))
            }
        };
        let attestation_evidence = AttestationEvidence {
            evidence_profile: attestation.platform.clone(),
            document: attestation.clone(),
        };
        let attestation_result = self.attestation_verifier.appraise_attestation_evidence(
            &attestation_evidence,
            request
                .execution_bindings
                .as_ref()
                .and_then(|bindings| bindings.challenge.as_ref()),
        )?;
        let attestation_result_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(&attestation_result).map_err(LsdcError::from)?,
            )
            .map_err(LsdcError::from)?,
        );
        let proof_execution_bindings = request.execution_bindings.as_ref().map(|bindings| {
            let mut bound = bindings.clone();
            bound.attestation_result_hash = Some(attestation_result_hash.clone());
            bound
        });

        let proof_result = self
            .proof_engine
            .execute_csv_transform(
                &request.agreement,
                request.input_csv.as_slice(),
                &request.manifest,
                request.prior_receipt.as_ref(),
                proof_execution_bindings.as_ref(),
            )
            .await?;

        let mut wipe_buffer = request.input_csv.clone();
        wipe_buffer.zeroize();

        let proof_of_forgetting = build_proof_of_forgetting(
            attestation.clone(),
            chrono::Utc::now(),
            &proof_result.receipt.input_hash,
        )?;
        let dev_deletion_evidence = DevDeletionEvidence::from(&proof_of_forgetting);
        let evidence_root_hash = Sha256Hash::digest_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "receipt_hash": proof_result.receipt.receipt_hash.to_hex(),
                "attestation_result_hash": attestation_result_hash.to_hex(),
                "teardown_hash": dev_deletion_evidence.proof_hash.to_hex(),
            }))
            .map_err(LsdcError::from)?,
        );

        let audit_bytes = serde_json::to_vec(&serde_json::json!({
            "receipt_hash": proof_result.receipt.receipt_hash.to_hex(),
            "attestation_hash": attestation.document_hash.to_hex(),
            "attestation_result_hash": attestation_result_hash.to_hex(),
            "teardown_hash": dev_deletion_evidence.proof_hash.to_hex(),
            "output_hash": Sha256Hash::digest_bytes(&proof_result.output_csv).to_hex(),
            "evidence_root_hash": evidence_root_hash.to_hex(),
        }))
        .map_err(LsdcError::from)?;

        let execution_evidence = ExecutionEvidenceBundle {
            attestation_evidence,
            provenance_receipt: proof_result.receipt,
            attestation_result: Some(attestation_result),
            teardown_evidence: Some(TeardownEvidence::DevDeletion(dev_deletion_evidence.clone())),
            transparency_receipt_hash: None,
            evidence_root_hash,
            job_audit_hash: Sha256Hash::digest_bytes(&audit_bytes),
        };
        let proof_bundle = ProofBundle {
            proof_backend: execution_evidence.provenance_receipt.proof_backend,
            receipt_format_version: execution_evidence
                .provenance_receipt
                .receipt_format_version
                .clone(),
            proof_method_id: execution_evidence
                .provenance_receipt
                .proof_method_id
                .clone(),
            prior_receipt_hash: execution_evidence
                .provenance_receipt
                .prior_receipt_hash
                .clone(),
            raw_receipt_bytes: execution_evidence.provenance_receipt.receipt_bytes.clone(),
            provenance_receipt: execution_evidence.provenance_receipt.clone(),
            attestation: attestation.clone(),
            proof_of_forgetting,
            attestation_result: execution_evidence.attestation_result.clone(),
            teardown_evidence: execution_evidence.teardown_evidence.clone(),
            key_erasure_evidence: None,
            evidence_root_hash: Some(execution_evidence.evidence_root_hash.clone()),
            transparency_receipt_hash: execution_evidence.transparency_receipt_hash.clone(),
            job_audit_hash: execution_evidence.job_audit_hash.clone(),
        };

        Ok(EnclaveJobResult {
            output_csv: proof_result.output_csv,
            proof_bundle,
            execution_evidence,
        })
    }
}

fn validate_live_attestation(
    material: &NitroLiveAttestationMaterial,
) -> Result<AttestationDocument> {
    let zero_pcrs = [0_u16, 1_u16, 2_u16].into_iter().all(|pcr| {
        material
            .measurements
            .pcrs
            .get(&pcr)
            .is_some_and(|value| is_zero_hex(value))
    });

    if zero_pcrs || material.measurements.debug {
        return Err(LsdcError::Attestation(
            "nitro-live attestation rejected debug-mode zero-PCR measurements".into(),
        ));
    }

    if material.measurements.image_hash != material.expected_image_hash {
        return Err(LsdcError::Attestation(
            "nitro-live attestation image hash does not match the pinned EIF measurement".into(),
        ));
    }

    if material.raw_attestation_document.is_empty() {
        return Err(LsdcError::Attestation(
            "nitro-live attestation must include the raw attestation document".into(),
        ));
    }

    let document_hash = Sha256Hash::digest_bytes(&material.raw_attestation_document);
    Ok(AttestationDocument {
        enclave_id: material.enclave_id.clone(),
        platform: "aws-nitro-live".into(),
        binary_hash: material.expected_image_hash.clone(),
        measurements: material.measurements.clone(),
        nonce: None,
        public_key: None,
        user_data_hash: None,
        document_hash,
        timestamp: material.timestamp,
        raw_attestation_document: material.raw_attestation_document.clone(),
        certificate_chain_pem: material.certificate_chain_pem.clone(),
        signature_hex: String::new(),
    })
}

fn is_zero_hex(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    struct NoopProofEngine;

    #[async_trait::async_trait]
    impl ProofEngine for NoopProofEngine {
        fn proof_backend(&self) -> lsdc_common::execution::ProofBackend {
            lsdc_common::execution::ProofBackend::None
        }

        async fn execute_csv_transform(
            &self,
            _agreement: &lsdc_common::dsp::ContractAgreement,
            _input_csv: &[u8],
            _manifest: &lsdc_common::liquid::CsvTransformManifest,
            _prior_receipt: Option<&lsdc_common::crypto::ProvenanceReceipt>,
            _execution_bindings: Option<&lsdc_ports::ExecutionBindings>,
        ) -> Result<lsdc_ports::ProofExecutionResult> {
            unreachable!("proof execution is not used in this test")
        }

        async fn verify_receipt(
            &self,
            _receipt: &lsdc_common::crypto::ProvenanceReceipt,
        ) -> Result<bool> {
            unreachable!("receipt verification is not used in this test")
        }

        async fn verify_chain(
            &self,
            _chain: &[lsdc_common::crypto::ProvenanceReceipt],
        ) -> Result<bool> {
            unreachable!("chain verification is not used in this test")
        }

        async fn compose_receipts(
            &self,
            _receipts: &[lsdc_common::crypto::ProvenanceReceipt],
            _ctx: lsdc_ports::CompositionContext,
        ) -> Result<lsdc_common::crypto::ProvenanceReceipt> {
            unreachable!("composition is not used in this test")
        }

        async fn verify_receipt_dag(
            &self,
            _dag: &lsdc_common::runtime_model::EvidenceDag,
        ) -> Result<bool> {
            unreachable!("dag verification is not used in this test")
        }
    }

    #[derive(Deserialize)]
    struct FixtureMeasurements {
        image_hash_hex: String,
        pcrs: std::collections::BTreeMap<u16, String>,
        debug: bool,
    }

    #[derive(Deserialize)]
    struct FixtureMaterial {
        enclave_id: String,
        expected_image_hash_hex: String,
        measurements: FixtureMeasurements,
        raw_attestation_document_utf8: String,
        certificate_chain_pem: Vec<String>,
        timestamp: String,
    }

    fn load_live_material() -> NitroLiveAttestationMaterial {
        let fixture: FixtureMaterial =
            lsdc_common::fixtures::read_json("nitro/live_attestation_material.json").unwrap();
        NitroLiveAttestationMaterial {
            enclave_id: fixture.enclave_id,
            expected_image_hash: Sha256Hash::from_hex(&fixture.expected_image_hash_hex).unwrap(),
            measurements: AttestationMeasurements {
                image_hash: Sha256Hash::from_hex(&fixture.measurements.image_hash_hex).unwrap(),
                pcrs: fixture.measurements.pcrs,
                debug: fixture.measurements.debug,
            },
            raw_attestation_document: fixture.raw_attestation_document_utf8.into_bytes(),
            certificate_chain_pem: fixture.certificate_chain_pem,
            timestamp: chrono::DateTime::parse_from_rfc3339(&fixture.timestamp)
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    #[test]
    fn test_live_attestation_rejects_wrong_measurement() {
        let mut material = load_live_material();
        material.measurements.image_hash = Sha256Hash::digest_bytes(b"wrong");

        let err = validate_live_attestation(&material).unwrap_err();
        assert!(err.to_string().contains("pinned EIF measurement"));
    }

    #[test]
    fn test_live_attestation_rejects_debug_zero_pcrs() {
        let mut material = load_live_material();
        material.measurements.debug = true;
        material.measurements.pcrs.insert(0, "0".repeat(64));
        material.measurements.pcrs.insert(1, "0".repeat(64));
        material.measurements.pcrs.insert(2, "0".repeat(64));

        let err = validate_live_attestation(&material).unwrap_err();
        assert!(err.to_string().contains("zero-PCR"));
    }

    #[test]
    fn test_live_attestation_accepts_fixture_sample() {
        let material = load_live_material();
        let expected = material.expected_image_hash.clone();

        let attestation = validate_live_attestation(&material).unwrap();
        assert_eq!(attestation.platform, "aws-nitro-live");
        assert_eq!(attestation.binary_hash, expected);
        assert!(!attestation.measurements.debug);
    }

    #[test]
    fn test_new_live_rejects_missing_forgetting_secret_without_dev_defaults() {
        let _guard = crate::forgetting::env_lock_for_tests();
        let old_allow_dev_defaults = std::env::var("LSDC_ALLOW_DEV_DEFAULTS").ok();
        let old_forgetting_secret = std::env::var("LSDC_FORGETTING_SECRET").ok();
        std::env::remove_var("LSDC_ALLOW_DEV_DEFAULTS");
        std::env::remove_var("LSDC_FORGETTING_SECRET");

        let result = NitroEnclaveManager::new_live(Arc::new(NoopProofEngine), load_live_material());

        match old_allow_dev_defaults {
            Some(value) => std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", value),
            None => std::env::remove_var("LSDC_ALLOW_DEV_DEFAULTS"),
        }
        match old_forgetting_secret {
            Some(value) => std::env::set_var("LSDC_FORGETTING_SECRET", value),
            None => std::env::remove_var("LSDC_FORGETTING_SECRET"),
        }

        let err = match result {
            Ok(_) => panic!("expected nitro-live startup to reject a missing forgetting secret"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("LSDC_FORGETTING_SECRET must be set unless LSDC_ALLOW_DEV_DEFAULTS=1"));
    }
}
