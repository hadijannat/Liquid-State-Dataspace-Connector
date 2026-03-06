use crate::attestation::build_attestation_document;
use crate::forgetting::build_proof_of_forgetting;
use async_trait::async_trait;
use lsdc_common::crypto::{AttestationDocument, AttestationMeasurements, ProofBundle, Sha256Hash};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::TeeBackend;
use lsdc_common::traits::{EnclaveJobRequest, EnclaveJobResult, EnclaveManager, ProofEngine};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

pub struct NitroEnclaveManager {
    proof_engine: Arc<dyn ProofEngine>,
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
    pub fn new_dev(proof_engine: Arc<dyn ProofEngine>) -> Self {
        Self {
            proof_engine,
            mode: TeeBackend::NitroDev,
            live_attestation: None,
        }
    }

    pub fn new_live(
        proof_engine: Arc<dyn ProofEngine>,
        live_attestation: NitroLiveAttestationMaterial,
    ) -> Self {
        Self {
            proof_engine,
            mode: TeeBackend::NitroLive,
            live_attestation: Some(live_attestation),
        }
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
                build_attestation_document(&enclave_id, &manifest_hash, chrono::Utc::now())?
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

        let proof_result = self
            .proof_engine
            .execute_csv_transform(
                &request.agreement,
                request.input_csv.as_slice(),
                &request.manifest,
                request.prior_receipt.as_ref(),
            )
            .await?;

        let input_hash = Sha256Hash::digest_bytes(&request.input_csv);
        let mut wipe_buffer = request.input_csv.clone();
        wipe_buffer.zeroize();

        let proof_of_forgetting =
            build_proof_of_forgetting(attestation.clone(), chrono::Utc::now(), &input_hash)?;

        let audit_bytes = serde_json::to_vec(&serde_json::json!({
            "receipt_hash": proof_result.receipt.receipt_hash.to_hex(),
            "attestation_hash": attestation.document_hash.to_hex(),
            "forgetting_hash": proof_of_forgetting.proof_hash.to_hex(),
            "output_hash": Sha256Hash::digest_bytes(&proof_result.output_csv).to_hex(),
        }))
        .map_err(LsdcError::from)?;

        let proof_bundle = ProofBundle {
            proof_backend: proof_result.receipt.proof_backend,
            receipt_format_version: proof_result.receipt.receipt_format_version.clone(),
            proof_method_id: proof_result.receipt.proof_method_id.clone(),
            prior_receipt_hash: proof_result.receipt.prior_receipt_hash.clone(),
            raw_receipt_bytes: proof_result.receipt.receipt_bytes.clone(),
            provenance_receipt: proof_result.receipt,
            attestation,
            proof_of_forgetting,
            job_audit_hash: Sha256Hash::digest_bytes(&audit_bytes),
        };

        Ok(EnclaveJobResult {
            output_csv: proof_result.output_csv,
            proof_bundle,
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
}
