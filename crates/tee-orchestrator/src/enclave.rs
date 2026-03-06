use crate::attestation::build_attestation_document;
use crate::forgetting::build_proof_of_forgetting;
use async_trait::async_trait;
use lsdc_common::crypto::{ProofBundle, Sha256Hash};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{EnclaveJobRequest, EnclaveJobResult, EnclaveManager, ProofEngine};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

const PROTOTYPE_PLATFORM: &str = "aws-nitro-prototype";

pub struct NitroEnclaveManager {
    proof_engine: Arc<dyn ProofEngine>,
}

impl NitroEnclaveManager {
    pub fn new(proof_engine: Arc<dyn ProofEngine>) -> Self {
        Self { proof_engine }
    }
}

#[async_trait]
impl EnclaveManager for NitroEnclaveManager {
    async fn run_csv_job(&self, request: EnclaveJobRequest) -> Result<EnclaveJobResult> {
        let binary_hash = Sha256Hash::digest_bytes(
            serde_json::to_vec(&serde_json::json!({
                "agreement_id": request.agreement.agreement_id.0,
                "policy_hash": request.agreement.policy_hash,
                "manifest": request.manifest,
            }))
            .map_err(LsdcError::from)?
            .as_slice(),
        );

        let enclave_id = format!("nitro-{}", Uuid::new_v4());
        let attestation =
            build_attestation_document(&enclave_id, PROTOTYPE_PLATFORM, &binary_hash, chrono::Utc::now())?;

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
