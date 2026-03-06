use lsdc_common::crypto::{
    MetricsWindow, PriceDecision, PricingAuditContext, ProofBundle, SanctionProposal, Sha256Hash,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::traits::{
    DataPlane, EnclaveJobRequest, EnclaveManager, EnforcementHandle, PricingOracle, TrainingMetrics,
};
use std::sync::Arc;
use tee_orchestrator::forgetting::verify_proof_of_forgetting;

pub struct BatchLineageRequest {
    pub agreement: ContractAgreement,
    pub iface: String,
    pub input_csv: Vec<u8>,
    pub manifest: CsvTransformManifest,
    pub current_price: f64,
    pub metrics: TrainingMetrics,
    pub prior_receipt: Option<lsdc_common::crypto::ProvenanceReceipt>,
}

pub struct BatchLineageResult {
    pub enforcement_handle: EnforcementHandle,
    pub transformed_csv: Vec<u8>,
    pub proof_bundle: ProofBundle,
    pub price_decision: PriceDecision,
    pub sanction_proposal: Option<SanctionProposal>,
    pub settlement_allowed: bool,
}

pub struct Orchestrator {
    data_plane: Arc<dyn DataPlane>,
    enclave_manager: Option<Arc<dyn EnclaveManager>>,
    pricing_oracle: Option<Arc<dyn PricingOracle>>,
}

impl Orchestrator {
    pub fn new(data_plane: Arc<dyn DataPlane>) -> Self {
        Self {
            data_plane,
            enclave_manager: None,
            pricing_oracle: None,
        }
    }

    pub fn with_pricing(
        data_plane: Arc<dyn DataPlane>,
        pricing_oracle: Arc<dyn PricingOracle>,
    ) -> Self {
        Self {
            data_plane,
            enclave_manager: None,
            pricing_oracle: Some(pricing_oracle),
        }
    }

    pub fn with_full_stack(
        data_plane: Arc<dyn DataPlane>,
        enclave_manager: Arc<dyn EnclaveManager>,
        pricing_oracle: Arc<dyn PricingOracle>,
    ) -> Self {
        Self {
            data_plane,
            enclave_manager: Some(enclave_manager),
            pricing_oracle: Some(pricing_oracle),
        }
    }

    pub async fn activate_agreement(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle> {
        self.data_plane.enforce(agreement, iface).await
    }

    pub async fn revoke_agreement(&self, handle: &EnforcementHandle) -> Result<()> {
        self.data_plane.revoke(handle).await
    }

    pub async fn request_price_decision(
        &self,
        agreement_id: &str,
        current_price: f64,
        audit_context: &PricingAuditContext,
        metrics: &TrainingMetrics,
    ) -> Result<PriceDecision> {
        let pricing_oracle = self.pricing_oracle.as_ref().ok_or_else(|| {
            LsdcError::Pricing("no pricing oracle configured for this orchestrator".into())
        })?;

        let shapley_value = pricing_oracle
            .evaluate_utility(audit_context, metrics)
            .await?;
        pricing_oracle
            .decide_price(agreement_id, current_price, &shapley_value)
            .await
    }

    pub async fn run_batch_csv_lineage(
        &self,
        request: BatchLineageRequest,
    ) -> Result<BatchLineageResult> {
        let enclave_manager = self.enclave_manager.as_ref().ok_or_else(|| {
            LsdcError::Attestation("no enclave manager configured for this orchestrator".into())
        })?;

        let handle = self
            .activate_agreement(&request.agreement, &request.iface)
            .await?;
        let result = async {
            let EnclaveJobRequest {
                agreement,
                input_csv,
                manifest,
                prior_receipt,
            } = EnclaveJobRequest {
                agreement: request.agreement.clone(),
                input_csv: request.input_csv.clone(),
                manifest: request.manifest.clone(),
                prior_receipt: request.prior_receipt.clone(),
            };

            let job_result = enclave_manager
                .run_csv_job(EnclaveJobRequest {
                    agreement,
                    input_csv,
                    manifest,
                    prior_receipt,
                })
                .await?;

            let forgetting_valid =
                verify_proof_of_forgetting(&job_result.proof_bundle.proof_of_forgetting)?;
            let transformed_hash = Sha256Hash::digest_bytes(&job_result.output_csv).to_hex();
            let audit_context = PricingAuditContext {
                dataset_id: request.manifest.dataset_id.clone(),
                transformed_asset_hash: transformed_hash.clone(),
                proof_receipt_hash: Some(
                    job_result
                        .proof_bundle
                        .provenance_receipt
                        .receipt_hash
                        .clone(),
                ),
                model_run_id: request.metrics.model_run_id.clone(),
                metrics_window: MetricsWindow {
                    started_at: request.metrics.metrics_window_started_at,
                    ended_at: request.metrics.metrics_window_ended_at,
                },
            };

            let price_decision = self
                .request_price_decision(
                    &request.agreement.agreement_id.0,
                    request.current_price,
                    &audit_context,
                    &request.metrics,
                )
                .await?;

            let sanction_proposal = (!forgetting_valid).then(|| SanctionProposal {
                subject_id: request.agreement.consumer_id.clone(),
                agreement_id: request.agreement.agreement_id.0.clone(),
                reason: "proof-of-forgetting verification failed; settlement must remain blocked"
                    .into(),
                approval_required: true,
                evidence_hash: job_result.proof_bundle.job_audit_hash.clone(),
            });

            Ok(BatchLineageResult {
                enforcement_handle: handle.clone(),
                transformed_csv: job_result.output_csv,
                proof_bundle: job_result.proof_bundle,
                price_decision,
                sanction_proposal,
                settlement_allowed: forgetting_valid,
            })
        }
        .await;

        if result.is_err() {
            let _ = self.revoke_agreement(&handle).await;
        }

        result
    }
}
