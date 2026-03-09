use crate::breach_service::assess_evidence;
use crate::pricing_service::PricingService;
use lsdc_common::crypto::{
    MetricsWindow, PriceDecision, PricingAuditContext, ProofBundle, SanctionProposal, Sha256Hash,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_ports::{
    DataPlane, EnclaveJobRequest, EnclaveManager, EnforcementHandle, PricingOracle, TrainingMetrics,
};
use std::sync::Arc;

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

pub struct ExecutionPipeline {
    data_plane: Arc<dyn DataPlane>,
    enclave_manager: Arc<dyn EnclaveManager>,
    pricing_service: PricingService,
}

impl ExecutionPipeline {
    pub fn new(
        data_plane: Arc<dyn DataPlane>,
        enclave_manager: Arc<dyn EnclaveManager>,
        pricing_oracle: Arc<dyn PricingOracle>,
    ) -> Self {
        Self {
            data_plane,
            enclave_manager,
            pricing_service: PricingService::new(pricing_oracle),
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

    pub async fn run_batch_csv_lineage(
        &self,
        request: BatchLineageRequest,
    ) -> Result<BatchLineageResult> {
        let handle = self
            .activate_agreement(&request.agreement, &request.iface)
            .await?;
        let result = async {
            let job_result = self
                .enclave_manager
                .run_csv_job(EnclaveJobRequest {
                    agreement: request.agreement.clone(),
                    input_csv: request.input_csv.clone(),
                    manifest: request.manifest.clone(),
                    prior_receipt: request.prior_receipt.clone(),
                })
                .await?;

            let audit_context = PricingAuditContext {
                dataset_id: request.manifest.dataset_id.clone(),
                transformed_asset_hash: Sha256Hash::digest_bytes(&job_result.output_csv).to_hex(),
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
                .pricing_service
                .request_price_decision(
                    &request.agreement.agreement_id.0,
                    request.current_price,
                    &audit_context,
                    &request.metrics,
                )
                .await?;

            let breach = assess_evidence(&request.agreement, &job_result.proof_bundle)?;

            Ok(BatchLineageResult {
                enforcement_handle: handle.clone(),
                transformed_csv: job_result.output_csv,
                proof_bundle: job_result.proof_bundle,
                price_decision,
                sanction_proposal: breach.sanction_proposal,
                settlement_allowed: breach.settlement_allowed,
            })
        }
        .await;

        if result.is_err() {
            let _ = self.revoke_agreement(&handle).await;
        }

        result
    }
}

pub fn require_enclave_manager(
    enclave_manager: Option<Arc<dyn EnclaveManager>>,
) -> Result<Arc<dyn EnclaveManager>> {
    enclave_manager.ok_or_else(|| {
        LsdcError::Attestation("no enclave manager configured for this orchestrator".into())
    })
}
