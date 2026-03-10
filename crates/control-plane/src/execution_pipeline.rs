use crate::breach_service::assess_evidence;
use crate::pricing_service::PricingService;
use lsdc_common::crypto::{
    canonical_json_bytes, ExecutionEvidenceBundle, MetricsWindow, PriceDecision,
    PricingAuditContext, ProofBundle, SanctionProposal, Sha256Hash,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution_overlay::ExecutionSessionChallenge;
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_ports::{
    DataPlane, EnclaveJobRequest, EnclaveManager, EnforcementHandle, ExecutionBindings,
    PricingOracle, ResolvedTransportGuard, TrainingMetrics,
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
    pub execution_bindings: Option<ExecutionBindings>,
}

pub struct BatchLineageResult {
    pub enforcement_handle: EnforcementHandle,
    pub execution_bindings: Option<ExecutionBindings>,
    pub transformed_csv: Vec<u8>,
    pub proof_bundle: ProofBundle,
    pub execution_evidence: ExecutionEvidenceBundle,
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
        let BatchLineageRequest {
            agreement,
            iface,
            input_csv,
            manifest,
            current_price,
            metrics,
            prior_receipt,
            execution_bindings,
        } = request;
        let handle = self.activate_agreement(&agreement, &iface).await?;
        let execution_bindings =
            materialize_execution_bindings(execution_bindings, handle.resolved_transport.as_ref())?;
        let result = async {
            let agreement_id = agreement.agreement_id.0.clone();
            let dataset_id = manifest.dataset_id.clone();
            let job_result = self
                .enclave_manager
                .run_csv_job(EnclaveJobRequest {
                    agreement: agreement.clone(),
                    input_csv,
                    manifest,
                    prior_receipt,
                    execution_bindings: execution_bindings.clone(),
                })
                .await?;

            let audit_context = PricingAuditContext {
                dataset_id,
                transformed_asset_hash: Sha256Hash::digest_bytes(&job_result.output_csv).to_hex(),
                proof_receipt_hash: Some(
                    job_result
                        .proof_bundle
                        .provenance_receipt
                        .receipt_hash
                        .clone(),
                ),
                model_run_id: metrics.model_run_id.clone(),
                metrics_window: MetricsWindow {
                    started_at: metrics.metrics_window_started_at,
                    ended_at: metrics.metrics_window_ended_at,
                },
            };

            let price_decision = self
                .pricing_service
                .request_price_decision(&agreement_id, current_price, &audit_context, &metrics)
                .await?;

            let breach = assess_evidence(&agreement, &job_result.proof_bundle)?;

            Ok(BatchLineageResult {
                enforcement_handle: handle.clone(),
                execution_bindings,
                transformed_csv: job_result.output_csv,
                proof_bundle: job_result.proof_bundle,
                execution_evidence: job_result.execution_evidence,
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

fn materialize_execution_bindings(
    execution_bindings: Option<ExecutionBindings>,
    resolved_transport: Option<&ResolvedTransportGuard>,
) -> Result<Option<ExecutionBindings>> {
    let Some(mut bindings) = execution_bindings else {
        return Ok(None);
    };
    let Some(resolved_transport) = resolved_transport.cloned() else {
        bindings.resolved_transport = None;
        return Ok(Some(bindings));
    };
    let resolved_selector_hash = Sha256Hash::digest_bytes(
        &canonical_json_bytes(
            &serde_json::to_value(&resolved_transport).map_err(LsdcError::from)?,
        )
        .map_err(LsdcError::from)?,
    );
    bindings.resolved_transport = Some(resolved_transport);
    bindings.session.resolved_selector_hash = Some(resolved_selector_hash.clone());

    match bindings.challenge.as_ref() {
        Some(challenge) if challenge.resolved_selector_hash != resolved_selector_hash => {
            return Err(LsdcError::PolicyCompile(
                "execution challenge does not match resolved transport guard".into(),
            ));
        }
        Some(_) => {}
        None => {
            bindings.challenge = Some(ExecutionSessionChallenge::issue(
                &bindings.session,
                resolved_selector_hash,
                chrono::Utc::now(),
            ));
        }
    }

    Ok(Some(bindings))
}

pub fn require_enclave_manager(
    enclave_manager: Option<Arc<dyn EnclaveManager>>,
) -> Result<Arc<dyn EnclaveManager>> {
    enclave_manager.ok_or_else(|| {
        LsdcError::Attestation("no enclave manager configured for this orchestrator".into())
    })
}
