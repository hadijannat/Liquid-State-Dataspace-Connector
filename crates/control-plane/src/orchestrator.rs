use crate::execution_pipeline::{require_enclave_manager, ExecutionPipeline};
use crate::lineage_job_service::LineageJobService;
use crate::pricing_service::{require_pricing_oracle, PricingService};
use lsdc_common::crypto::{PriceDecision, PricingAuditContext};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use lsdc_ports::{DataPlane, EnclaveManager, EnforcementHandle, PricingOracle, TrainingMetrics};
use std::sync::Arc;

pub use crate::execution_pipeline::{BatchLineageRequest, BatchLineageResult};

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
        let pricing = PricingService::new(require_pricing_oracle(self.pricing_oracle.clone())?);
        pricing
            .request_price_decision(agreement_id, current_price, audit_context, metrics)
            .await
    }

    pub async fn run_batch_csv_lineage(
        &self,
        request: BatchLineageRequest,
    ) -> Result<BatchLineageResult> {
        let pipeline = ExecutionPipeline::new(
            self.data_plane.clone(),
            require_enclave_manager(self.enclave_manager.clone())?,
            require_pricing_oracle(self.pricing_oracle.clone())?,
        );
        let lineage = LineageJobService::new(pipeline);
        lineage.run_batch_csv_lineage(request).await
    }
}
