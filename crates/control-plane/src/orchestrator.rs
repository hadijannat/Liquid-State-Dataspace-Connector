use lsdc_common::crypto::PriceAdjustment;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use lsdc_common::traits::{DataPlane, EnforcementHandle, PricingOracle, TrainingMetrics};
use std::sync::Arc;

/// The Orchestrator dispatches finalized agreements to the appropriate planes.
pub struct Orchestrator {
    data_plane: Arc<dyn DataPlane>,
    pricing_oracle: Option<Arc<dyn PricingOracle>>,
}

impl Orchestrator {
    pub fn new(data_plane: Arc<dyn DataPlane>) -> Self {
        Self {
            data_plane,
            pricing_oracle: None,
        }
    }

    pub fn with_pricing(
        data_plane: Arc<dyn DataPlane>,
        pricing_oracle: Arc<dyn PricingOracle>,
    ) -> Self {
        Self {
            data_plane,
            pricing_oracle: Some(pricing_oracle),
        }
    }

    /// After a contract is signed, enforce the policy on the data plane.
    pub async fn activate_agreement(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle> {
        tracing::info!(
            agreement_id = %agreement.agreement_id.0,
            "Activating agreement on data plane"
        );

        self.data_plane.enforce(agreement, iface).await
    }

    /// Revoke an active agreement.
    pub async fn revoke_agreement(&self, handle: &EnforcementHandle) -> Result<()> {
        self.data_plane.revoke(handle).await
    }

    /// Request an advisory price adjustment from the configured pricing oracle.
    pub async fn advise_price_adjustment(
        &self,
        agreement_id: &str,
        dataset_id: &str,
        current_price: f64,
        metrics: &TrainingMetrics,
    ) -> Result<PriceAdjustment> {
        let pricing_oracle = self.pricing_oracle.as_ref().ok_or_else(|| {
            lsdc_common::error::LsdcError::Pricing(
                "No pricing oracle configured for this orchestrator".into(),
            )
        })?;

        let shapley_value = pricing_oracle.evaluate_utility(dataset_id, metrics).await?;
        pricing_oracle
            .renegotiate(agreement_id, current_price, &shapley_value)
            .await
    }
}
