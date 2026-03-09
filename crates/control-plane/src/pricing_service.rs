use lsdc_common::crypto::{PriceDecision, PricingAuditContext};
use lsdc_common::error::{LsdcError, Result};
use lsdc_ports::{PricingOracle, TrainingMetrics};
use std::sync::Arc;

pub struct PricingService {
    pricing_oracle: Arc<dyn PricingOracle>,
}

impl PricingService {
    pub fn new(pricing_oracle: Arc<dyn PricingOracle>) -> Self {
        Self { pricing_oracle }
    }

    pub async fn request_price_decision(
        &self,
        agreement_id: &str,
        current_price: f64,
        audit_context: &PricingAuditContext,
        metrics: &TrainingMetrics,
    ) -> Result<PriceDecision> {
        let shapley_value = self
            .pricing_oracle
            .evaluate_utility(audit_context, metrics)
            .await?;
        self.pricing_oracle
            .decide_price(agreement_id, current_price, &shapley_value)
            .await
    }
}

pub fn require_pricing_oracle(
    pricing_oracle: Option<Arc<dyn PricingOracle>>,
) -> Result<Arc<dyn PricingOracle>> {
    pricing_oracle
        .ok_or_else(|| LsdcError::Pricing("no pricing oracle configured for this orchestrator".into()))
}
