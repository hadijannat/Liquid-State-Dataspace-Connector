use lsdc_common::crypto::{PriceDecision, ShapleyValue};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{PricingOracle, TrainingMetrics};
use tonic::transport::Channel;

pub mod proto {
    tonic::include_proto!("lsdc.pricing");
}

use proto::pricing_oracle_client::PricingOracleClient;

#[derive(Clone)]
pub struct GrpcPricingOracle {
    endpoint: String,
}

impl GrpcPricingOracle {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    async fn client(&self) -> Result<PricingOracleClient<Channel>> {
        PricingOracleClient::connect(self.endpoint.clone())
            .await
            .map_err(|err| LsdcError::Pricing(format!("failed to connect to pricing oracle: {err}")))
    }
}

#[async_trait::async_trait]
impl PricingOracle for GrpcPricingOracle {
    async fn evaluate_utility(
        &self,
        dataset_id: &str,
        transformed_asset_hash: &str,
        metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue> {
        let mut client = self.client().await?;
        let response = client
            .evaluate_utility(proto::UtilityRequest {
                dataset_id: dataset_id.to_string(),
                transformed_asset_hash: transformed_asset_hash.to_string(),
                loss_with_dataset: metrics.loss_with_dataset,
                loss_without_dataset: metrics.loss_without_dataset,
                accuracy_with_dataset: metrics.accuracy_with_dataset,
                accuracy_without_dataset: metrics.accuracy_without_dataset,
            })
            .await
            .map_err(pricing_transport_error)?
            .into_inner();

        Ok(ShapleyValue {
            dataset_id: response.dataset_id,
            transformed_asset_hash: response.transformed_asset_hash,
            marginal_contribution: response.marginal_contribution,
            confidence: response.confidence,
            algorithm_version: response.algorithm_version,
        })
    }

    async fn decide_price(
        &self,
        agreement_id: &str,
        current_price: f64,
        value: &ShapleyValue,
    ) -> Result<PriceDecision> {
        let mut client = self.client().await?;
        let response = client
            .decide_price(proto::PriceDecisionRequest {
                agreement_id: agreement_id.to_string(),
                dataset_id: value.dataset_id.clone(),
                current_price,
                shapley_value: Some(proto::ShapleyResponse {
                    dataset_id: value.dataset_id.clone(),
                    transformed_asset_hash: value.transformed_asset_hash.clone(),
                    marginal_contribution: value.marginal_contribution,
                    confidence: value.confidence,
                    algorithm_version: value.algorithm_version.clone(),
                }),
            })
            .await
            .map_err(pricing_transport_error)?
            .into_inner();

        let shapley = response
            .shapley_value
            .ok_or_else(|| LsdcError::Pricing("pricing oracle omitted shapley value".into()))?;

        Ok(PriceDecision {
            agreement_id: response.agreement_id,
            dataset_id: response.dataset_id,
            original_price: response.original_price,
            adjusted_price: response.adjusted_price,
            approval_required: response.approval_required,
            shapley_value: ShapleyValue {
                dataset_id: shapley.dataset_id,
                transformed_asset_hash: shapley.transformed_asset_hash,
                marginal_contribution: shapley.marginal_contribution,
                confidence: shapley.confidence,
                algorithm_version: shapley.algorithm_version,
            },
            signed_by: response.signed_by,
            signature_hex: response.signature_hex,
        })
    }
}

fn pricing_transport_error(err: tonic::Status) -> LsdcError {
    LsdcError::Pricing(format!("pricing oracle request failed: {err}"))
}
