use lsdc_common::crypto::{PriceAdjustment, ShapleyValue};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{PricingOracle, TrainingMetrics};
use serde::Serialize;

#[derive(Clone)]
pub struct RestPricingOracle {
    base_url: String,
    client: reqwest::Client,
}

impl RestPricingOracle {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }
}

#[derive(Debug, Serialize)]
struct UtilityRequest<'a> {
    dataset_id: &'a str,
    loss_with_dataset: f64,
    loss_without_dataset: f64,
    accuracy_with_dataset: f64,
    accuracy_without_dataset: f64,
}

#[derive(Debug, Serialize)]
struct RenegotiateRequest<'a> {
    agreement_id: &'a str,
    current_price: f64,
    shapley_value: &'a ShapleyValue,
}

#[async_trait::async_trait]
impl PricingOracle for RestPricingOracle {
    async fn evaluate_utility(
        &self,
        dataset_id: &str,
        metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue> {
        let request = UtilityRequest {
            dataset_id,
            loss_with_dataset: metrics.loss_with_dataset,
            loss_without_dataset: metrics.loss_without_dataset,
            accuracy_with_dataset: metrics.accuracy_with_dataset,
            accuracy_without_dataset: metrics.accuracy_without_dataset,
        };

        let response = self
            .client
            .post(self.endpoint("/evaluate"))
            .json(&request)
            .send()
            .await
            .map_err(pricing_transport_error)?
            .error_for_status()
            .map_err(pricing_transport_error)?;

        response.json().await.map_err(pricing_transport_error)
    }

    async fn renegotiate(
        &self,
        agreement_id: &str,
        current_price: f64,
        value: &ShapleyValue,
    ) -> Result<PriceAdjustment> {
        let response = self
            .client
            .post(self.endpoint("/renegotiate"))
            .json(&RenegotiateRequest {
                agreement_id,
                current_price,
                shapley_value: value,
            })
            .send()
            .await
            .map_err(pricing_transport_error)?
            .error_for_status()
            .map_err(pricing_transport_error)?;

        response.json().await.map_err(pricing_transport_error)
    }
}

fn pricing_transport_error(err: reqwest::Error) -> LsdcError {
    LsdcError::Pricing(format!("pricing oracle request failed: {err}"))
}
