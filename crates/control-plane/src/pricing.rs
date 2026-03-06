use lsdc_common::crypto::{
    MetricsWindow, PriceDecision, PricingAuditContext, Sha256Hash, ShapleyValue,
};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::PricingMode;
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
            .map_err(|err| {
                LsdcError::Pricing(format!("failed to connect to pricing oracle: {err}"))
            })
    }
}

#[async_trait::async_trait]
impl PricingOracle for GrpcPricingOracle {
    async fn evaluate_utility(
        &self,
        audit_context: &PricingAuditContext,
        metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue> {
        let mut client = self.client().await?;
        let response = client
            .evaluate_utility(proto::UtilityRequest {
                audit_context: Some(proto::PricingAuditContext {
                    dataset_id: audit_context.dataset_id.clone(),
                    transformed_asset_hash: audit_context.transformed_asset_hash.clone(),
                    proof_receipt_hash: audit_context
                        .proof_receipt_hash
                        .as_ref()
                        .map_or_else(String::new, Sha256Hash::to_hex),
                    model_run_id: audit_context.model_run_id.clone(),
                    metrics_window_started_at: audit_context.metrics_window.started_at.to_rfc3339(),
                    metrics_window_ended_at: audit_context.metrics_window.ended_at.to_rfc3339(),
                }),
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
            audit_context: audit_context_from_proto(response.audit_context)?,
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
                current_price,
                shapley_value: Some(proto::ShapleyResponse {
                    dataset_id: value.dataset_id.clone(),
                    transformed_asset_hash: value.transformed_asset_hash.clone(),
                    marginal_contribution: value.marginal_contribution,
                    confidence: value.confidence,
                    algorithm_version: value.algorithm_version.clone(),
                    audit_context: Some(proto::PricingAuditContext {
                        dataset_id: value.audit_context.dataset_id.clone(),
                        transformed_asset_hash: value.audit_context.transformed_asset_hash.clone(),
                        proof_receipt_hash: value
                            .audit_context
                            .proof_receipt_hash
                            .as_ref()
                            .map_or_else(String::new, Sha256Hash::to_hex),
                        model_run_id: value.audit_context.model_run_id.clone(),
                        metrics_window_started_at: value
                            .audit_context
                            .metrics_window
                            .started_at
                            .to_rfc3339(),
                        metrics_window_ended_at: value
                            .audit_context
                            .metrics_window
                            .ended_at
                            .to_rfc3339(),
                    }),
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
            pricing_mode: parse_pricing_mode(&response.pricing_mode),
            shapley_value: ShapleyValue {
                dataset_id: shapley.dataset_id,
                transformed_asset_hash: shapley.transformed_asset_hash,
                marginal_contribution: shapley.marginal_contribution,
                confidence: shapley.confidence,
                algorithm_version: shapley.algorithm_version,
                audit_context: audit_context_from_proto(shapley.audit_context)?,
            },
            signed_by: response.signed_by,
            signature_hex: response.signature_hex,
        })
    }
}

fn pricing_transport_error(err: tonic::Status) -> LsdcError {
    LsdcError::Pricing(format!("pricing oracle request failed: {err}"))
}

fn audit_context_from_proto(
    proto: Option<proto::PricingAuditContext>,
) -> Result<PricingAuditContext> {
    let proto =
        proto.ok_or_else(|| LsdcError::Pricing("pricing oracle omitted audit context".into()))?;

    let proof_receipt_hash = if proto.proof_receipt_hash.is_empty() {
        None
    } else {
        Some(parse_sha256_hex(&proto.proof_receipt_hash)?)
    };

    Ok(PricingAuditContext {
        dataset_id: proto.dataset_id,
        transformed_asset_hash: proto.transformed_asset_hash,
        proof_receipt_hash,
        model_run_id: proto.model_run_id,
        metrics_window: MetricsWindow {
            started_at: parse_rfc3339_utc(&proto.metrics_window_started_at)?,
            ended_at: parse_rfc3339_utc(&proto.metrics_window_ended_at)?,
        },
    })
}

fn parse_pricing_mode(value: &str) -> PricingMode {
    match value {
        "advisory" => PricingMode::Advisory,
        _ => PricingMode::Disabled,
    }
}

fn parse_sha256_hex(value: &str) -> Result<Sha256Hash> {
    Sha256Hash::from_hex(value)
        .map_err(|err| LsdcError::Pricing(format!("invalid proof receipt hash hex: {err}")))
}

fn parse_rfc3339_utc(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .map_err(|err| LsdcError::Pricing(format!("invalid RFC3339 timestamp: {err}")))
}
