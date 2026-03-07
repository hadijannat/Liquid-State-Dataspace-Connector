use async_trait::async_trait;
use control_plane::orchestrator::Orchestrator;
use control_plane::pricing::proto::pricing_oracle_server::{PricingOracle, PricingOracleServer};
use control_plane::pricing::proto::{
    PriceDecisionRequest, PriceDecisionResponse, ShapleyResponse, UtilityRequest,
};
use control_plane::pricing::GrpcPricingOracle;
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_common::crypto::{MetricsWindow, PriceDecision, PricingAuditContext, ShapleyValue};
use lsdc_common::error::Result;
use lsdc_common::execution::PricingMode;
use lsdc_ports::{PricingOracle as PricingOracleTrait, TrainingMetrics};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Default)]
struct TestPricingService;

#[async_trait]
impl PricingOracle for TestPricingService {
    async fn evaluate_utility(
        &self,
        request: Request<UtilityRequest>,
    ) -> std::result::Result<Response<ShapleyResponse>, Status> {
        let request = request.into_inner();
        let audit_context = request
            .audit_context
            .ok_or_else(|| Status::invalid_argument("missing audit context"))?;
        Ok(Response::new(ShapleyResponse {
            dataset_id: audit_context.dataset_id.clone(),
            transformed_asset_hash: audit_context.transformed_asset_hash.clone(),
            marginal_contribution: 0.14,
            confidence: 0.9,
            algorithm_version: "heuristic_marginal_v0".into(),
            audit_context: Some(audit_context),
        }))
    }

    async fn decide_price(
        &self,
        request: Request<PriceDecisionRequest>,
    ) -> std::result::Result<Response<PriceDecisionResponse>, Status> {
        let request = request.into_inner();
        let shapley = request
            .shapley_value
            .ok_or_else(|| Status::invalid_argument("missing shapley value"))?;

        Ok(Response::new(PriceDecisionResponse {
            agreement_id: request.agreement_id,
            dataset_id: shapley.dataset_id.clone(),
            original_price: request.current_price,
            adjusted_price: request.current_price + 15.0,
            approval_required: true,
            pricing_mode: "advisory".into(),
            shapley_value: Some(shapley),
            signed_by: "pricing-oracle-test".into(),
            signature_hex: "cafebabe".into(),
        }))
    }
}

struct MockPricingOracle;

#[async_trait]
impl PricingOracleTrait for MockPricingOracle {
    async fn evaluate_utility(
        &self,
        audit_context: &PricingAuditContext,
        _metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue> {
        Ok(ShapleyValue {
            dataset_id: audit_context.dataset_id.clone(),
            transformed_asset_hash: audit_context.transformed_asset_hash.clone(),
            marginal_contribution: 0.2,
            confidence: 0.9,
            algorithm_version: "heuristic_marginal_v0".into(),
            audit_context: audit_context.clone(),
        })
    }

    async fn decide_price(
        &self,
        agreement_id: &str,
        current_price: f64,
        value: &ShapleyValue,
    ) -> Result<PriceDecision> {
        Ok(PriceDecision {
            agreement_id: agreement_id.to_string(),
            dataset_id: value.dataset_id.clone(),
            original_price: current_price,
            adjusted_price: current_price + 25.0,
            approval_required: true,
            pricing_mode: PricingMode::Advisory,
            shapley_value: value.clone(),
            signed_by: "mock-pricing".into(),
            signature_hex: "deadbeef".into(),
        })
    }
}

fn audit_context(dataset_id: &str, transformed_asset_hash: &str) -> PricingAuditContext {
    PricingAuditContext {
        dataset_id: dataset_id.into(),
        transformed_asset_hash: transformed_asset_hash.into(),
        proof_receipt_hash: None,
        model_run_id: "run-test".into(),
        metrics_window: MetricsWindow {
            started_at: chrono::DateTime::parse_from_rfc3339("2026-03-06T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            ended_at: chrono::DateTime::parse_from_rfc3339("2026-03-06T10:05:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        },
    }
}

fn metrics() -> TrainingMetrics {
    TrainingMetrics {
        loss_with_dataset: 0.3,
        loss_without_dataset: 0.5,
        accuracy_with_dataset: 0.85,
        accuracy_without_dataset: 0.75,
        model_run_id: "run-test".into(),
        metrics_window_started_at: chrono::DateTime::parse_from_rfc3339("2026-03-06T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        metrics_window_ended_at: chrono::DateTime::parse_from_rfc3339("2026-03-06T10:05:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    }
}

#[tokio::test]
async fn test_grpc_pricing_oracle_evaluate_utility_contract() {
    let (endpoint, shutdown_tx) = spawn_pricing_server().await;
    let oracle = GrpcPricingOracle::new(endpoint);

    let value = oracle
        .evaluate_utility(&audit_context("ds-1", "hash-1"), &metrics())
        .await
        .unwrap();

    assert_eq!(value.algorithm_version, "heuristic_marginal_v0");
    assert_eq!(value.transformed_asset_hash, "hash-1");
    assert_eq!(value.audit_context.model_run_id, "run-test");
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_grpc_pricing_oracle_decide_price_contract() {
    let (endpoint, shutdown_tx) = spawn_pricing_server().await;
    let oracle = GrpcPricingOracle::new(endpoint);

    let decision = oracle
        .decide_price(
            "agreement-1",
            100.0,
            &ShapleyValue {
                dataset_id: "ds-1".into(),
                transformed_asset_hash: "hash-1".into(),
                marginal_contribution: 0.1,
                confidence: 0.9,
                algorithm_version: "heuristic_marginal_v0".into(),
                audit_context: audit_context("ds-1", "hash-1"),
            },
        )
        .await
        .unwrap();

    assert_eq!(decision.adjusted_price, 115.0);
    assert!(decision.approval_required);
    assert_eq!(decision.pricing_mode, PricingMode::Advisory);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_orchestrator_returns_price_decision() {
    let orchestrator = Orchestrator::with_pricing(
        Arc::new(LiquidDataPlane::new_simulated()),
        Arc::new(MockPricingOracle),
    );

    let decision = orchestrator
        .request_price_decision(
            "agreement-1",
            100.0,
            &audit_context("dataset-1", "hash-1"),
            &TrainingMetrics {
                loss_with_dataset: 0.2,
                loss_without_dataset: 0.4,
                accuracy_with_dataset: 0.91,
                accuracy_without_dataset: 0.86,
                model_run_id: "run-1".into(),
                metrics_window_started_at: chrono::DateTime::parse_from_rfc3339(
                    "2026-03-06T11:00:00Z",
                )
                .unwrap()
                .with_timezone(&chrono::Utc),
                metrics_window_ended_at: chrono::DateTime::parse_from_rfc3339(
                    "2026-03-06T11:05:00Z",
                )
                .unwrap()
                .with_timezone(&chrono::Utc),
            },
        )
        .await
        .unwrap();

    assert_eq!(decision.agreement_id, "agreement-1");
    assert_eq!(decision.adjusted_price, 125.0);
    assert!(decision.approval_required);
    assert_eq!(decision.pricing_mode, PricingMode::Advisory);
}

async fn spawn_pricing_server() -> (String, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        Server::builder()
            .add_service(PricingOracleServer::new(TestPricingService))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
    });

    (format!("http://{}", address), shutdown_tx)
}
