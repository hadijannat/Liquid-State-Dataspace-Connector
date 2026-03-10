#![cfg(feature = "risc0")]

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use control_plane_api::{router, ApiState, ApiStateInit, BackendSummary};
use liquid_agent_core::loader::LiquidDataPlane;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use liquid_agent_grpc::server::{serve as serve_agent, LiquidAgentService};
use lsdc_common::crypto::{PriceDecision, PricingAuditContext, ShapleyValue};
use lsdc_common::dsp::{ContractRequest, EvidenceRequirement};
use lsdc_common::execution::{PricingMode, ProofBackend, TeeBackend, TransportBackend};
use lsdc_ports::{PricingOracle, TrainingMetrics};
use lsdc_service_types::{
    EvidenceVerificationRequest, EvidenceVerificationResult, FinalizeContractResponse,
    LineageJobAccepted, LineageJobRecord, LineageJobRequest, LineageJobState,
};
use proof_plane_host::Risc0ProofEngine;
use std::sync::Arc;
use std::sync::Once;
use tee_orchestrator::enclave::NitroEnclaveManager;
use tower::ServiceExt;

const TEST_API_TOKEN: &str = "test-api-token";

fn ensure_test_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
        std::env::set_var("LSDC_API_BEARER_TOKEN", TEST_API_TOKEN);
        std::env::set_var("LSDC_PROOF_SECRET", "test-proof-secret");
        std::env::set_var("LSDC_FORGETTING_SECRET", "test-forgetting-secret");
    });
}

struct MockPricingOracle;

#[async_trait]
impl PricingOracle for MockPricingOracle {
    async fn evaluate_utility(
        &self,
        audit_context: &PricingAuditContext,
        _metrics: &TrainingMetrics,
    ) -> lsdc_common::Result<ShapleyValue> {
        Ok(ShapleyValue {
            dataset_id: audit_context.dataset_id.clone(),
            transformed_asset_hash: audit_context.transformed_asset_hash.clone(),
            marginal_contribution: 0.12,
            confidence: 0.88,
            algorithm_version: "heuristic_marginal_v0".into(),
            audit_context: audit_context.clone(),
        })
    }

    async fn decide_price(
        &self,
        agreement_id: &str,
        current_price: f64,
        value: &ShapleyValue,
    ) -> lsdc_common::Result<PriceDecision> {
        Ok(PriceDecision {
            agreement_id: agreement_id.to_string(),
            dataset_id: value.dataset_id.clone(),
            original_price: current_price,
            adjusted_price: current_price + 7.0,
            approval_required: true,
            pricing_mode: PricingMode::Advisory,
            shapley_value: value.clone(),
            signed_by: "mock-pricing".into(),
            signature_hex: "beadfeed".into(),
        })
    }
}

#[tokio::test]
async fn test_single_hop_risc0_lineage_via_http_api() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let proof_engine = Arc::new(Risc0ProofEngine::new());
    let enclave_manager = Arc::new(NitroEnclaveManager::new_dev(proof_engine.clone()).unwrap());
    let app = router(ApiState::new(ApiStateInit {
        store,
        node_name: "test-risc0-node".into(),
        liquid_agent: Arc::new(LiquidAgentGrpcClient::new(agent_endpoint)),
        proof_engine,
        dev_receipt_verifier: Arc::new(proof_plane_host::DevReceiptProofEngine::new().unwrap()),
        enclave_manager,
        pricing_oracle: Arc::new(MockPricingOracle),
        default_interface: "lo".into(),
        api_bearer_token: TEST_API_TOKEN.into(),
        configured_backends: BackendSummary {
            transport_backend: TransportBackend::Simulated,
            proof_backend: lsdc_common::execution::ProofBackend::RiscZero,
            tee_backend: TeeBackend::NitroDev,
        },
        actual_transport_backend: TransportBackend::Simulated,
    }));

    let offer = post_json(
        &app,
        "/dsp/contracts/request",
        ContractRequest {
            consumer_id: "did:web:risc0-consumer".into(),
            provider_id: "did:web:risc0-provider".into(),
            offer_id: uuid::Uuid::new_v4().to_string(),
            asset_id: "asset-risc0".into(),
            odrl_policy: lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap(),
            policy_hash: String::new(),
            evidence_requirements: vec![
                EvidenceRequirement::ProvenanceReceipt,
                EvidenceRequirement::ProofOfForgetting,
                EvidenceRequirement::PriceApproval,
            ],
        },
        StatusCode::OK,
    )
    .await;
    let finalized: FinalizeContractResponse =
        post_json(&app, "/dsp/contracts/finalize", offer, StatusCode::OK).await;

    let accepted: LineageJobAccepted = post_json(
        &app,
        "/lsdc/lineage/jobs",
        LineageJobRequest {
            agreement: finalized.agreement,
            iface: Some("lo".into()),
            input_csv_utf8: String::from_utf8(
                lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            )
            .unwrap(),
            manifest: lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap(),
            current_price: 42.0,
            metrics: TrainingMetrics {
                loss_with_dataset: 0.25,
                loss_without_dataset: 0.4,
                accuracy_with_dataset: 0.9,
                accuracy_without_dataset: 0.84,
                model_run_id: uuid::Uuid::new_v4().to_string(),
                metrics_window_started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                metrics_window_ended_at: chrono::Utc::now(),
            },
            prior_receipt: None,
        },
        StatusCode::ACCEPTED,
    )
    .await;

    let record = wait_for_job(&app, &accepted.job_id).await;
    let result = record.result.expect("expected RISC Zero result");
    assert_eq!(record.state, LineageJobState::Succeeded);
    assert_eq!(
        result.actual_execution_profile.proof_backend,
        lsdc_common::execution::ProofBackend::RiscZero
    );
}

#[tokio::test]
async fn test_risc0_node_verifies_valid_dev_receipt_chain() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let proof_engine = Arc::new(Risc0ProofEngine::new());
    let enclave_manager = Arc::new(NitroEnclaveManager::new_dev(proof_engine.clone()).unwrap());
    let app = router(ApiState::new(ApiStateInit {
        store,
        node_name: "test-risc0-node".into(),
        liquid_agent: Arc::new(LiquidAgentGrpcClient::new(agent_endpoint)),
        dev_receipt_verifier: Arc::new(proof_plane_host::DevReceiptProofEngine::new().unwrap()),
        proof_engine,
        enclave_manager,
        pricing_oracle: Arc::new(MockPricingOracle),
        default_interface: "lo".into(),
        api_bearer_token: TEST_API_TOKEN.into(),
        configured_backends: BackendSummary {
            transport_backend: TransportBackend::Simulated,
            proof_backend: ProofBackend::RiscZero,
            tee_backend: TeeBackend::NitroDev,
        },
        actual_transport_backend: TransportBackend::Simulated,
    }));

    let agreement = lsdc_common::dsp::ContractAgreement {
        agreement_id: lsdc_common::odrl::ast::PolicyId("agreement-dev-chain".into()),
        asset_id: "asset-risc0".into(),
        provider_id: "did:web:risc0-provider".into(),
        consumer_id: "did:web:risc0-consumer".into(),
        odrl_policy: lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap(),
        policy_hash: "policy-hash".into(),
        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
        liquid_policy: lsdc_common::odrl::parser::lower_policy(
            &lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap(),
            &[EvidenceRequirement::ProvenanceReceipt],
        )
        .unwrap(),
    };
    let manifest = lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let dev_engine = proof_plane_host::DevReceiptProofEngine::new().unwrap();
    let first = dev_engine
        .execute_csv_transform(&agreement, &input, &manifest, None)
        .await
        .unwrap();
    let second = dev_engine
        .execute_csv_transform(
            &agreement,
            &first.output_csv,
            &manifest,
            Some(&first.receipt),
        )
        .await
        .unwrap();

    let verification: EvidenceVerificationResult = post_json(
        &app,
        "/lsdc/evidence/verify-chain",
        EvidenceVerificationRequest {
            receipts: vec![first.receipt, second.receipt],
        },
        StatusCode::OK,
    )
    .await;

    assert!(verification.valid);
    assert_eq!(
        verification.verified_backends,
        vec![ProofBackend::DevReceipt]
    );
}

async fn start_simulated_agent() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let plane = Arc::new(LiquidDataPlane::new_simulated());
    tokio::spawn(async move {
        serve_agent(
            listener,
            LiquidAgentService::new(plane, TransportBackend::Simulated),
        )
        .await
        .unwrap();
    });
    format!("http://{address}")
}

async fn wait_for_job(app: &axum::Router, job_id: &str) -> LineageJobRecord {
    for _ in 0..30 {
        let record: LineageJobRecord = get_json(
            app,
            Method::GET,
            &format!("/lsdc/lineage/jobs/{job_id}"),
            None::<serde_json::Value>,
            StatusCode::OK,
        )
        .await;
        match record.state {
            LineageJobState::Pending | LineageJobState::Running => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            _ => return record,
        }
    }

    panic!("RISC Zero job did not complete in time");
}

async fn post_json<T, B>(app: &axum::Router, path: &str, body: B, status: StatusCode) -> T
where
    T: serde::de::DeserializeOwned,
    B: serde::Serialize,
{
    get_json(app, Method::POST, path, Some(body), status).await
}

async fn get_json<T, B>(
    app: &axum::Router,
    method: Method,
    path: &str,
    body: Option<B>,
    status: StatusCode,
) -> T
where
    T: serde::de::DeserializeOwned,
    B: serde::Serialize,
{
    let request = if let Some(body) = body {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {TEST_API_TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {TEST_API_TOKEN}"))
            .body(Body::empty())
            .unwrap()
    };

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), status);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
