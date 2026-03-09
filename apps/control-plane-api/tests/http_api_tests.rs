use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use control_plane_api::config::ControlPlaneApiConfig;
use control_plane_api::{router, ApiState, ApiStateInit, BackendSummary};
use liquid_agent_core::loader::LiquidDataPlane;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use liquid_agent_grpc::server::{serve as serve_agent, LiquidAgentService};
use lsdc_common::crypto::{PriceDecision, PricingAuditContext, ShapleyValue};
use lsdc_common::dsp::{ContractOffer, ContractRequest, EvidenceRequirement, TransferRequest};
use lsdc_common::execution::{PricingMode, ProofBackend, TeeBackend, TransportBackend};
use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};
use lsdc_ports::{PricingOracle, TrainingMetrics};
use lsdc_service_types::{
    EvidenceVerificationRequest, FinalizeContractResponse, LineageJobAccepted, LineageJobRecord,
    LineageJobRequest, LineageJobState, SettlementDecision, TransferStartResponse,
};
use proof_plane_host::DevReceiptProofEngine;
use std::sync::Arc;
use tee_orchestrator::enclave::NitroEnclaveManager;
use tower::ServiceExt;

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
            marginal_contribution: 0.18,
            confidence: 0.91,
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
            adjusted_price: current_price + 12.5,
            approval_required: true,
            pricing_mode: PricingMode::Advisory,
            shapley_value: value.clone(),
            signed_by: "mock-pricing".into(),
            signature_hex: "deadbeef".into(),
        })
    }
}

#[tokio::test]
async fn test_contract_finalize_transfer_and_settlement_surface() {
    let app = build_test_app(start_simulated_agent().await).await;
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;
    assert!(finalized.policy_execution.is_some());

    let settlement = get_json::<SettlementDecision, _>(
        &app,
        Method::GET,
        &format!(
            "/lsdc/agreements/{}/settlement",
            finalized.agreement.agreement_id.0
        ),
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert_eq!(settlement.agreement_id, finalized.agreement.agreement_id.0);
    assert!(settlement.latest_job_id.is_none());
    assert!(!settlement.settlement_allowed);
    assert!(settlement.policy_execution.is_some());

    let transfer = get_json::<TransferStartResponse, _>(
        &app,
        Method::POST,
        "/dsp/transfers/start",
        Some(TransferRequest {
            agreement_id: finalized.agreement.agreement_id.clone(),
            data_address: "udp://127.0.0.1:31337".into(),
            protocol: finalized.agreement.liquid_policy.transport_guard.protocol,
            session_port: Some(31_337),
        }),
        StatusCode::OK,
    )
    .await;
    assert_eq!(transfer.transfer_start.session_port, 31_337);
    assert!(transfer.enforcement_handle.active);
    assert!(transfer.policy_execution.is_some());
    assert!(transfer.resolved_transport.is_some());
    assert!(transfer.enforcement_runtime.is_some());

    let completion = get_json::<lsdc_common::dsp::TransferCompletion, _>(
        &app,
        Method::POST,
        &format!(
            "/dsp/transfers/{}/complete",
            transfer.transfer_start.transfer_id
        ),
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert_eq!(completion.transfer_id, transfer.transfer_start.transfer_id);
}

#[tokio::test]
async fn test_phase3_three_party_demo_flow() {
    let tier_a = build_test_app(start_simulated_agent().await).await;
    let tier_b = build_test_app(start_simulated_agent().await).await;
    let tier_c = build_test_app(start_simulated_agent().await).await;

    let offer_ab = request_offer(&tier_a, "did:web:tier-a", "did:web:tier-b").await;
    let finalized_ab = finalize_offer(&tier_a, &offer_ab).await;
    let offer_bc = request_offer(&tier_b, "did:web:tier-b", "did:web:tier-c").await;
    let finalized_bc = finalize_offer(&tier_b, &offer_bc).await;

    let first_job = start_lineage_job(&tier_b, &finalized_ab.agreement, None).await;
    let first_record = wait_for_job(&tier_b, &first_job.job_id).await;
    let first_result = first_record
        .result
        .clone()
        .expect("expected lineage result");
    assert_eq!(first_record.state, LineageJobState::Succeeded);
    assert!(first_result.settlement_allowed);
    assert_eq!(
        first_result.actual_execution_profile.pricing_mode,
        PricingMode::Advisory
    );

    let second_job = start_lineage_job_with_input(
        &tier_c,
        &finalized_bc.agreement,
        Some(first_result.proof_bundle.provenance_receipt.clone()),
        first_result.transformed_csv_utf8.clone(),
    )
    .await;
    let second_record = wait_for_job(&tier_c, &second_job.job_id).await;
    let second_result = second_record
        .result
        .clone()
        .expect("expected downstream lineage result");
    assert_eq!(second_record.state, LineageJobState::Succeeded);
    assert!(second_result.settlement_allowed);

    let verification = get_json::<lsdc_service_types::EvidenceVerificationResult, _>(
        &tier_c,
        Method::POST,
        "/lsdc/evidence/verify-chain",
        Some(EvidenceVerificationRequest {
            receipts: vec![
                first_result.proof_bundle.provenance_receipt.clone(),
                second_result.proof_bundle.provenance_receipt.clone(),
            ],
        }),
        StatusCode::OK,
    )
    .await;
    assert!(verification.valid);
    assert_eq!(verification.checked_receipt_count, 2);

    let settlement_b = get_json::<SettlementDecision, _>(
        &tier_b,
        Method::GET,
        &format!(
            "/lsdc/agreements/{}/settlement",
            finalized_ab.agreement.agreement_id.0
        ),
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert!(settlement_b.settlement_allowed);
    assert!(settlement_b.price_decision.is_some());

    let settlement_c = get_json::<SettlementDecision, _>(
        &tier_c,
        Method::GET,
        &format!(
            "/lsdc/agreements/{}/settlement",
            finalized_bc.agreement.agreement_id.0
        ),
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert!(settlement_c.settlement_allowed);
    assert!(settlement_c.proof_bundle.is_some());
}

#[tokio::test]
async fn test_health_reports_configured_and_actual_backends() {
    let app = build_test_app(start_simulated_agent().await).await;
    let health: serde_json::Value = get_json(
        &app,
        Method::GET,
        "/health",
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;

    assert_eq!(health["status"], "ok");
    assert_eq!(health["node_name"], "test-node");
    assert_eq!(
        health["configured_backends"]["transport_backend"],
        "simulated"
    );
    assert_eq!(
        health["configured_backends"]["proof_backend"],
        "dev_receipt"
    );
    assert_eq!(health["configured_backends"]["tee_backend"], "nitro_dev");
    assert_eq!(health["actual_backends"]["transport_backend"], "simulated");
    assert_eq!(health["actual_backends"]["proof_backend"], "dev_receipt");
    assert_eq!(health["actual_backends"]["tee_backend"], "nitro_dev");
    assert_eq!(
        health["policy_truthfulness"]["clauses"][3]["clause"],
        "transport.valid_until"
    );
}

#[tokio::test]
async fn test_transfer_start_rejects_mismatched_data_address_scheme() {
    let app = build_test_app(start_simulated_agent().await).await;
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let response: serde_json::Value = get_json(
        &app,
        Method::POST,
        "/dsp/transfers/start",
        Some(TransferRequest {
            agreement_id: finalized.agreement.agreement_id.clone(),
            data_address: "tcp://127.0.0.1:31337".into(),
            protocol: lsdc_common::dsp::TransportProtocol::Udp,
            session_port: Some(31_337),
        }),
        StatusCode::BAD_REQUEST,
    )
    .await;

    assert!(response["error"]
        .as_str()
        .unwrap()
        .contains("does not match requested protocol"));
}

#[tokio::test]
async fn test_state_from_config_rejects_transport_backend_mismatch() {
    let agent_endpoint = start_simulated_agent().await;
    let config = ControlPlaneApiConfig {
        node_name: "mismatch-node".into(),
        listen_addr: "127.0.0.1:0".into(),
        database_path: ":memory:".into(),
        liquid_agent_endpoint: agent_endpoint,
        transport_backend: TransportBackend::AyaXdp,
        proof_backend: ProofBackend::DevReceipt,
        tee_backend: TeeBackend::NitroDev,
        pricing_endpoint: "http://127.0.0.1:50051".into(),
        default_interface: "lo".into(),
        nitro_live_attestation_path: None,
    };

    let err = match control_plane_api::state_from_config(&config).await {
        Ok(_) => panic!("expected transport backend mismatch to fail startup"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("configured transport backend"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_state_from_config_rejects_missing_nitro_live_material() {
    let agent_endpoint = start_simulated_agent().await;
    let config = ControlPlaneApiConfig {
        node_name: "nitro-live-node".into(),
        listen_addr: "127.0.0.1:0".into(),
        database_path: ":memory:".into(),
        liquid_agent_endpoint: agent_endpoint,
        transport_backend: TransportBackend::Simulated,
        proof_backend: ProofBackend::DevReceipt,
        tee_backend: TeeBackend::NitroLive,
        pricing_endpoint: "http://127.0.0.1:50051".into(),
        default_interface: "lo".into(),
        nitro_live_attestation_path: None,
    };

    let err = match control_plane_api::state_from_config(&config).await {
        Ok(_) => panic!("expected missing nitro_live_attestation_path to fail startup"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("nitro_live_attestation_path"),
        "unexpected error: {err}"
    );
}

async fn build_test_app(agent_endpoint: String) -> axum::Router {
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let proof_engine = Arc::new(DevReceiptProofEngine::new());
    let enclave_manager = Arc::new(NitroEnclaveManager::new_dev(proof_engine.clone()));
    let pricing_oracle = Arc::new(MockPricingOracle);
    let liquid_agent = Arc::new(LiquidAgentGrpcClient::new(agent_endpoint));

    router(ApiState::new(ApiStateInit {
        store,
        node_name: "test-node".into(),
        liquid_agent,
        proof_engine,
        enclave_manager,
        pricing_oracle,
        default_interface: "lo".into(),
        configured_backends: BackendSummary {
            transport_backend: TransportBackend::Simulated,
            proof_backend: ProofBackend::DevReceipt,
            tee_backend: TeeBackend::NitroDev,
        },
        actual_transport_backend: TransportBackend::Simulated,
    }))
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

async fn request_offer(app: &axum::Router, provider_id: &str, consumer_id: &str) -> ContractOffer {
    get_json(
        app,
        Method::POST,
        "/dsp/contracts/request",
        Some(ContractRequest {
            consumer_id: consumer_id.into(),
            provider_id: provider_id.into(),
            offer_id: uuid::Uuid::new_v4().to_string(),
            asset_id: "asset-csv".into(),
            odrl_policy: lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap(),
            policy_hash: String::new(),
            evidence_requirements: vec![
                EvidenceRequirement::ProvenanceReceipt,
                EvidenceRequirement::ProofOfForgetting,
                EvidenceRequirement::PriceApproval,
            ],
        }),
        StatusCode::OK,
    )
    .await
}

async fn finalize_offer(app: &axum::Router, offer: &ContractOffer) -> FinalizeContractResponse {
    get_json(
        app,
        Method::POST,
        "/dsp/contracts/finalize",
        Some(offer.clone()),
        StatusCode::OK,
    )
    .await
}

async fn start_lineage_job(
    app: &axum::Router,
    agreement: &lsdc_common::dsp::ContractAgreement,
    prior_receipt: Option<lsdc_common::crypto::ProvenanceReceipt>,
) -> LineageJobAccepted {
    start_lineage_job_with_input(
        app,
        agreement,
        prior_receipt,
        String::from_utf8(lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap())
            .unwrap(),
    )
    .await
}

async fn start_lineage_job_with_input(
    app: &axum::Router,
    agreement: &lsdc_common::dsp::ContractAgreement,
    prior_receipt: Option<lsdc_common::crypto::ProvenanceReceipt>,
    input_csv_utf8: String,
) -> LineageJobAccepted {
    let mut manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    if prior_receipt.is_some() {
        manifest.dataset_id = "dataset-derived".into();
        manifest.ops.push(CsvTransformOp::HashColumns {
            columns: vec!["region".into()],
            salt: "tier-c".into(),
        });
    }

    get_json(
        app,
        Method::POST,
        "/lsdc/lineage/jobs",
        Some(LineageJobRequest {
            agreement: agreement.clone(),
            iface: Some("lo".into()),
            input_csv_utf8,
            manifest,
            current_price: 99.0,
            metrics: TrainingMetrics {
                loss_with_dataset: 0.2,
                loss_without_dataset: 0.41,
                accuracy_with_dataset: 0.93,
                accuracy_without_dataset: 0.87,
                model_run_id: uuid::Uuid::new_v4().to_string(),
                metrics_window_started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                metrics_window_ended_at: chrono::Utc::now(),
            },
            prior_receipt,
        }),
        StatusCode::ACCEPTED,
    )
    .await
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
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            _ => return record,
        }
    }

    panic!("lineage job {job_id} did not complete in time");
}

#[tokio::test]
async fn test_empty_receipt_chain_is_invalid() {
    let app = build_test_app(start_simulated_agent().await).await;
    let result: lsdc_service_types::EvidenceVerificationResult = get_json(
        &app,
        Method::POST,
        "/lsdc/evidence/verify-chain",
        Some(EvidenceVerificationRequest { receipts: vec![] }),
        StatusCode::OK,
    )
    .await;
    assert!(!result.valid, "empty receipt list must not be valid");
    assert_eq!(result.checked_receipt_count, 0);
}

async fn get_json<T, B>(
    app: &axum::Router,
    method: Method,
    path: &str,
    body: Option<B>,
    expected_status: StatusCode,
) -> T
where
    T: serde::de::DeserializeOwned,
    B: serde::Serialize,
{
    let request = if let Some(body) = body {
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    };

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), expected_status);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
