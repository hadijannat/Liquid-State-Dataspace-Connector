use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use control_plane_api::config::ControlPlaneApiConfig;
use control_plane_api::{router, serve, ApiState, ApiStateInit, BackendSummary};
use liquid_agent_core::loader::LiquidDataPlane;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use liquid_agent_grpc::server::{serve as serve_agent, LiquidAgentService};
use lsdc_common::crypto::{
    PriceDecision, PricingAuditContext, ProvenanceReceipt, Sha256Hash, ShapleyValue,
};
use lsdc_common::dsp::{
    ContractAgreement, ContractOffer, ContractRequest, EvidenceRequirement, TransferRequest,
    TransportProtocol,
};
use lsdc_common::execution::{PricingMode, ProofBackend, TeeBackend, TransportBackend};
use lsdc_common::liquid::{
    CsvTransformManifest, CsvTransformOp, LiquidPolicyIr, RuntimeGuard, TransformGuard,
    TransportGuard,
};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_ports::{DataPlane, PricingOracle, TrainingMetrics};
use lsdc_service_types::{
    EvidenceVerificationRequest, FinalizeContractResponse, LineageJobAccepted, LineageJobRecord,
    LineageJobRequest, LineageJobState, SettlementDecision, TransferStartResponse,
};
use proof_plane_host::DevReceiptProofEngine;
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
    ensure_test_env();
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
    ensure_test_env();
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
    assert_eq!(
        verification.verified_backends,
        vec![ProofBackend::DevReceipt]
    );

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
    ensure_test_env();
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
async fn test_non_health_routes_require_bearer_auth() {
    ensure_test_env();
    let app = build_test_app(start_simulated_agent().await).await;

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dsp/contracts/request")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&ContractRequest {
                        consumer_id: "did:web:consumer".into(),
                        provider_id: "did:web:provider".into(),
                        offer_id: uuid::Uuid::new_v4().to_string(),
                        asset_id: "asset-csv".into(),
                        odrl_policy: lsdc_common::fixtures::read_json("odrl/supported_policy.json")
                            .unwrap(),
                        policy_hash: String::new(),
                        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_transfer_start_rejects_mismatched_data_address_scheme() {
    ensure_test_env();
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
    ensure_test_env();
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
    ensure_test_env();
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

#[tokio::test]
async fn test_successful_lineage_job_revokes_enforcement() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let app = build_test_app(agent_endpoint.clone()).await;
    let liquid_agent = LiquidAgentGrpcClient::new(agent_endpoint);
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let accepted = start_lineage_job(&app, &finalized.agreement, None).await;
    let record = wait_for_job(&app, &accepted.job_id).await;
    let result = record.result.expect("expected lineage result");

    assert!(matches!(
        liquid_agent
            .status(&result.enforcement_handle)
            .await
            .unwrap(),
        lsdc_ports::EnforcementStatus::Revoked
    ));
}

#[tokio::test]
async fn test_failed_lineage_job_releases_enforcement_for_retry() {
    ensure_test_env();
    let app = build_test_app(start_simulated_agent().await).await;
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;
    let mut invalid_manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    invalid_manifest.ops.push(CsvTransformOp::RedactColumns {
        columns: vec!["missing-column".into()],
        replacement: "***".into(),
    });

    let failed_job =
        start_lineage_job_with_manifest(&app, &finalized.agreement, invalid_manifest).await;
    let failed_record = wait_for_job(&app, &failed_job.job_id).await;
    assert_eq!(failed_record.state, LineageJobState::Failed);

    let retry_job = start_lineage_job(&app, &finalized.agreement, None).await;
    let retry_record = wait_for_job(&app, &retry_job.job_id).await;
    assert_eq!(retry_record.state, LineageJobState::Succeeded);
}

async fn build_test_app(agent_endpoint: String) -> axum::Router {
    ensure_test_env();
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    router(build_test_state(agent_endpoint, store))
}

fn build_test_state(agent_endpoint: String, store: control_plane_api::store::Store) -> ApiState {
    ensure_test_env();
    let proof_engine = Arc::new(DevReceiptProofEngine::new().unwrap());
    let enclave_manager = Arc::new(NitroEnclaveManager::new_dev(proof_engine.clone()).unwrap());
    let pricing_oracle = Arc::new(MockPricingOracle);
    let liquid_agent = Arc::new(LiquidAgentGrpcClient::new(agent_endpoint));

    ApiState::new(ApiStateInit {
        store,
        node_name: "test-node".into(),
        liquid_agent,
        dev_receipt_verifier: proof_engine.clone(),
        proof_engine,
        enclave_manager,
        pricing_oracle,
        default_interface: "lo".into(),
        api_bearer_token: TEST_API_TOKEN.into(),
        configured_backends: BackendSummary {
            transport_backend: TransportBackend::Simulated,
            proof_backend: ProofBackend::DevReceipt,
            tee_backend: TeeBackend::NitroDev,
        },
        actual_transport_backend: TransportBackend::Simulated,
    })
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
    let mut manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    if prior_receipt.is_some() {
        manifest.dataset_id = "dataset-derived".into();
        manifest.ops.push(CsvTransformOp::HashColumns {
            columns: vec!["region".into()],
            salt: "tier-c".into(),
        });
    }

    start_lineage_job_with_manifest_and_input(
        app,
        agreement,
        prior_receipt,
        String::from_utf8(lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap())
            .unwrap(),
        manifest,
    )
    .await
}

async fn start_lineage_job_with_manifest(
    app: &axum::Router,
    agreement: &lsdc_common::dsp::ContractAgreement,
    manifest: CsvTransformManifest,
) -> LineageJobAccepted {
    start_lineage_job_with_manifest_and_input(
        app,
        agreement,
        None,
        String::from_utf8(lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap())
            .unwrap(),
        manifest,
    )
    .await
}

async fn start_lineage_job_with_manifest_and_input(
    app: &axum::Router,
    agreement: &lsdc_common::dsp::ContractAgreement,
    prior_receipt: Option<lsdc_common::crypto::ProvenanceReceipt>,
    input_csv_utf8: String,
    manifest: CsvTransformManifest,
) -> LineageJobAccepted {
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

    start_lineage_job_with_manifest_and_input(
        app,
        agreement,
        prior_receipt,
        input_csv_utf8,
        manifest,
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

async fn wait_for_store_job(
    store: &control_plane_api::store::Store,
    job_id: &str,
) -> LineageJobRecord {
    for _ in 0..100 {
        let record = store
            .get_job(job_id)
            .unwrap()
            .expect("expected seeded lineage job");
        match record.state {
            LineageJobState::Pending | LineageJobState::Running => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            _ => return record,
        }
    }

    panic!("lineage job {job_id} did not complete in time");
}

fn sample_lineage_job_request() -> LineageJobRequest {
    let now = chrono::Utc::now();
    LineageJobRequest {
        agreement: ContractAgreement {
            agreement_id: PolicyId("agreement-stale".into()),
            asset_id: "asset-csv".into(),
            provider_id: "did:web:provider".into(),
            consumer_id: "did:web:consumer".into(),
            odrl_policy: serde_json::json!({"permission": [{"action": "read"}]}),
            policy_hash: "policy-hash".into(),
            evidence_requirements: vec![],
            liquid_policy: LiquidPolicyIr {
                transport_guard: TransportGuard {
                    allow_read: true,
                    allow_transfer: true,
                    packet_cap: None,
                    byte_cap: None,
                    allowed_regions: vec![],
                    valid_until: None,
                    protocol: TransportProtocol::Udp,
                    session_port: Some(31_337),
                },
                transform_guard: TransformGuard {
                    allow_anonymize: true,
                    allowed_purposes: vec!["analytics".into()],
                    required_ops: vec![],
                },
                runtime_guard: RuntimeGuard {
                    delete_after_seconds: None,
                    evidence_requirements: vec![],
                    approval_required: false,
                },
            },
        },
        iface: Some("lo".into()),
        input_csv_utf8: "id,value\n1,2\n".into(),
        manifest: CsvTransformManifest {
            dataset_id: "dataset-1".into(),
            purpose: "analytics".into(),
            ops: vec![],
        },
        current_price: 42.0,
        metrics: TrainingMetrics {
            loss_with_dataset: 0.1,
            loss_without_dataset: 0.2,
            accuracy_with_dataset: 0.9,
            accuracy_without_dataset: 0.8,
            model_run_id: "model-1".into(),
            metrics_window_started_at: now,
            metrics_window_ended_at: now,
        },
        prior_receipt: None,
    }
}

#[tokio::test]
async fn test_internal_error_does_not_leak_raw_message() {
    ensure_test_env();
    let app = build_test_app(start_simulated_agent().await).await;
    let invalid_receipt = ProvenanceReceipt {
        agreement_id: "agreement-invalid".into(),
        input_hash: Sha256Hash::digest_bytes(b"input"),
        output_hash: Sha256Hash::digest_bytes(b"output"),
        policy_hash: Sha256Hash::digest_bytes(b"policy"),
        transform_manifest_hash: Sha256Hash::digest_bytes(b"manifest"),
        prior_receipt_hash: None,
        receipt_hash: Sha256Hash::digest_bytes(b"receipt"),
        proof_backend: ProofBackend::DevReceipt,
        receipt_format_version: "lsdc.dev-receipt.v1".into(),
        proof_method_id: "dev-hmac-manifest-v1".into(),
        receipt_bytes: b"not-json".to_vec(),
        timestamp: chrono::Utc::now(),
    };
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(Method::POST)
                .uri("/lsdc/evidence/verify-chain")
                .header("authorization", format!("Bearer {TEST_API_TOKEN}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&EvidenceVerificationRequest {
                        receipts: vec![invalid_receipt],
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: lsdc_service_types::EvidenceVerificationResult =
        serde_json::from_slice(&bytes).unwrap();
    assert!(!body.valid);
}

#[tokio::test]
async fn test_empty_receipt_chain_is_invalid() {
    ensure_test_env();
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

#[tokio::test]
async fn test_serve_reconciles_stale_jobs_on_startup() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let request = sample_lineage_job_request();
    let stale_at = chrono::Utc::now() - chrono::Duration::minutes(5);
    let job_id = "stale-job-startup".to_string();
    store
        .insert_job(&LineageJobRecord {
            job_id: job_id.clone(),
            agreement_id: request.agreement.agreement_id.0.clone(),
            state: LineageJobState::Pending,
            request,
            result: None,
            error: None,
            created_at: stale_at - chrono::Duration::minutes(1),
            updated_at: stale_at,
        })
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_store = store.clone();
    let server = tokio::spawn(async move {
        serve(listener, build_test_state(agent_endpoint, server_store))
            .await
            .unwrap();
    });

    let record = wait_for_store_job(&store, &job_id).await;
    assert_eq!(record.state, LineageJobState::Succeeded);
    assert!(record.result.is_some());

    server.abort();
    let _ = server.await;
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
    assert_eq!(response.status(), expected_status);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
