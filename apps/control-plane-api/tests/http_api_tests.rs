use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use control_plane_api::config::ControlPlaneApiConfig;
use control_plane_api::{router, serve, ApiState, ApiStateInit, BackendSummary};
use liquid_agent_core::loader::LiquidDataPlane;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use liquid_agent_grpc::server::{serve as serve_agent, LiquidAgentService};
use lsdc_common::crypto::{
    sign_bytes, AttestationDocument, AttestationEvidence, AttestationMeasurements, PriceDecision,
    PricingAuditContext, ProvenanceReceipt, ReceiptKind, Sha256Hash, ShapleyValue,
};
use lsdc_common::dsp::{
    ContractAgreement, ContractOffer, ContractRequest, EvidenceRequirement, TransferRequest,
    TransportProtocol,
};
use lsdc_common::execution::{PricingMode, ProofBackend, TeeBackend, TransportBackend};
use lsdc_common::execution_overlay::{
    ExecutionSessionState, ExecutionStatement, ExecutionStatementKind,
    LSDC_EXECUTION_PROTOCOL_VERSION,
};
use lsdc_common::liquid::{
    CsvTransformManifest, CsvTransformOp, LiquidPolicyIr, RuntimeGuard, TransformGuard,
    TransportGuard,
};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::runtime_model::{EvidenceDag, EvidenceNode, NodeStatus};
use lsdc_config::KeyBrokerBackend;
use lsdc_ports::{
    DataPlane, EnforcementIdentity, PricingOracle, ResolvedTransportGuard, TrainingMetrics,
};
use lsdc_service_types::{
    CreateExecutionSessionRequest, CreateExecutionSessionResponse, EvidenceVerificationRequest,
    ExecutionCapabilitiesResponse, FinalizeContractResponse, IssueExecutionChallengeRequest,
    IssueExecutionChallengeResponse, LineageJobAccepted, LineageJobRecord, LineageJobRequest,
    LineageJobState, RegisterEvidenceStatementRequest, RegisterEvidenceStatementResponse,
    SettlementDecision, SubmitAttestationEvidenceRequest, SubmitAttestationEvidenceResponse,
    TransferStartResponse, VerifyEvidenceDagRequest, VerifyEvidenceDagResponse,
};
use proof_plane_host::DevReceiptProofEngine;
use std::sync::Arc;
use std::sync::Once;
use tee_orchestrator::attestation::LocalAttestationVerifier;
use tee_orchestrator::enclave::NitroEnclaveManager;
use tower::ServiceExt;

const TEST_API_TOKEN: &str = "test-api-token";
const TEST_ATTESTATION_SECRET: &str = "test-attestation-secret";

fn ensure_test_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
        std::env::set_var("LSDC_API_BEARER_TOKEN", TEST_API_TOKEN);
        std::env::set_var("LSDC_PROOF_SECRET", "test-proof-secret");
        std::env::set_var("LSDC_FORGETTING_SECRET", "test-forgetting-secret");
        std::env::set_var("LSDC_ATTESTATION_SECRET", TEST_ATTESTATION_SECRET);
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
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
    let execution_overlay = finalized
        .execution_overlay
        .clone()
        .expect("expected execution overlay summary");
    assert_eq!(
        execution_overlay.overlay_version,
        LSDC_EXECUTION_PROTOCOL_VERSION
    );
    assert!(execution_overlay
        .support_summary
        .contains_key("proof.dev_receipt_dag"));

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
    assert!(settlement.session_id.is_none());
    assert!(settlement.evidence_root_hash.is_none());
    assert!(settlement.transparency_receipt_hash.is_none());

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
    assert!(first_result.session_id.is_some());
    assert!(first_result.evidence_root_hash.is_some());
    assert!(first_result.transparency_receipt_hash.is_some());
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
    assert!(second_result.session_id.is_some());
    assert!(second_result.evidence_root_hash.is_some());
    assert!(second_result.transparency_receipt_hash.is_some());

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
    assert_eq!(settlement_b.session_id, first_result.session_id);
    assert_eq!(
        settlement_b.evidence_root_hash,
        first_result.evidence_root_hash
    );
    assert_eq!(
        settlement_b.transparency_receipt_hash,
        first_result.transparency_receipt_hash
    );

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
    assert_eq!(settlement_c.session_id, second_result.session_id);
    assert_eq!(
        settlement_c.evidence_root_hash,
        second_result.evidence_root_hash
    );
    assert_eq!(
        settlement_c.transparency_receipt_hash,
        second_result.transparency_receipt_hash
    );
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
        health["execution_overlay"]["capability_descriptor"]["overlay_version"],
        LSDC_EXECUTION_PROTOCOL_VERSION
    );
    assert_eq!(
        health["execution_overlay"]["strict_mode_supported"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        health["policy_truthfulness"]["clauses"][3]["clause"],
        "transport.valid_until"
    );
}

#[tokio::test]
async fn test_execution_overlay_session_and_evidence_endpoints() {
    ensure_test_env();
    let app = build_test_app(start_simulated_agent().await).await;
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;
    let finalized_overlay = finalized
        .execution_overlay
        .clone()
        .expect("expected execution overlay summary");

    let capabilities: ExecutionCapabilitiesResponse = get_json(
        &app,
        Method::GET,
        "/lsdc/v1/capabilities",
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        capabilities.capability_descriptor.overlay_version,
        LSDC_EXECUTION_PROTOCOL_VERSION
    );
    assert_eq!(
        capabilities.capability_descriptor_hash,
        capabilities
            .capability_descriptor
            .canonical_hash()
            .expect("capability descriptor hash")
    );

    let created: CreateExecutionSessionResponse = get_json(
        &app,
        Method::POST,
        "/lsdc/v1/sessions",
        Some(CreateExecutionSessionRequest {
            agreement_id: finalized.agreement.agreement_id.0.clone(),
            requester_ephemeral_pubkey: vec![1, 2, 3],
            expires_in_seconds: Some(120),
        }),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(
        created.execution_overlay.agreement_commitment_hash,
        finalized_overlay.agreement_commitment_hash
    );
    assert_eq!(created.session.state, ExecutionSessionState::Created);

    let challenge: IssueExecutionChallengeResponse = get_json(
        &app,
        Method::POST,
        &format!(
            "/lsdc/v1/sessions/{}/challenges",
            created.session.session_id
        ),
        Some(IssueExecutionChallengeRequest {
            resolved_transport: sample_resolved_transport(&finalized.agreement.agreement_id.0),
        }),
        StatusCode::OK,
    )
    .await;
    assert_eq!(challenge.session.state, ExecutionSessionState::Challenged);
    assert_eq!(
        challenge.challenge.agreement_hash,
        created.execution_overlay.agreement_commitment_hash
    );

    let duplicate_challenge_error: serde_json::Value = get_json(
        &app,
        Method::POST,
        &format!(
            "/lsdc/v1/sessions/{}/challenges",
            created.session.session_id
        ),
        Some(IssueExecutionChallengeRequest {
            resolved_transport: sample_resolved_transport(&finalized.agreement.agreement_id.0),
        }),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert!(duplicate_challenge_error["error"]
        .as_str()
        .unwrap()
        .contains("active challenge"));

    let attestation_evidence = sample_bound_attestation_evidence(&challenge.challenge);
    let registered_attestation: SubmitAttestationEvidenceResponse = get_json(
        &app,
        Method::POST,
        &format!(
            "/lsdc/v1/sessions/{}/attestation-evidence",
            created.session.session_id
        ),
        Some(SubmitAttestationEvidenceRequest {
            session_id: created.session.session_id.to_string(),
            attestation_evidence,
        }),
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        registered_attestation.session.state,
        ExecutionSessionState::AttestationVerified
    );

    let statement = ExecutionStatement {
        statement_id: "statement-http-test".into(),
        statement_hash: Sha256Hash::digest_bytes(b"statement-http-test"),
        agreement_id: finalized.agreement.agreement_id.0.clone(),
        session_id: Some(created.session.session_id),
        statement_kind: ExecutionStatementKind::SettlementRecorded,
        payload_hash: registered_attestation.attestation_result_hash.clone(),
        parent_hashes: vec![registered_attestation.attestation_result_hash.clone()],
        producer: "http-test".into(),
        profile: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
        created_at: chrono::Utc::now(),
    }
    .with_computed_hash()
    .expect("statement hash");
    let registered_statement: RegisterEvidenceStatementResponse = get_json(
        &app,
        Method::POST,
        "/lsdc/v1/evidence/statements",
        Some(RegisterEvidenceStatementRequest {
            statement: statement.clone(),
        }),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(
        registered_statement.receipt.statement_id,
        statement.statement_id
    );

    let fetched_receipt: lsdc_common::execution_overlay::TransparencyReceipt = get_json(
        &app,
        Method::GET,
        &format!(
            "/lsdc/v1/evidence/statements/{}/receipt",
            statement.statement_id
        ),
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        fetched_receipt.root_hash,
        registered_statement.receipt.root_hash
    );

    let dag = EvidenceDag::new(
        vec![EvidenceNode {
            node_id: statement.statement_id.clone(),
            kind: statement.statement_kind,
            canonical_hash: statement.canonical_hash().expect("statement hash"),
            status: NodeStatus::Anchored,
            payload_json: serde_json::to_value(&statement).unwrap(),
        }],
        vec![],
    )
    .unwrap();
    let verification: VerifyEvidenceDagResponse = get_json(
        &app,
        Method::POST,
        "/lsdc/v1/evidence/verify",
        Some(VerifyEvidenceDagRequest {
            dag,
            receipts: vec![registered_statement.receipt],
        }),
        StatusCode::OK,
    )
    .await;
    assert!(verification.valid);
    assert_eq!(verification.checked_receipt_count, 1);
    assert_eq!(verification.checked_statement_count, 1);
}

#[tokio::test]
async fn test_lineage_jobs_persist_evidence_dag_and_verify_via_v1_route() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let app = router(build_test_state(agent_endpoint, store.clone()));
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let accepted = start_lineage_job(&app, &finalized.agreement, None).await;
    let record = wait_for_job(&app, &accepted.job_id).await;
    let result = record.result.expect("expected lineage result");
    assert_eq!(record.state, LineageJobState::Succeeded);
    assert!(result.session_id.is_some());
    assert!(result.evidence_root_hash.is_some());
    assert!(result.transparency_receipt_hash.is_some());

    let dag = store
        .get_evidence_dag(&accepted.job_id)
        .unwrap()
        .expect("expected persisted evidence dag");
    let receipt = store
        .get_transparency_receipt(&format!("{}:settlement", accepted.job_id))
        .unwrap()
        .expect("expected transparency receipt");

    let verification: VerifyEvidenceDagResponse = get_json(
        &app,
        Method::POST,
        "/lsdc/v1/evidence/verify",
        Some(VerifyEvidenceDagRequest {
            dag: dag.clone(),
            receipts: vec![receipt.clone()],
        }),
        StatusCode::OK,
    )
    .await;

    assert!(verification.valid);
    assert_eq!(verification.evidence_root_hash, dag.root_hash);
    assert_eq!(
        result.transparency_receipt_hash,
        Some(receipt.canonical_hash().expect("transparency receipt hash"))
    );
}

#[tokio::test]
async fn test_submit_attestation_evidence_rejects_expired_and_mismatched_challenges() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let state = build_test_state(agent_endpoint, store.clone());
    let app = router(state.clone());
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let created = state
        .create_execution_session(CreateExecutionSessionRequest {
            agreement_id: finalized.agreement.agreement_id.0.clone(),
            requester_ephemeral_pubkey: vec![4, 5, 6],
            expires_in_seconds: Some(120),
        })
        .expect("execution session");
    let challenged = state
        .issue_execution_challenge(
            &created.session.session_id.to_string(),
            &IssueExecutionChallengeRequest {
                resolved_transport: sample_resolved_transport(&finalized.agreement.agreement_id.0),
            },
        )
        .expect("execution challenge");

    let expired_challenge = lsdc_common::execution_overlay::ExecutionSessionChallenge {
        expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
        ..challenged.challenge.clone()
    };
    store
        .update_execution_challenge(
            &created.session.session_id.to_string(),
            &challenged.session,
            &expired_challenge,
        )
        .unwrap();

    let attestation_evidence = sample_bound_attestation_evidence(&expired_challenge);
    let expired_err = state
        .submit_attestation_evidence(
            &created.session.session_id.to_string(),
            &attestation_evidence,
        )
        .unwrap_err();
    assert!(expired_err.to_string().contains("challenge has expired"));

    let mismatch_challenge = lsdc_common::execution_overlay::ExecutionSessionChallenge {
        agreement_hash: Sha256Hash::digest_bytes(b"wrong-agreement"),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        ..challenged.challenge
    };
    store
        .update_execution_challenge(
            &created.session.session_id.to_string(),
            &challenged.session,
            &mismatch_challenge,
        )
        .unwrap();

    let mismatch_attestation = sample_bound_attestation_evidence(&mismatch_challenge);
    let mismatch_err = state
        .submit_attestation_evidence(
            &created.session.session_id.to_string(),
            &mismatch_attestation,
        )
        .unwrap_err();
    assert!(mismatch_err.to_string().contains("agreement hash mismatch"));
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

    let wrong_token = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dsp/contracts/request")
                .header("authorization", "Bearer wrong-token")
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
    assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

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
        key_broker_backend: KeyBrokerBackend::None,
        aws_region: None,
        kms_key_id: None,
        nitro_trust_bundle_path: None,
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
async fn test_state_from_config_rejects_missing_nitro_live_kms_config() {
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
        key_broker_backend: KeyBrokerBackend::None,
        aws_region: None,
        kms_key_id: None,
        nitro_trust_bundle_path: None,
        nitro_live_attestation_path: None,
    };

    let err = match control_plane_api::state_from_config(&config).await {
        Ok(_) => panic!("expected missing nitro_live AWS configuration to fail startup"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("key_broker_backend"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_state_from_config_allows_nitro_live_without_fixture_path() {
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
        key_broker_backend: KeyBrokerBackend::AwsKms,
        aws_region: Some("eu-central-1".into()),
        kms_key_id: Some("arn:aws:kms:eu-central-1:123:key/test".into()),
        nitro_trust_bundle_path: None,
        nitro_live_attestation_path: None,
    };

    let state = control_plane_api::state_from_config(&config)
        .await
        .expect("nitro_live should not require a startup fixture path");

    assert_eq!(
        state.actual_backends_summary().tee_backend,
        TeeBackend::NitroLive
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
    let enclave_manager = Arc::new(
        NitroEnclaveManager::new_dev(
            proof_engine.clone(),
            Arc::new(LocalAttestationVerifier::new()),
        )
        .unwrap(),
    );
    let attestation_verifier = Arc::new(LocalAttestationVerifier::new());
    let pricing_oracle = Arc::new(MockPricingOracle);
    let liquid_agent = Arc::new(LiquidAgentGrpcClient::new(agent_endpoint));

    ApiState::new(ApiStateInit {
        store,
        node_name: "test-node".into(),
        liquid_agent,
        dev_receipt_verifier: proof_engine.clone(),
        proof_engine,
        attestation_verifier,
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

fn sample_resolved_transport(agreement_id: &str) -> ResolvedTransportGuard {
    ResolvedTransportGuard {
        selector: lsdc_common::execution::TransportSelector {
            protocol: TransportProtocol::Udp,
            port: 31_337,
        },
        enforcement: EnforcementIdentity {
            agreement_id: agreement_id.into(),
            enforcement_key: 7,
        },
        packet_cap: Some(100),
        byte_cap: Some(2048),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
    }
}

fn sample_valid_attestation_evidence(
    nonce: Option<String>,
    public_key: Option<Vec<u8>>,
    user_data_hash: Option<Sha256Hash>,
) -> AttestationEvidence {
    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    let timestamp = chrono::Utc::now();
    let binary_hash = Sha256Hash::digest_bytes(b"binary");
    let measurements = AttestationMeasurements {
        image_hash: binary_hash.clone(),
        pcrs: std::collections::BTreeMap::from([(0, binary_hash.to_hex())]),
        debug: false,
    };
    let raw_attestation_document = serde_json::to_vec(&serde_json::json!({
        "enclave_id": "http-test-enclave",
        "platform": "aws-nitro-dev",
        "binary_hash": binary_hash.to_hex(),
        "measurements": measurements.clone(),
        "nonce": nonce,
        "public_key": public_key.as_ref().map(|bytes| encode_hex(bytes)),
        "user_data_hash": user_data_hash.as_ref().map(Sha256Hash::to_hex),
        "timestamp": timestamp.to_rfc3339(),
    }))
    .unwrap();

    AttestationEvidence {
        evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
        document: AttestationDocument {
            enclave_id: "http-test-enclave".into(),
            platform: "aws-nitro-dev".into(),
            binary_hash: binary_hash.clone(),
            measurements,
            nonce,
            public_key,
            user_data_hash,
            document_hash: Sha256Hash::digest_bytes(&raw_attestation_document),
            timestamp,
            raw_attestation_document: raw_attestation_document.clone(),
            certificate_chain_pem: Vec::new(),
            signature_hex: sign_bytes(TEST_ATTESTATION_SECRET, &raw_attestation_document),
        },
    }
}

fn sample_bound_attestation_evidence(
    challenge: &lsdc_common::execution_overlay::ExecutionSessionChallenge,
) -> AttestationEvidence {
    sample_valid_attestation_evidence(
        Some(challenge.challenge_nonce_hex.clone()),
        Some(vec![9, 8, 7, 6]),
        Some(challenge.resolved_selector_hash.clone()),
    )
}

#[tokio::test]
async fn test_submit_attestation_evidence_rejects_invalid_and_replayed_submissions() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let state = build_test_state(agent_endpoint, store);
    let app = router(state.clone());
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let created = state
        .create_execution_session(CreateExecutionSessionRequest {
            agreement_id: finalized.agreement.agreement_id.0.clone(),
            requester_ephemeral_pubkey: vec![1, 2, 3],
            expires_in_seconds: Some(120),
        })
        .expect("execution session");
    let challenged = state
        .issue_execution_challenge(
            &created.session.session_id.to_string(),
            &IssueExecutionChallengeRequest {
                resolved_transport: sample_resolved_transport(&finalized.agreement.agreement_id.0),
            },
        )
        .expect("execution challenge");

    let mut invalid_evidence = sample_bound_attestation_evidence(&challenged.challenge);
    invalid_evidence.document.signature_hex = "deadbeef".into();
    let invalid_err = state
        .submit_attestation_evidence(&created.session.session_id.to_string(), &invalid_evidence)
        .unwrap_err();
    assert!(invalid_err
        .to_string()
        .contains("attestation evidence appraisal rejected"));

    let registered = state
        .submit_attestation_evidence(
            &created.session.session_id.to_string(),
            &sample_bound_attestation_evidence(&challenged.challenge),
        )
        .expect("valid attestation submission");
    assert_eq!(
        registered.session.state,
        ExecutionSessionState::AttestationVerified
    );

    let replay_err = state
        .submit_attestation_evidence(
            &created.session.session_id.to_string(),
            &sample_bound_attestation_evidence(&challenged.challenge),
        )
        .unwrap_err();
    assert!(replay_err.to_string().contains("already been consumed"));
}

#[tokio::test]
async fn test_submit_attestation_evidence_preserves_recipient_key_without_requester_match() {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let state = build_test_state(agent_endpoint, store);
    let app = router(state.clone());
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let created = state
        .create_execution_session(CreateExecutionSessionRequest {
            agreement_id: finalized.agreement.agreement_id.0.clone(),
            requester_ephemeral_pubkey: vec![1, 2, 3],
            expires_in_seconds: Some(120),
        })
        .expect("execution session");
    let challenged = state
        .issue_execution_challenge(
            &created.session.session_id.to_string(),
            &IssueExecutionChallengeRequest {
                resolved_transport: sample_resolved_transport(&finalized.agreement.agreement_id.0),
            },
        )
        .expect("execution challenge");

    let response = state
        .submit_attestation_evidence(
            &created.session.session_id.to_string(),
            &sample_bound_attestation_evidence(&challenged.challenge),
        )
        .expect("recipient key should not be compared to requester key");

    assert_eq!(
        response.attestation_result.public_key,
        Some(vec![9, 8, 7, 6])
    );
    assert_eq!(
        response.session.state,
        ExecutionSessionState::AttestationVerified
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
            execution_bindings: None,
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
        execution_bindings: None,
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
        agreement_commitment_hash: None,
        session_id: None,
        challenge_nonce_hash: None,
        selector_hash: None,
        attestation_result_hash: None,
        capability_commitment_hash: None,
        transparency_statement_hash: None,
        parent_receipt_hashes: vec![],
        recursion_depth: 0,
        receipt_kind: ReceiptKind::Transform,
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
async fn test_receipt_chain_with_broken_prior_hash_is_invalid() {
    ensure_test_env();
    let app = build_test_app(start_simulated_agent().await).await;
    let offer = request_offer(&app, "did:web:provider", "did:web:consumer").await;
    let finalized = finalize_offer(&app, &offer).await;

    let first_job = start_lineage_job(&app, &finalized.agreement, None).await;
    let first_record = wait_for_job(&app, &first_job.job_id).await;
    let first_result = first_record.result.expect("expected first lineage result");

    let second_job = start_lineage_job_with_input(
        &app,
        &finalized.agreement,
        Some(first_result.proof_bundle.provenance_receipt.clone()),
        first_result.transformed_csv_utf8.clone(),
    )
    .await;
    let second_record = wait_for_job(&app, &second_job.job_id).await;
    let second_result = second_record
        .result
        .expect("expected second lineage result");

    let mut broken_receipt = second_result.proof_bundle.provenance_receipt;
    broken_receipt.prior_receipt_hash = Some(Sha256Hash::digest_bytes(b"wrong-prior"));

    let verification: lsdc_service_types::EvidenceVerificationResult = get_json(
        &app,
        Method::POST,
        "/lsdc/evidence/verify-chain",
        Some(EvidenceVerificationRequest {
            receipts: vec![first_result.proof_bundle.provenance_receipt, broken_receipt],
        }),
        StatusCode::OK,
    )
    .await;

    assert!(!verification.valid);
    assert_eq!(verification.checked_receipt_count, 2);
    assert_eq!(
        verification.verified_backends,
        vec![ProofBackend::DevReceipt]
    );
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
