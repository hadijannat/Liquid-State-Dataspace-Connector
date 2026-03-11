#![cfg(feature = "risc0")]

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use control_plane_api::{router, ApiState, ApiStateInit, BackendSummary};
use liquid_agent_core::loader::LiquidDataPlane;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use liquid_agent_grpc::server::{serve as serve_agent, LiquidAgentService};
use lsdc_common::crypto::{PriceDecision, PricingAuditContext, ShapleyValue};
use lsdc_common::dsp::{ContractOffer, ContractRequest, EvidenceRequirement};
use lsdc_common::execution::{PricingMode, ProofBackend, TeeBackend, TransportBackend};
use lsdc_common::execution_overlay::{CapabilitySupportLevel, ProofCompositionMode};
use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};
use lsdc_common::runtime_model::{
    DependencyType, EvidenceDag, EvidenceEdge, EvidenceNode, NodeStatus,
};
use lsdc_ports::{PricingOracle, ProofEngine, TrainingMetrics};
use lsdc_service_types::{
    CreateExecutionSessionRequest, CreateExecutionSessionResponse, EvidenceVerificationRequest,
    EvidenceVerificationResult, ExecutionCapabilitiesResponse, FinalizeContractResponse,
    LineageJobAccepted, LineageJobRecord, LineageJobRequest, LineageJobState,
    VerifyEvidenceDagRequest, VerifyEvidenceDagResponse,
};
use proof_plane_host::Risc0ProofEngine;
use std::future::Future;
use std::sync::Arc;
use std::sync::Once;
use tee_orchestrator::attestation::LocalAttestationVerifier;
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
        std::env::set_var("RISC0_DEV_MODE", "1");
    });
}

fn run_risc0_http_test<F>(name: &str, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    ensure_test_env();
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(future);
        })
        .unwrap()
        .join()
        .unwrap();
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

async fn build_risc0_state_and_app() -> (ApiState, control_plane_api::store::Store, axum::Router) {
    ensure_test_env();
    let agent_endpoint = start_simulated_agent().await;
    let store = control_plane_api::store::Store::new(":memory:").unwrap();
    let liquid_agent = Arc::new(LiquidAgentGrpcClient::new(agent_endpoint));
    let proof_engine = Arc::new(Risc0ProofEngine::new());
    let attestation_verifier = Arc::new(LocalAttestationVerifier::new());
    let enclave_manager = Arc::new(
        NitroEnclaveManager::new_dev(proof_engine.clone(), attestation_verifier.clone()).unwrap(),
    );

    let state = ApiState::new(ApiStateInit {
        store: store.clone(),
        node_name: "test-risc0-node".into(),
        liquid_agent: liquid_agent.clone(),
        proof_engine,
        dev_receipt_verifier: Arc::new(proof_plane_host::DevReceiptProofEngine::new().unwrap()),
        attestation_verifier,
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
    });
    let app = router(state.clone());

    (state, store, app)
}

async fn build_risc0_app() -> axum::Router {
    let (_, _, app) = build_risc0_state_and_app().await;
    app
}

fn proof_node(node_id: &str, receipt: &lsdc_common::crypto::ProvenanceReceipt) -> EvidenceNode {
    EvidenceNode {
        node_id: node_id.into(),
        kind: lsdc_common::execution_overlay::ExecutionStatementKind::ProofReceiptRegistered,
        canonical_hash: receipt.receipt_hash.clone(),
        status: NodeStatus::Verified,
        payload_json: serde_json::to_value(receipt).unwrap(),
    }
}

fn recursive_manifest() -> CsvTransformManifest {
    let mut manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    manifest.dataset_id = "dataset-derived".into();
    manifest.ops.push(CsvTransformOp::HashColumns {
        columns: vec!["region".into()],
        salt: "tier-c".into(),
    });
    manifest
}

async fn assert_risc0_capabilities_advertise_recursive_support() {
    let (state, _store, app) = build_risc0_state_and_app().await;
    let capabilities: ExecutionCapabilitiesResponse = get_json(
        &app,
        Method::GET,
        "/lsdc/v1/capabilities",
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;

    assert_eq!(
        capabilities.evidence_requirements.proof_composition_mode,
        ProofCompositionMode::Recursive
    );
    assert_eq!(
        capabilities
            .capability_descriptor
            .advertised_profiles
            .proof_profile,
        "risc0-recursive-dag-v1"
    );
    assert_eq!(
        capabilities.capability_descriptor.support["proof.risc0_recursive"],
        CapabilitySupportLevel::Implemented
    );

    let health: serde_json::Value = get_json(
        &app,
        Method::GET,
        "/health",
        None::<serde_json::Value>,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        health["execution_overlay"]["evidence_requirements"]["proof_composition_mode"],
        "recursive"
    );
    assert_eq!(
        health["execution_overlay"]["capability_descriptor"]["advertised_profiles"]
            ["proof_profile"],
        "risc0-recursive-dag-v1"
    );

    let classification =
        lsdc_common::execution::PolicyExecutionClassification::from_runtime_capability_context(
            state.runtime_capability_context(),
        );
    let recursive_rollups = classification
        .clauses
        .iter()
        .find(|clause| clause.clause == "proof.recursive_rollups")
        .expect("proof.recursive_rollups classification");
    assert_eq!(
        recursive_rollups.status,
        lsdc_common::execution::PolicyClauseStatus::Executable
    );
    assert_eq!(
        recursive_rollups.detail.as_deref(),
        Some("recursive transform chaining and receipt composition are implemented for the risc0 backend")
    );
    assert_eq!(
        health["policy_truthfulness"]["clauses"]
            .as_array()
            .expect("health truthfulness clauses")
            .iter()
            .find(|clause| clause["clause"] == "proof.recursive_rollups")
            .expect("health recursive rollups clause")["status"],
        "executable"
    );
}

#[test]
fn test_risc0_capabilities_advertise_recursive_support() {
    run_risc0_http_test(
        "risc0-http-capabilities",
        assert_risc0_capabilities_advertise_recursive_support(),
    );
}

async fn assert_single_hop_risc0_lineage_via_http_api() {
    let app = build_risc0_app().await;

    let offer: ContractOffer = post_json(
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
            execution_bindings: None,
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

#[test]
fn test_single_hop_risc0_lineage_via_http_api() {
    run_risc0_http_test(
        "risc0-http-single-hop",
        assert_single_hop_risc0_lineage_via_http_api(),
    );
}

async fn assert_risc0_node_verifies_valid_dev_receipt_chain() {
    let app = build_risc0_app().await;

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
    let manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let dev_engine = proof_plane_host::DevReceiptProofEngine::new().unwrap();
    let first = dev_engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = dev_engine
        .execute_csv_transform(
            &agreement,
            &first.output_csv,
            &manifest,
            Some(&first.receipt),
            None,
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

#[test]
fn test_risc0_node_verifies_valid_dev_receipt_chain() {
    run_risc0_http_test(
        "risc0-http-verify-dev-chain",
        assert_risc0_node_verifies_valid_dev_receipt_chain(),
    );
}

async fn assert_recursive_risc0_two_hop_lineage_via_http_api() {
    let (state, store, app) = build_risc0_state_and_app().await;

    let offer: ContractOffer = post_json(
        &app,
        "/dsp/contracts/request",
        ContractRequest {
            consumer_id: "did:web:risc0-consumer".into(),
            provider_id: "did:web:risc0-provider".into(),
            offer_id: uuid::Uuid::new_v4().to_string(),
            asset_id: "asset-risc0-recursive".into(),
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
    let created: CreateExecutionSessionResponse = post_json(
        &app,
        &"/lsdc/v1/sessions".to_string(),
        CreateExecutionSessionRequest {
            agreement_id: finalized.agreement.agreement_id.0.clone(),
            requester_ephemeral_pubkey: vec![1, 2, 3, 4],
            expected_attestation_public_key: None,
            expires_in_seconds: Some(900),
        },
        StatusCode::CREATED,
    )
    .await;
    let execution_bindings = lsdc_ports::ExecutionBindings {
        overlay_commitment: state
            .execution_overlay_commitment_for(&finalized.agreement)
            .unwrap(),
        session: created.session.clone(),
        challenge: None,
        resolved_transport: None,
        attestation_result_hash: None,
    };

    let discovery: LineageJobAccepted = post_json(
        &app,
        "/lsdc/lineage/jobs",
        LineageJobRequest {
            agreement: finalized.agreement.clone(),
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
            execution_bindings: Some(execution_bindings.clone()),
        },
        StatusCode::ACCEPTED,
    )
    .await;
    let discovery_record = wait_for_job(&app, &discovery.job_id).await;
    assert_eq!(
        discovery_record.state,
        LineageJobState::Succeeded,
        "discovery job failed: {:?}",
        discovery_record.error
    );
    let discovery_result = discovery_record
        .result
        .expect("expected discovery RISC Zero result");
    let session_id = discovery_result
        .session_id
        .clone()
        .expect("expected persisted execution session");
    let (session, challenge, _) = store
        .get_execution_session(&session_id)
        .unwrap()
        .expect("expected stored execution session");
    let first_result = discovery_result;
    let execution_bindings = lsdc_ports::ExecutionBindings {
        overlay_commitment: state
            .execution_overlay_commitment_for(&finalized.agreement)
            .unwrap(),
        session,
        challenge,
        resolved_transport: first_result.resolved_transport.clone(),
        attestation_result_hash: None,
    };

    let second: LineageJobAccepted = post_json(
        &app,
        "/lsdc/lineage/jobs",
        LineageJobRequest {
            agreement: finalized.agreement,
            iface: Some("lo".into()),
            input_csv_utf8: first_result.transformed_csv_utf8.clone(),
            manifest: recursive_manifest(),
            current_price: 48.0,
            metrics: TrainingMetrics {
                loss_with_dataset: 0.22,
                loss_without_dataset: 0.41,
                accuracy_with_dataset: 0.91,
                accuracy_without_dataset: 0.84,
                model_run_id: uuid::Uuid::new_v4().to_string(),
                metrics_window_started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                metrics_window_ended_at: chrono::Utc::now(),
            },
            prior_receipt: Some(first_result.proof_bundle.provenance_receipt.clone()),
            execution_bindings: Some(execution_bindings),
        },
        StatusCode::ACCEPTED,
    )
    .await;
    let second_record = wait_for_job(&app, &second.job_id).await;
    let second_result = second_record
        .result
        .expect("expected recursive RISC Zero result");

    assert_eq!(second_record.state, LineageJobState::Succeeded);
    assert_eq!(
        second_result
            .proof_bundle
            .provenance_receipt
            .prior_receipt_hash,
        Some(first_result.proof_bundle.provenance_receipt.receipt_hash)
    );
    assert_eq!(
        second_result.actual_execution_profile.proof_backend,
        ProofBackend::RiscZero
    );
}

#[test]
fn test_recursive_risc0_two_hop_lineage_via_http_api() {
    run_risc0_http_test(
        "risc0-http-two-hop",
        assert_recursive_risc0_two_hop_lineage_via_http_api(),
    );
}

async fn assert_verify_chain_accepts_recursive_risc0_transforms() {
    let app = build_risc0_app().await;
    let engine = Risc0ProofEngine::new();
    let agreement = lsdc_common::dsp::ContractAgreement {
        agreement_id: lsdc_common::odrl::ast::PolicyId("agreement-risc0-recursive-chain".into()),
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
    let manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(
            &agreement,
            &first.output_csv,
            &manifest,
            Some(&first.receipt),
            None,
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
    assert_eq!(verification.verified_backends, vec![ProofBackend::RiscZero]);
}

#[test]
fn test_verify_chain_accepts_recursive_risc0_transforms() {
    run_risc0_http_test(
        "risc0-http-chain-accepts-recursive",
        assert_verify_chain_accepts_recursive_risc0_transforms(),
    );
}

async fn assert_verify_evidence_dag_accepts_valid_recursive_risc0_subgraph() {
    let app = build_risc0_app().await;
    let engine = Risc0ProofEngine::new();
    let agreement = lsdc_common::dsp::ContractAgreement {
        agreement_id: lsdc_common::odrl::ast::PolicyId("agreement-risc0-dag".into()),
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
    let manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    let mut second_manifest = manifest.clone();
    second_manifest.dataset_id = "dataset-risc0-dag-sibling".into();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(&agreement, input.as_slice(), &second_manifest, None, None)
        .await
        .unwrap();
    let composed = engine
        .compose_receipts(
            &[first.receipt.clone(), second.receipt.clone()],
            lsdc_ports::CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();

    let dag = EvidenceDag::new(
        vec![
            proof_node("left", &first.receipt),
            proof_node("right", &second.receipt),
            proof_node("composed", &composed),
        ],
        vec![
            EvidenceEdge {
                from_node_id: "left".into(),
                to_node_id: "composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: "right".into(),
                to_node_id: "composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
        ],
    )
    .unwrap();

    let verification: VerifyEvidenceDagResponse = post_json(
        &app,
        "/lsdc/v1/evidence/verify",
        VerifyEvidenceDagRequest {
            dag: dag.clone(),
            receipts: Vec::new(),
        },
        StatusCode::OK,
    )
    .await;
    assert!(verification.valid);

    let mut tampered = composed.clone();
    tampered.parent_receipt_hashes.swap(0, 1);
    let tampered_dag = EvidenceDag::new(
        vec![
            proof_node("left", &first.receipt),
            proof_node("right", &second.receipt),
            proof_node("composed", &tampered),
        ],
        vec![
            EvidenceEdge {
                from_node_id: "left".into(),
                to_node_id: "composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: "right".into(),
                to_node_id: "composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
        ],
    )
    .unwrap();
    let tampered_verification: VerifyEvidenceDagResponse = post_json(
        &app,
        "/lsdc/v1/evidence/verify",
        VerifyEvidenceDagRequest {
            dag: tampered_dag,
            receipts: Vec::new(),
        },
        StatusCode::OK,
    )
    .await;
    assert!(!tampered_verification.valid);
}

#[test]
fn test_verify_evidence_dag_accepts_valid_recursive_risc0_subgraph() {
    run_risc0_http_test(
        "risc0-http-dag",
        assert_verify_evidence_dag_accepts_valid_recursive_risc0_subgraph(),
    );
}

async fn assert_verify_chain_rejects_composition_nodes() {
    let app = build_risc0_app().await;
    let engine = Risc0ProofEngine::new();
    let agreement = lsdc_common::dsp::ContractAgreement {
        agreement_id: lsdc_common::odrl::ast::PolicyId("agreement-risc0-chain".into()),
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
    let manifest: CsvTransformManifest =
        lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(&agreement, input.as_slice(), &manifest, None, None)
        .await
        .unwrap();
    let composed = engine
        .compose_receipts(
            &[first.receipt.clone(), second.receipt.clone()],
            lsdc_ports::CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();

    let verification: EvidenceVerificationResult = post_json(
        &app,
        "/lsdc/evidence/verify-chain",
        EvidenceVerificationRequest {
            receipts: vec![first.receipt, composed],
        },
        StatusCode::OK,
    )
    .await;

    assert!(!verification.valid);
}

#[test]
fn test_verify_chain_rejects_composition_nodes() {
    run_risc0_http_test(
        "risc0-http-chain-rejects-composition",
        assert_verify_chain_rejects_composition_nodes(),
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
