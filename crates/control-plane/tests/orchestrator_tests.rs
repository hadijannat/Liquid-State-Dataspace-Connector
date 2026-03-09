use async_trait::async_trait;
use control_plane::negotiation::NegotiationEngine;
use control_plane::orchestrator::{BatchLineageRequest, Orchestrator};
use liquid_agent_core::loader::LiquidDataPlane;
use lsdc_common::crypto::{PriceDecision, PricingAuditContext, ShapleyValue};
use lsdc_common::dsp::{ContractRequest, EvidenceRequirement};
use lsdc_common::error::Result;
use lsdc_common::execution::PricingMode;
use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};
use lsdc_ports::{DataPlane, PricingOracle, ProofEngine, TrainingMetrics};
use proof_plane_host::DevReceiptProofEngine;
use std::sync::Arc;
use std::sync::Once;
use tee_orchestrator::enclave::NitroEnclaveManager;

fn ensure_test_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
    });
}

struct MockPricingOracle;

#[async_trait]
impl PricingOracle for MockPricingOracle {
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
            signed_by: "mock-pricing-oracle".into(),
            signature_hex: "deadbeef".into(),
        })
    }
}

fn supported_policy() -> serde_json::Value {
    lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap()
}

fn base_manifest() -> CsvTransformManifest {
    lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap()
}

#[tokio::test]
async fn test_full_negotiation_and_enforcement() {
    let request = ContractRequest {
        consumer_id: "did:web:consumer.example".into(),
        provider_id: "did:web:provider.example".into(),
        offer_id: "offer-1".into(),
        asset_id: "asset-1".into(),
        odrl_policy: supported_policy(),
        policy_hash: String::new(),
        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
    };

    let engine = NegotiationEngine::new();
    let offer = engine.handle_request(request).await.unwrap();
    let agreement = engine.finalize(offer).await.unwrap();

    let data_plane = Arc::new(LiquidDataPlane::new_simulated());
    let orch = Orchestrator::new(data_plane.clone());
    let handle = orch.activate_agreement(&agreement, "lo").await.unwrap();

    assert!(handle.active);
    let status = data_plane.status(&handle).await.unwrap();
    assert!(matches!(
        status,
        lsdc_ports::EnforcementStatus::Active { .. }
    ));
}

#[tokio::test]
async fn test_two_hop_batch_lineage_flow() {
    ensure_test_env();
    let negotiation = NegotiationEngine::new();
    let offer = negotiation
        .handle_request(ContractRequest {
            consumer_id: "did:web:tier-b".into(),
            provider_id: "did:web:tier-a".into(),
            offer_id: "offer-lineage".into(),
            asset_id: "asset-lineage".into(),
            odrl_policy: supported_policy(),
            policy_hash: String::new(),
            evidence_requirements: vec![
                EvidenceRequirement::ProvenanceReceipt,
                EvidenceRequirement::ProofOfForgetting,
                EvidenceRequirement::PriceApproval,
            ],
        })
        .await
        .unwrap();
    let agreement = negotiation.finalize(offer).await.unwrap();
    let downstream_agreement = negotiation
        .finalize(
            negotiation
                .handle_request(ContractRequest {
                    consumer_id: "did:web:tier-c".into(),
                    provider_id: "did:web:tier-b".into(),
                    offer_id: "offer-lineage-downstream".into(),
                    asset_id: "asset-lineage-derived".into(),
                    odrl_policy: supported_policy(),
                    policy_hash: String::new(),
                    evidence_requirements: vec![
                        EvidenceRequirement::ProvenanceReceipt,
                        EvidenceRequirement::ProofOfForgetting,
                        EvidenceRequirement::PriceApproval,
                    ],
                })
                .await
                .unwrap(),
        )
        .await
        .unwrap();

    let proof_engine = Arc::new(DevReceiptProofEngine::new().unwrap());
    let enclave = Arc::new(NitroEnclaveManager::new_dev(proof_engine.clone()).unwrap());
    let data_plane = Arc::new(LiquidDataPlane::new_simulated());
    let orch = Orchestrator::with_full_stack(data_plane, enclave, Arc::new(MockPricingOracle));

    let first_manifest = base_manifest();
    let input_csv = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let expected_first_output =
        lsdc_common::fixtures::read_bytes("proof/expected_redacted.csv").unwrap();

    let first = orch
        .run_batch_csv_lineage(BatchLineageRequest {
            agreement: agreement.clone(),
            iface: "lo".into(),
            input_csv: input_csv.clone(),
            manifest: first_manifest,
            current_price: 100.0,
            metrics: TrainingMetrics {
                loss_with_dataset: 0.2,
                loss_without_dataset: 0.4,
                accuracy_with_dataset: 0.91,
                accuracy_without_dataset: 0.86,
                model_run_id: "tier-b-run".into(),
                metrics_window_started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                metrics_window_ended_at: chrono::Utc::now(),
            },
            prior_receipt: None,
        })
        .await
        .unwrap();

    assert!(first.settlement_allowed);
    assert!(first.sanction_proposal.is_none());
    assert_eq!(first.price_decision.pricing_mode, PricingMode::Advisory);
    assert_eq!(first.transformed_csv, expected_first_output);

    let second = orch
        .run_batch_csv_lineage(BatchLineageRequest {
            agreement: downstream_agreement,
            iface: "lo".into(),
            input_csv: first.transformed_csv.clone(),
            manifest: {
                let mut manifest = base_manifest();
                manifest.dataset_id = "dataset-1-derived".into();
                manifest.ops.push(CsvTransformOp::HashColumns {
                    columns: vec!["region".into()],
                    salt: "tier-c".into(),
                });
                manifest
            },
            current_price: 125.0,
            metrics: TrainingMetrics {
                loss_with_dataset: 0.18,
                loss_without_dataset: 0.4,
                accuracy_with_dataset: 0.93,
                accuracy_without_dataset: 0.86,
                model_run_id: "tier-c-run".into(),
                metrics_window_started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                metrics_window_ended_at: chrono::Utc::now(),
            },
            prior_receipt: Some(first.proof_bundle.provenance_receipt.clone()),
        })
        .await
        .unwrap();

    assert!(second.settlement_allowed);
    assert!(second.sanction_proposal.is_none());
    assert!(proof_engine
        .verify_chain(&[
            first.proof_bundle.provenance_receipt,
            second.proof_bundle.provenance_receipt
        ])
        .await
        .unwrap());
}
