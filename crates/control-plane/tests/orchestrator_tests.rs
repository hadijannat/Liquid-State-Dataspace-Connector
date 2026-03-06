use async_trait::async_trait;
use control_plane::negotiation::NegotiationEngine;
use control_plane::orchestrator::{BatchLineageRequest, Orchestrator};
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_common::crypto::{PriceDecision, PricingAuditContext, ShapleyValue};
use lsdc_common::dsp::{ContractRequest, EvidenceRequirement};
use lsdc_common::error::Result;
use lsdc_common::execution::PricingMode;
use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};
use lsdc_common::traits::{DataPlane, PricingOracle, ProofEngine, TrainingMetrics};
use proof_plane_host::DevReceiptProofEngine;
use std::sync::Arc;
use tee_orchestrator::enclave::NitroEnclaveManager;

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
            algorithm_version: "tmc_shapley_v0".into(),
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
    serde_json::json!({
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "uid": "policy-1",
        "validUntil": (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
        "permission": [{
            "action": ["read", "transfer", "anonymize"],
            "constraint": [
                {"leftOperand": "count", "rightOperand": 100},
                {"leftOperand": "purpose", "rightOperand": ["analytics"]},
                {"leftOperand": "spatial", "rightOperand": ["EU"]}
            ],
            "duty": [
                {"action": "delete", "constraint": [{"leftOperand": "delete-after", "rightOperand": "P7D"}]},
                {"action": "anonymize", "constraint": [{"leftOperand": "transform-required", "rightOperand": "redact_columns"}]}
            ]
        }]
    })
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
        lsdc_common::traits::EnforcementStatus::Active { .. }
    ));
}

#[tokio::test]
async fn test_two_hop_batch_lineage_flow() {
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

    let proof_engine = Arc::new(DevReceiptProofEngine::new());
    let enclave = Arc::new(NitroEnclaveManager::new(proof_engine.clone()));
    let data_plane = Arc::new(LiquidDataPlane::new_simulated());
    let orch = Orchestrator::with_full_stack(data_plane, enclave, Arc::new(MockPricingOracle));

    let first_manifest = CsvTransformManifest {
        dataset_id: "dataset-1".into(),
        purpose: "analytics".into(),
        ops: vec![CsvTransformOp::RedactColumns {
            columns: vec!["name".into()],
            replacement: "***".into(),
        }],
    };

    let first = orch
        .run_batch_csv_lineage(BatchLineageRequest {
            agreement: agreement.clone(),
            iface: "lo".into(),
            input_csv: b"id,name,region\n1,Alice,EU\n2,Bob,EU\n".to_vec(),
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

    let second = orch
        .run_batch_csv_lineage(BatchLineageRequest {
            agreement: downstream_agreement,
            iface: "lo".into(),
            input_csv: first.transformed_csv.clone(),
            manifest: CsvTransformManifest {
                dataset_id: "dataset-1-derived".into(),
                purpose: "analytics".into(),
                ops: vec![
                    CsvTransformOp::RedactColumns {
                        columns: vec!["name".into()],
                        replacement: "***".into(),
                    },
                    CsvTransformOp::HashColumns {
                        columns: vec!["region".into()],
                        salt: "tier-c".into(),
                    },
                ],
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
