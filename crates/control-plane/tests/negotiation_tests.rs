use control_plane::negotiation::NegotiationEngine;
use lsdc_common::dsp::{ContractRequest, EvidenceRequirement};
use lsdc_common::execution::{PricingMode, ProofBackend, TeeBackend, TransportBackend};

fn policy() -> serde_json::Value {
    serde_json::json!({
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "validUntil": (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
        "permission": [{
            "action": ["read", "transfer", "anonymize"],
            "constraint": [
                {"leftOperand": "count", "rightOperand": 100},
                {"leftOperand": "purpose", "rightOperand": ["analytics"]},
                {"leftOperand": "spatial", "rightOperand": ["EU"]}
            ],
            "duty": [
                {"action": "delete", "constraint": [{"leftOperand": "delete-after", "rightOperand": "P1D"}]},
                {"action": "anonymize", "constraint": [{"leftOperand": "transform-required", "rightOperand": "redact_columns"}]}
            ]
        }]
    })
}

#[tokio::test]
async fn test_finalize_profiled_derives_execution_profile() {
    let engine = NegotiationEngine::new();
    let offer = engine
        .handle_request(ContractRequest {
            consumer_id: "did:web:consumer".into(),
            provider_id: "did:web:provider".into(),
            offer_id: "offer-1".into(),
            asset_id: "asset-1".into(),
            odrl_policy: policy(),
            policy_hash: String::new(),
            evidence_requirements: vec![
                EvidenceRequirement::ProvenanceReceipt,
                EvidenceRequirement::ProofOfForgetting,
                EvidenceRequirement::PriceApproval,
            ],
        })
        .await
        .unwrap();

    let profiled = engine.finalize_profiled(offer).await.unwrap();

    assert_eq!(
        profiled.execution_profile.transport_backend,
        TransportBackend::AyaXdp
    );
    assert_eq!(
        profiled.execution_profile.proof_backend,
        ProofBackend::RiscZero
    );
    assert_eq!(
        profiled.execution_profile.tee_backend,
        TeeBackend::NitroLive
    );
    assert_eq!(
        profiled.execution_profile.pricing_mode,
        PricingMode::Advisory
    );
}

#[tokio::test]
async fn test_finalize_profiled_is_deterministic_for_same_offer_shape() {
    let engine = NegotiationEngine::new();

    let first = engine
        .finalize_profiled(
            engine
                .handle_request(ContractRequest {
                    consumer_id: "did:web:consumer".into(),
                    provider_id: "did:web:provider".into(),
                    offer_id: "offer-a".into(),
                    asset_id: "asset-1".into(),
                    odrl_policy: policy(),
                    policy_hash: String::new(),
                    evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                })
                .await
                .unwrap(),
        )
        .await
        .unwrap();

    let second = engine
        .finalize_profiled(
            engine
                .handle_request(ContractRequest {
                    consumer_id: "did:web:consumer".into(),
                    provider_id: "did:web:provider".into(),
                    offer_id: "offer-b".into(),
                    asset_id: "asset-1".into(),
                    odrl_policy: policy(),
                    policy_hash: String::new(),
                    evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                })
                .await
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(first.execution_profile, second.execution_profile);
}
