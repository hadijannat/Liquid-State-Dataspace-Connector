use control_plane::negotiation::NegotiationEngine;
use lsdc_common::dsp::{ContractRequest, EvidenceRequirement};
use lsdc_common::execution::{
    PricingMode, RequestedProofProfile, RequestedTeeProfile, RequestedTransportProfile,
};

fn policy() -> serde_json::Value {
    lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap()
}

#[tokio::test]
async fn test_finalize_profiled_derives_requested_profile() {
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
        profiled.requested_profile.transport_profile,
        RequestedTransportProfile::GuardedTransfer
    );
    assert_eq!(
        profiled.requested_profile.proof_profile,
        RequestedProofProfile::ProvenanceReceipt
    );
    assert_eq!(
        profiled.requested_profile.tee_profile,
        RequestedTeeProfile::AttestedExecution
    );
    assert_eq!(
        profiled.requested_profile.pricing_mode,
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

    assert_eq!(first.requested_profile, second.requested_profile);
}
