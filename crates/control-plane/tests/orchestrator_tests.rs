use chrono::Utc;
use control_plane::negotiation::NegotiationEngine;
use control_plane::orchestrator::Orchestrator;
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_common::dsp::ContractRequest;
use lsdc_common::odrl::ast::*;
use lsdc_common::traits::{DataPlane, EnforcementStatus};
use std::sync::Arc;

#[tokio::test]
async fn test_full_negotiation_and_enforcement() {
    let policy = PolicyAgreement {
        id: PolicyId("orch-test-1".into()),
        provider: "did:web:provider.example".into(),
        consumer: "did:web:consumer.example".into(),
        target: "urn:data:stream".into(),
        permissions: vec![Permission {
            action: Action::Stream,
            constraints: vec![Constraint::Count { max: 100 }],
            duties: vec![],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + chrono::Duration::days(7)),
    };

    let request = ContractRequest {
        consumer_id: "did:web:consumer.example".into(),
        offer_id: "offer-1".into(),
        policy,
    };

    // Negotiate
    let engine = NegotiationEngine::new();
    let offer = engine.handle_request(request).await.unwrap();
    let agreement = engine.finalize(offer).await.unwrap();

    // Enforce
    let data_plane = Arc::new(LiquidDataPlane::new());
    let orch = Orchestrator::new(data_plane.clone());
    let handle = orch.activate_agreement(&agreement, "eth0").await.unwrap();

    assert!(handle.active);
    assert_eq!(handle.interface, "eth0");

    // Verify status via the data plane directly
    let status = data_plane.status(&handle).await.unwrap();
    assert!(matches!(status, EnforcementStatus::Active { .. }));
}

#[tokio::test]
async fn test_revoke_agreement() {
    let policy = PolicyAgreement {
        id: PolicyId("revoke-test".into()),
        provider: "did:web:p".into(),
        consumer: "did:web:c".into(),
        target: "urn:data:x".into(),
        permissions: vec![Permission {
            action: Action::Read,
            constraints: vec![Constraint::Count { max: 10 }],
            duties: vec![],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: None,
    };

    let data_plane = Arc::new(LiquidDataPlane::new());
    let orch = Orchestrator::new(data_plane.clone());

    let handle = orch
        .activate_agreement(
            &lsdc_common::dsp::ContractAgreement {
                agreement_id: PolicyId::new(),
                policy,
            },
            "lo",
        )
        .await
        .unwrap();

    // Revoke
    orch.revoke_agreement(&handle).await.unwrap();

    // Verify revoked
    let status = data_plane.status(&handle).await.unwrap();
    assert!(matches!(status, EnforcementStatus::Revoked));
}
