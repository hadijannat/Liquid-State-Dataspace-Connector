use liquid_agent::client::LiquidAgentGrpcClient;
use liquid_agent::server::{serve, LiquidAgentService};
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
use lsdc_common::execution::TransportBackend;
use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::traits::{DataPlane, EnforcementStatus};
use std::sync::Arc;

#[tokio::test]
async fn test_simulated_agent_round_trip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let plane = Arc::new(LiquidDataPlane::new_simulated());
    tokio::spawn(async move {
        serve(listener, LiquidAgentService::from_plane(plane))
            .await
            .unwrap();
    });

    let client =
        LiquidAgentGrpcClient::new(format!("http://{address}"), TransportBackend::Simulated);
    let agreement = sample_agreement("agent-round-trip", Some(31_337));
    let handle = client.enforce(&agreement, "lo").await.unwrap();
    let status = client.status(&handle).await.unwrap();
    assert!(matches!(status, EnforcementStatus::Active { .. }));

    client.revoke(&handle).await.unwrap();
    assert!(matches!(
        client.status(&handle).await.unwrap(),
        EnforcementStatus::Revoked
    ));
}

fn sample_agreement(id: &str, session_port: Option<u16>) -> ContractAgreement {
    ContractAgreement {
        agreement_id: PolicyId(id.into()),
        asset_id: "asset-loopback".into(),
        provider_id: "did:web:provider.example".into(),
        consumer_id: "did:web:consumer.example".into(),
        odrl_policy: serde_json::json!({ "permission": [{ "action": ["read", "transfer"] }] }),
        policy_hash: "policy-hash".into(),
        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
        liquid_policy: LiquidPolicyIr {
            transport_guard: TransportGuard {
                allow_read: true,
                allow_transfer: true,
                packet_cap: Some(100),
                byte_cap: None,
                allowed_regions: vec!["EU".into()],
                valid_until: Some(chrono::Utc::now() + chrono::Duration::minutes(5)),
                protocol: TransportProtocol::Udp,
                session_port,
            },
            transform_guard: TransformGuard {
                allow_anonymize: true,
                allowed_purposes: vec!["analytics".into()],
                required_ops: vec![],
            },
            runtime_guard: RuntimeGuard {
                delete_after_seconds: Some(300),
                evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                approval_required: false,
            },
        },
    }
}
