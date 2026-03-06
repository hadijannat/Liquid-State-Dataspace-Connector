use chrono::Utc;
use liquid_data_plane::compiler::compile_agreement;
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};
use lsdc_common::odrl::ast::PolicyId;

#[test]
fn test_full_pipeline_compile() {
    let agreement = ContractAgreement {
        agreement_id: PolicyId("agreement-integration-1".into()),
        asset_id: "asset-1".into(),
        provider_id: "did:web:acme.example".into(),
        consumer_id: "did:web:buyer.example".into(),
        odrl_policy: serde_json::json!({
            "permission": [{
                "action": ["read", "transfer"]
            }]
        }),
        policy_hash: "policy-hash".into(),
        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
        liquid_policy: LiquidPolicyIr {
            transport_guard: TransportGuard {
                allow_read: true,
                allow_transfer: true,
                packet_cap: Some(60),
                byte_cap: Some(4096),
                allowed_regions: vec!["EU".into()],
                valid_until: Some(Utc::now() + chrono::Duration::days(90)),
                protocol: TransportProtocol::Udp,
                session_port: None,
            },
            transform_guard: TransformGuard {
                allow_anonymize: true,
                allowed_purposes: vec!["analytics".into()],
                required_ops: vec![],
            },
            runtime_guard: RuntimeGuard {
                delete_after_seconds: Some(3600),
                evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                approval_required: false,
            },
        },
    };

    let compiled = compile_agreement(&agreement).unwrap();

    assert_eq!(compiled.agreement_id, "agreement-integration-1");
    assert_eq!(compiled.max_packets, Some(60));
    assert_eq!(compiled.max_bytes, Some(4096));
    assert!(compiled.expires_at.is_some());
}
