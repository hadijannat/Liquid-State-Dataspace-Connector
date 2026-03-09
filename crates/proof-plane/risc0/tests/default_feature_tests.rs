use chrono::{Duration, Utc};
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement};
use lsdc_common::error::LsdcError;
use lsdc_common::liquid::{
    CsvTransformManifest, CsvTransformOp, CsvTransformOpKind, LiquidPolicyIr, RuntimeGuard,
    TransformGuard, TransportGuard, TransportProtocol,
};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_ports::ProofEngine;
use proof_plane_risc0::Risc0ProofEngine;

#[tokio::test]
async fn test_default_risc0_crate_reports_feature_gate_truthfully() {
    let engine = Risc0ProofEngine::new();
    let agreement = sample_agreement();
    let manifest = CsvTransformManifest {
        dataset_id: "dataset-1".into(),
        purpose: "analytics".into(),
        ops: vec![CsvTransformOp::RedactColumns {
            columns: vec!["email".into()],
            replacement: "[redacted]".into(),
        }],
    };

    let err = engine
        .execute_csv_transform(
            &agreement,
            b"id,email\n1,a@example.com\n",
            &manifest,
            None,
        )
        .await
        .unwrap_err();

    match err {
        LsdcError::Unsupported(message) => {
            assert!(message.contains("risc0 backend requires the `risc0` feature"));
        }
        other => panic!("expected unsupported risc0 feature-gate error, got {other:?}"),
    }
}

fn sample_agreement() -> ContractAgreement {
    ContractAgreement {
        agreement_id: PolicyId("agreement-risc0-feature-test".into()),
        asset_id: "asset-1".into(),
        provider_id: "did:web:provider".into(),
        consumer_id: "did:web:consumer".into(),
        odrl_policy: serde_json::json!({"uid": "agreement-risc0-feature-test"}),
        policy_hash: "policy-hash".into(),
        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
        liquid_policy: LiquidPolicyIr {
            transport_guard: TransportGuard {
                allow_read: true,
                allow_transfer: true,
                packet_cap: Some(100),
                byte_cap: Some(1024),
                allowed_regions: vec![],
                valid_until: Some(Utc::now() + Duration::hours(1)),
                protocol: TransportProtocol::Udp,
                session_port: Some(31_337),
            },
            transform_guard: TransformGuard {
                allow_anonymize: true,
                allowed_purposes: vec!["analytics".into()],
                required_ops: vec![CsvTransformOpKind::RedactColumns],
            },
            runtime_guard: RuntimeGuard {
                delete_after_seconds: None,
                evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                approval_required: false,
            },
        },
    }
}
