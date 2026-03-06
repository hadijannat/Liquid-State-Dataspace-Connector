use chrono::Utc;
use liquid_data_plane::compiler::compile_agreement;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::odrl::ast::*;

#[test]
fn test_full_pipeline_compile() {
    let agreement = ContractAgreement {
        agreement_id: PolicyId("agreement-integration-1".into()),
        policy: PolicyAgreement {
            id: PolicyId("integration-test-1".into()),
            provider: "did:web:acme.example".into(),
            consumer: "did:web:buyer.example".into(),
            target: "urn:dataset:sensor-stream".into(),
            permissions: vec![Permission {
                action: Action::Stream,
                constraints: vec![
                    Constraint::Count { max: 120 },
                    Constraint::Count { max: 60 },
                ],
                duties: vec![],
            }],
            prohibitions: vec![],
            obligations: vec![],
            valid_from: Utc::now(),
            valid_until: Some(Utc::now() + chrono::Duration::days(90)),
        },
    };

    let compiled = compile_agreement(&agreement).unwrap();

    assert_eq!(compiled.agreement_id, "agreement-integration-1");
    assert_eq!(compiled.max_packets, 60);
    assert!(compiled.expires_at.is_some());
}
