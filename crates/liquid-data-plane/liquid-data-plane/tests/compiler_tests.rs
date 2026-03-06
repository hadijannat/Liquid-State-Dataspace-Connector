use chrono::Utc;
use lsdc_common::odrl::ast::*;
use liquid_data_plane::compiler::compile_policy;
use liquid_data_plane::maps::MapEntry;

#[test]
fn test_full_pipeline_compile() {
    let policy = PolicyAgreement {
        id: PolicyId("integration-test-1".into()),
        provider: "did:web:acme.example".into(),
        consumer: "did:web:buyer.example".into(),
        target: "urn:dataset:sensor-stream".into(),
        permissions: vec![Permission {
            action: Action::Stream,
            constraints: vec![
                Constraint::RateLimit { max_per_second: 60 },
                Constraint::Spatial {
                    allowed_regions: vec![GeoRegion::EU],
                },
            ],
            duties: vec![Duty {
                action: Action::Delete,
                constraints: vec![Constraint::Temporal {
                    not_after: Utc::now() + chrono::Duration::days(30),
                }],
            }],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + chrono::Duration::days(90)),
    };

    let compiled = compile_policy(&policy).unwrap();

    // Should have: RatePerSecond + GeoFence + Expiry (from valid_until)
    assert_eq!(compiled.entries.len(), 3);

    let has_rate = compiled.entries.iter().any(|e| matches!(e, MapEntry::RatePerSecond { .. }));
    let has_geo = compiled.entries.iter().any(|e| matches!(e, MapEntry::GeoFence { .. }));
    let has_expiry = compiled.entries.iter().any(|e| matches!(e, MapEntry::Expiry { .. }));

    assert!(has_rate, "Missing rate limit entry");
    assert!(has_geo, "Missing geo fence entry");
    assert!(has_expiry, "Missing expiry entry");
}
