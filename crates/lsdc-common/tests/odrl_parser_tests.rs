use chrono::Utc;
use lsdc_common::odrl::ast::*;
use lsdc_common::odrl::parser::parse_policy_json;

#[test]
fn test_parse_simple_policy() {
    let policy = PolicyAgreement {
        id: PolicyId("test-policy-1".into()),
        provider: "did:web:provider.example".into(),
        consumer: "did:web:consumer.example".into(),
        target: "urn:dataset:sensor-data-2026".into(),
        permissions: vec![Permission {
            action: Action::Stream,
            constraints: vec![
                Constraint::RateLimit {
                    max_per_second: 1000,
                },
                Constraint::Spatial {
                    allowed_regions: vec![GeoRegion::EU],
                },
                Constraint::Temporal {
                    not_after: Utc::now() + chrono::Duration::days(30),
                },
            ],
            duties: vec![],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + chrono::Duration::days(30)),
    };

    let json = serde_json::to_string(&policy).unwrap();
    let parsed = parse_policy_json(&json).unwrap();

    assert_eq!(parsed.id, policy.id);
    assert_eq!(parsed.permissions.len(), 1);
    assert_eq!(parsed.permissions[0].constraints.len(), 3);
}

#[test]
fn test_parse_invalid_json_returns_error() {
    let result = parse_policy_json("not valid json");
    assert!(result.is_err());
}

#[test]
fn test_parse_empty_policy() {
    let policy = PolicyAgreement {
        id: PolicyId("empty-policy".into()),
        provider: "did:web:a".into(),
        consumer: "did:web:b".into(),
        target: "urn:data:empty".into(),
        permissions: vec![],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: None,
    };

    let json = serde_json::to_string(&policy).unwrap();
    let parsed = parse_policy_json(&json).unwrap();
    assert!(parsed.permissions.is_empty());
    assert!(parsed.valid_until.is_none());
}
