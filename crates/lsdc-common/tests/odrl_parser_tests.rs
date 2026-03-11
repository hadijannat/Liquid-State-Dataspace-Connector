use chrono::{Duration, Utc};
use lsdc_common::dsp::EvidenceRequirement;
use lsdc_common::liquid::CsvTransformOpKind;
use lsdc_common::odrl::parser::{lower_policy, parse_policy_json, policy_hash_hex};
use serde_json::json;

#[test]
fn test_parse_and_lower_supported_odrl_subset() {
    let policy = json!({
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "uid": "policy-1",
        "validUntil": (Utc::now() + Duration::days(30)).to_rfc3339(),
        "permission": [{
            "action": ["read", "transfer", "anonymize"],
            "constraint": [
                {"leftOperand": "count", "operator": "lteq", "rightOperand": 100},
                {"leftOperand": "spatial", "operator": "eq", "rightOperand": ["EU"]},
                {"leftOperand": "purpose", "operator": "eq", "rightOperand": ["analytics"]}
            ],
            "duty": [
                {"action": "delete", "constraint": [{"leftOperand": "delete-after", "rightOperand": "P30D"}]},
                {"action": "anonymize", "constraint": [{"leftOperand": "transform-required", "rightOperand": "redact_columns"}]}
            ]
        }]
    });

    let lowered = lower_policy(
        &policy,
        &[
            EvidenceRequirement::ProvenanceReceipt,
            EvidenceRequirement::PriceApproval,
        ],
    )
    .unwrap();

    assert!(lowered.transport_guard.allow_read);
    assert!(lowered.transport_guard.allow_transfer);
    assert_eq!(lowered.transport_guard.packet_cap, Some(100));
    assert_eq!(lowered.transport_guard.allowed_regions, vec!["EU"]);
    assert!(lowered.transform_guard.allow_anonymize);
    assert_eq!(lowered.transform_guard.allowed_purposes, vec!["analytics"]);
    assert_eq!(
        lowered.transform_guard.required_ops,
        vec![CsvTransformOpKind::RedactColumns]
    );
    assert_eq!(
        lowered.runtime_guard.delete_after_seconds,
        Some(30 * 24 * 60 * 60)
    );
    assert!(lowered.runtime_guard.approval_required);
}

#[test]
fn test_policy_hash_is_stable_for_equivalent_json_key_order() {
    let left = json!({
        "permission": [{"action": "read"}],
        "uid": "policy-a"
    });
    let right = json!({
        "uid": "policy-a",
        "permission": [{"action": "read"}]
    });

    assert_eq!(
        policy_hash_hex(&left).unwrap(),
        policy_hash_hex(&right).unwrap()
    );
}

#[test]
fn test_parse_invalid_json_returns_error() {
    let result = parse_policy_json("not valid json");
    assert!(result.is_err());
}

#[test]
fn test_lower_rejects_unsupported_action() {
    let policy = json!({
        "permission": [{
            "action": "stream"
        }]
    });

    let result = lower_policy(&policy, &[]);
    assert!(result.is_err());
}

#[test]
fn test_multi_constraint_delete_duty_uses_smallest_delete_after() {
    let policy = serde_json::json!({
        "permission": [{
            "action": "transfer",
            "duty": [{
                "action": "delete",
                "constraint": [
                    {"leftOperand": "delete-after", "rightOperand": "P7D"},
                    {"leftOperand": "delete-after", "rightOperand": "P30D"}
                ]
            }]
        }]
    });
    let lowered = lsdc_common::odrl::parser::lower_policy(
        &policy,
        &[lsdc_common::dsp::EvidenceRequirement::ProvenanceReceipt],
    )
    .unwrap();
    assert_eq!(
        lowered.runtime_guard.delete_after_seconds,
        Some(7 * 24 * 60 * 60)
    );
}

#[test]
fn test_multi_constraint_anonymize_duty_collects_required_ops() {
    let policy = serde_json::json!({
        "permission": [{
            "action": "anonymize",
            "duty": [{
                "action": "anonymize",
                "constraint": [
                    {"leftOperand": "transform-required", "rightOperand": "redact_columns"},
                    {"leftOperand": "transform-required", "rightOperand": "hash_columns"}
                ]
            }]
        }]
    });
    let lowered = lsdc_common::odrl::parser::lower_policy(
        &policy,
        &[lsdc_common::dsp::EvidenceRequirement::ProvenanceReceipt],
    )
    .unwrap();
    assert!(lowered.transform_guard.allow_anonymize);
    assert_eq!(lowered.transform_guard.required_ops.len(), 2);
    assert!(
        lowered
            .transform_guard
            .required_ops
            .contains(&lsdc_common::liquid::CsvTransformOpKind::HashColumns)
    );
    assert!(
        lowered
            .transform_guard
            .required_ops
            .contains(&lsdc_common::liquid::CsvTransformOpKind::RedactColumns)
    );
}

#[test]
fn test_lower_accepts_prohibitions_while_deriving_executable_subset() {
    let policy = json!({
        "permission": [{"action": "read"}],
        "prohibition": [{"action": "transfer"}]
    });

    let lowered = lower_policy(&policy, &[]).unwrap();
    assert!(lowered.transport_guard.allow_read);
    assert!(!lowered.transport_guard.allow_transfer);
}

#[test]
fn test_lower_collects_logical_constraint_values_and_normalized_geography() {
    let policy = json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "operator": "and",
                "constraint": [
                    {"leftOperand": "count", "operator": "lteq", "rightOperand": 25},
                    {
                        "operator": "or",
                        "constraints": [
                            {"leftOperand": "spatial", "operator": "eq", "rightOperand": ["US", "EU", "US"]},
                            {"leftOperand": "spatial", "operator": "eq", "rightOperand": ["EU", "CA"]}
                        ]
                    },
                    {"leftOperand": "purpose", "operator": "eq", "rightOperand": ["fraud", "analytics", "fraud"]}
                ]
            }]
        }]
    });

    let lowered = lower_policy(&policy, &[]).unwrap();
    assert_eq!(lowered.transport_guard.packet_cap, Some(25));
    assert_eq!(
        lowered.transport_guard.allowed_regions,
        vec!["CA".to_string(), "EU".to_string(), "US".to_string()]
    );
    assert_eq!(
        lowered.transform_guard.allowed_purposes,
        vec!["analytics".to_string(), "fraud".to_string()]
    );
}
