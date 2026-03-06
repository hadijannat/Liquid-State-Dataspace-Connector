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
    assert_eq!(lowered.runtime_guard.delete_after_seconds, Some(30 * 24 * 60 * 60));
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

    assert_eq!(policy_hash_hex(&left).unwrap(), policy_hash_hex(&right).unwrap());
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
fn test_lower_rejects_prohibitions() {
    let policy = json!({
        "permission": [{"action": "read"}],
        "prohibition": [{"action": "transfer"}]
    });

    let result = lower_policy(&policy, &[]);
    assert!(result.is_err());
}
