use chrono::{Duration, Utc};
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement};
use lsdc_common::execution::{
    PolicyClauseStatus, PolicyExecutionClassification, ProofBackend, TeeBackend, TransportBackend,
};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::odrl::parser::{lower_policy, policy_hash_hex};
use serde_json::json;

fn sample_agreement() -> ContractAgreement {
    let odrl_policy = json!({
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "uid": "policy-classification",
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

    ContractAgreement {
        agreement_id: PolicyId("agreement-policy-execution".into()),
        asset_id: "asset-1".into(),
        provider_id: "did:web:provider".into(),
        consumer_id: "did:web:consumer".into(),
        policy_hash: policy_hash_hex(&odrl_policy).unwrap(),
        liquid_policy: lower_policy(
            &odrl_policy,
            &[
                EvidenceRequirement::ProvenanceReceipt,
                EvidenceRequirement::ProofOfForgetting,
                EvidenceRequirement::PriceApproval,
            ],
        )
        .unwrap(),
        odrl_policy,
        evidence_requirements: vec![
            EvidenceRequirement::ProvenanceReceipt,
            EvidenceRequirement::ProofOfForgetting,
            EvidenceRequirement::PriceApproval,
        ],
    }
}

#[test]
fn test_classification_marks_executable_metadata_only_and_rejected_truthfully() {
    let classification = PolicyExecutionClassification::classify_agreement(
        &sample_agreement(),
        TransportBackend::Simulated,
        ProofBackend::DevReceipt,
        TeeBackend::NitroDev,
    );

    assert_eq!(
        clause_status(&classification, "transport.allowed_regions"),
        Some(PolicyClauseStatus::MetadataOnly)
    );
    assert_eq!(
        clause_status(&classification, "runtime.evidence.price_approval"),
        Some(PolicyClauseStatus::MetadataOnly)
    );
    assert_eq!(
        clause_status(&classification, "transport.packet_cap"),
        Some(PolicyClauseStatus::Executable)
    );
    assert_eq!(
        clause_status(&classification, "runtime.evidence.proof_of_forgetting"),
        Some(PolicyClauseStatus::Executable)
    );
}

#[test]
fn test_classification_rejects_forgetting_without_tee_backend() {
    let classification = PolicyExecutionClassification::classify_agreement(
        &sample_agreement(),
        TransportBackend::Simulated,
        ProofBackend::DevReceipt,
        TeeBackend::None,
    );

    assert_eq!(
        clause_status(&classification, "runtime.delete_after_seconds"),
        Some(PolicyClauseStatus::Rejected)
    );
    assert_eq!(
        clause_status(&classification, "runtime.evidence.proof_of_forgetting"),
        Some(PolicyClauseStatus::Rejected)
    );
}

fn clause_status(
    classification: &PolicyExecutionClassification,
    clause: &str,
) -> Option<PolicyClauseStatus> {
    classification
        .clauses
        .iter()
        .find(|item| item.clause == clause)
        .map(|item| item.status)
}
