use lsdc_policy::{
    canonical_policy_json, normalize_policy, EvidenceRequirement, PolicyClauseStatus,
    ProofBackend, RuntimeCapabilities, TeeBackend, TransportBackend, TruthfulnessMode,
};

#[test]
fn canonical_policy_json_is_stable_across_key_order() {
    let policy_a = serde_json::json!({
        "permission": [{
            "constraint": [
                {"rightOperand": 300, "leftOperand": "attestationFreshnessSeconds", "operator": "lteq"},
                {"rightOperand": 4096, "operator": "lteq", "leftOperand": "maxEgressBytes"}
            ],
            "action": "read"
        }],
        "lsdcTruthfulnessMode": "strict"
    });
    let policy_b = serde_json::json!({
        "lsdcTruthfulnessMode": "strict",
        "permission": [{
            "action": "read",
            "constraint": [
                {"operator": "lteq", "leftOperand": "attestationFreshnessSeconds", "rightOperand": 300},
                {"leftOperand": "maxEgressBytes", "rightOperand": 4096, "operator": "lteq"}
            ]
        }]
    });

    assert_eq!(canonical_policy_json(&policy_a), canonical_policy_json(&policy_b));

    let normalized = normalize_policy(&policy_a).expect("policy should normalize");
    assert_eq!(normalized.truthfulness_mode, TruthfulnessMode::Strict);
    assert_eq!(normalized.permissions.len(), 1);
}

#[test]
fn capability_solver_is_permissive_when_dev_teardown_is_unavailable() {
    let policy = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [
                {"leftOperand": "deletionMode", "operator": "eq", "rightOperand": "dev_deletion"},
                {"leftOperand": "keyReleaseProfile", "operator": "eq", "rightOperand": "kms-attested"}
            ]
        }]
    });
    let normalized = normalize_policy(&policy).expect("policy should normalize");
    let capabilities = RuntimeCapabilities {
        transport_backend: TransportBackend::Simulated,
        proof_backend: ProofBackend::RiscZero,
        tee_backend: TeeBackend::NitroLive,
        transparency_supported: true,
        strict_mode_supported: true,
        dev_backends_allowed: false,
    };

    let realizations = capabilities.clause_realizations(&normalized, &[]);
    assert_eq!(realizations.len(), 2);
    assert_eq!(realizations[0].clause_id, "deletionMode");
    assert_eq!(realizations[0].status, PolicyClauseStatus::MetadataOnly);
    assert_eq!(
        realizations[0].reason_code.as_deref(),
        Some("teardown_mode_unavailable")
    );
    assert_eq!(realizations[1].status, PolicyClauseStatus::MetadataOnly);
}

#[test]
fn capability_solver_rejects_metadata_only_overlay_clauses_in_strict_mode() {
    let policy = serde_json::json!({
        "lsdcTruthfulnessMode": "strict",
        "permission": [{
            "action": "read",
            "constraint": [
                {"leftOperand": "deletionMode", "operator": "eq", "rightOperand": "kms_erasure"},
                {"leftOperand": "keyReleaseProfile", "operator": "eq", "rightOperand": "kms-attested"}
            ]
        }]
    });
    let normalized = normalize_policy(&policy).expect("policy should normalize");
    let capabilities = RuntimeCapabilities {
        transport_backend: TransportBackend::Simulated,
        proof_backend: ProofBackend::RiscZero,
        tee_backend: TeeBackend::NitroLive,
        transparency_supported: true,
        strict_mode_supported: true,
        dev_backends_allowed: false,
    };

    let realizations = capabilities.clause_realizations(
        &normalized,
        &[EvidenceRequirement::PriceApproval],
    );
    let deletion = realizations
        .iter()
        .find(|item| item.clause_id == "deletionMode")
        .expect("deletion clause");
    let key_release = realizations
        .iter()
        .find(|item| item.clause_id == "keyReleaseProfile")
        .expect("key release clause");

    assert_eq!(deletion.status, PolicyClauseStatus::Rejected);
    assert_eq!(key_release.status, PolicyClauseStatus::Rejected);
}
