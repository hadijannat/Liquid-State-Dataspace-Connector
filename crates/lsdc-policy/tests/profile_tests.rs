use lsdc_policy::{
    canonical_normalized_policy_bytes, canonical_policy_json, normalize_policy,
    EvidenceRequirement, PolicyClauseStatus, ProofBackend, RuntimeCapabilities, TeeBackend,
    TransportBackend, TruthfulnessMode,
};

fn sample_capabilities(
    attested_key_release_supported: bool,
    attested_teardown_supported: bool,
) -> RuntimeCapabilities {
    RuntimeCapabilities {
        transport_backend: TransportBackend::Simulated,
        proof_backend: ProofBackend::RiscZero,
        tee_backend: TeeBackend::NitroLive,
        transparency_supported: true,
        strict_mode_supported: true,
        dev_backends_allowed: false,
        attested_key_release_supported,
        attested_teardown_supported,
    }
}

fn find_realization<'a>(
    realizations: &'a [lsdc_policy::ClauseRealization],
    semantic_key: &str,
) -> &'a lsdc_policy::ClauseRealization {
    realizations
        .iter()
        .find(|item| item.semantic_key == semantic_key)
        .unwrap_or_else(|| panic!("missing realization for `{semantic_key}`"))
}

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

    assert_eq!(
        canonical_policy_json(&policy_a),
        canonical_policy_json(&policy_b)
    );

    let normalized = normalize_policy(&policy_a).expect("policy should normalize");
    assert_eq!(normalized.truthfulness_mode, TruthfulnessMode::Strict);
    assert_eq!(normalized.permissions.len(), 1);
}

#[test]
fn normalized_policy_commitment_is_stable_across_rule_and_key_order() {
    let left = serde_json::json!({
        "permission": [
            {
                "action": ["transfer", "read"],
                "constraint": [
                    {"leftOperand": "purpose", "rightOperand": ["analytics", "research"], "operator": "eq"},
                    {"leftOperand": "spatial", "rightOperand": ["US", "EU"], "operator": "eq"}
                ]
            },
            {
                "action": "read",
                "constraint": [{"leftOperand": "maxEgressBytes", "rightOperand": 4096}]
            }
        ],
        "prohibition": [{"action": "stream"}]
    });
    let right = serde_json::json!({
        "prohibition": [{"action": "stream"}],
        "permission": [
            {
                "constraint": [{"rightOperand": 4096, "leftOperand": "maxEgressBytes"}],
                "action": "read"
            },
            {
                "constraint": [
                    {"operator": "eq", "rightOperand": ["EU", "US"], "leftOperand": "spatial"},
                    {"operator": "eq", "leftOperand": "purpose", "rightOperand": ["research", "analytics"]}
                ],
                "action": ["read", "transfer"]
            }
        ]
    });

    let left_normalized = normalize_policy(&left).expect("left normalize");
    let right_normalized = normalize_policy(&right).expect("right normalize");

    assert_eq!(
        canonical_normalized_policy_bytes(&left_normalized).unwrap(),
        canonical_normalized_policy_bytes(&right_normalized).unwrap()
    );
}

#[test]
fn and_sequence_order_changes_commitment_but_and_does_not() {
    let unordered_a = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "and": [
                    {"leftOperand": "maxEgressBytes", "rightOperand": 1024},
                    {"leftOperand": "attestationFreshnessSeconds", "rightOperand": 300}
                ]
            }]
        }]
    });
    let unordered_b = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "and": [
                    {"leftOperand": "attestationFreshnessSeconds", "rightOperand": 300},
                    {"leftOperand": "maxEgressBytes", "rightOperand": 1024}
                ]
            }]
        }]
    });
    let ordered_a = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "andSequence": [
                    {"leftOperand": "maxEgressBytes", "rightOperand": 1024},
                    {"leftOperand": "attestationFreshnessSeconds", "rightOperand": 300}
                ]
            }]
        }]
    });
    let ordered_b = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "andSequence": [
                    {"leftOperand": "attestationFreshnessSeconds", "rightOperand": 300},
                    {"leftOperand": "maxEgressBytes", "rightOperand": 1024}
                ]
            }]
        }]
    });

    let unordered_a = normalize_policy(&unordered_a).unwrap();
    let unordered_b = normalize_policy(&unordered_b).unwrap();
    let ordered_a = normalize_policy(&ordered_a).unwrap();
    let ordered_b = normalize_policy(&ordered_b).unwrap();

    assert_eq!(
        canonical_normalized_policy_bytes(&unordered_a).unwrap(),
        canonical_normalized_policy_bytes(&unordered_b).unwrap()
    );
    assert_ne!(
        canonical_normalized_policy_bytes(&ordered_a).unwrap(),
        canonical_normalized_policy_bytes(&ordered_b).unwrap()
    );
}

#[test]
fn normalize_policy_keeps_prohibitions_obligations_and_distinct_clause_ids() {
    let policy = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [
                {"leftOperand": "maxEgressBytes", "rightOperand": 1024},
                {"leftOperand": "maxEgressBytes", "rightOperand": 2048}
            ]
        }],
        "prohibition": [{
            "uid": "deny-stream",
            "action": "stream"
        }],
        "obligation": [{
            "action": "notify",
            "constraint": [{"leftOperand": "purpose", "rightOperand": "audit"}]
        }]
    });

    let normalized = normalize_policy(&policy).expect("policy should normalize");
    assert_eq!(normalized.prohibitions.len(), 1);
    assert_eq!(normalized.obligations.len(), 1);

    let leaves = normalized.constraint_leaves_by_operand("maxEgressBytes");
    assert_eq!(leaves.len(), 2);
    assert_ne!(leaves[0].clause_id, leaves[1].clause_id);
}

#[test]
fn unsupported_semantic_extensions_change_v2_commitment() {
    let left = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "leftOperand": "maxEgressBytes",
                "rightOperand": 1024,
                "status": "active"
            }]
        }]
    });
    let right = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "leftOperand": "maxEgressBytes",
                "rightOperand": 1024,
                "status": "inactive"
            }]
        }]
    });

    let left = normalize_policy(&left).unwrap();
    let right = normalize_policy(&right).unwrap();
    assert_ne!(
        canonical_normalized_policy_bytes(&left).unwrap(),
        canonical_normalized_policy_bytes(&right).unwrap()
    );
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
    let realizations = sample_capabilities(false, false).clause_realizations(&normalized, &[]);
    assert_eq!(realizations.len(), 2);

    let deletion = find_realization(&realizations, "deletionMode");
    assert_eq!(deletion.status, PolicyClauseStatus::MetadataOnly);
    assert_eq!(
        deletion.reason_code.as_deref(),
        Some("dev_teardown_unavailable")
    );

    let key_release = find_realization(&realizations, "keyReleaseProfile");
    assert_eq!(key_release.status, PolicyClauseStatus::MetadataOnly);
    assert_eq!(
        key_release.reason_code.as_deref(),
        Some("attested_key_release_unavailable")
    );
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
        }],
        "prohibition": [{"action": "stream"}]
    });
    let normalized = normalize_policy(&policy).expect("policy should normalize");
    let realizations = sample_capabilities(false, false)
        .clause_realizations(&normalized, &[EvidenceRequirement::PriceApproval]);

    assert_eq!(
        find_realization(&realizations, "deletionMode").status,
        PolicyClauseStatus::Rejected
    );
    assert_eq!(
        find_realization(&realizations, "keyReleaseProfile").status,
        PolicyClauseStatus::Rejected
    );
    assert_eq!(
        find_realization(&realizations, "prohibition.rule").status,
        PolicyClauseStatus::Rejected
    );
}

#[test]
fn capability_solver_executes_live_kms_operands_when_attested_support_is_available() {
    let policy = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [
                {"leftOperand": "deletionMode", "operator": "eq", "rightOperand": "kms_erasure"},
                {"leftOperand": "keyReleaseProfile", "operator": "eq", "rightOperand": "kms-attested"}
            ]
        }]
    });
    let normalized = normalize_policy(&policy).expect("policy should normalize");
    let realizations = sample_capabilities(true, true).clause_realizations(&normalized, &[]);

    let deletion = find_realization(&realizations, "deletionMode");
    assert_eq!(deletion.status, PolicyClauseStatus::Executable);
    assert_eq!(deletion.reason_code, None);

    let key_release = find_realization(&realizations, "keyReleaseProfile");
    assert_eq!(key_release.status, PolicyClauseStatus::Executable);
    assert_eq!(key_release.reason_code, None);
}
