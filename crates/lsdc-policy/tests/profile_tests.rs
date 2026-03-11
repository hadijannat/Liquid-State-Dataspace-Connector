use lsdc_policy::{
    canonical_policy_json, normalize_policy, EvidenceRequirement, NormalizedConstraint,
    NormalizedLogicalOperator, PolicyClauseStatus, ProofBackend, RuntimeCapabilities, TeeBackend,
    TransportBackend, TruthfulnessMode,
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

    assert_eq!(
        canonical_policy_json(&policy_a),
        canonical_policy_json(&policy_b)
    );

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
        attested_key_release_supported: false,
        attested_teardown_supported: false,
    };

    let realizations = capabilities.clause_realizations(&normalized, &[]);
    assert_eq!(realizations.len(), 2);
    assert_eq!(realizations[0].clause_id, "deletionMode");
    assert_eq!(realizations[0].status, PolicyClauseStatus::MetadataOnly);
    assert_eq!(
        realizations[0].reason_code.as_deref(),
        Some("dev_teardown_unavailable")
    );
    assert_eq!(realizations[1].status, PolicyClauseStatus::MetadataOnly);
    assert_eq!(
        realizations[1].reason_code.as_deref(),
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
        attested_key_release_supported: false,
        attested_teardown_supported: false,
    };

    let realizations =
        capabilities.clause_realizations(&normalized, &[EvidenceRequirement::PriceApproval]);
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
    let capabilities = RuntimeCapabilities {
        transport_backend: TransportBackend::Simulated,
        proof_backend: ProofBackend::RiscZero,
        tee_backend: TeeBackend::NitroLive,
        transparency_supported: true,
        strict_mode_supported: true,
        dev_backends_allowed: false,
        attested_key_release_supported: true,
        attested_teardown_supported: true,
    };

    let realizations = capabilities.clause_realizations(&normalized, &[]);
    let deletion = realizations
        .iter()
        .find(|item| item.clause_id == "deletionMode")
        .expect("deletion clause");
    let key_release = realizations
        .iter()
        .find(|item| item.clause_id == "keyReleaseProfile")
        .expect("key release clause");

    assert_eq!(deletion.status, PolicyClauseStatus::Executable);
    assert_eq!(deletion.reason_code, None);
    assert_eq!(key_release.status, PolicyClauseStatus::Executable);
    assert_eq!(key_release.reason_code, None);
}

#[test]
fn canonical_policy_json_is_stable_across_rule_order_and_semantic_collections() {
    let policy_a = serde_json::json!({
        "lsdcTruthfulnessMode": "strict",
        "obligation": [{
            "action": "notify",
            "constraint": [{
                "leftOperand": "spatial",
                "operator": "eq",
                "rightOperand": ["DE", "FR", "DE"]
            }]
        }],
        "prohibition": [{
            "constraint": [{
                "leftOperand": "spatial",
                "operator": "eq",
                "rightOperand": ["AT", "DE", "AT"]
            }],
            "action": ["transfer", "read"]
        }],
        "permission": [{
            "duty": [{
                "action": "delete",
                "constraint": [{"leftOperand": "delete-after", "rightOperand": "P30D"}]
            }],
            "action": ["transfer", "read"],
            "constraint": [{
                "operator": "and",
                "constraint": [
                    {
                        "leftOperand": "spatial",
                        "operator": "eq",
                        "rightOperand": ["US", "EU", "US"]
                    },
                    {
                        "operator": "or",
                        "constraints": [
                            {
                                "leftOperand": "purpose",
                                "operator": "eq",
                                "rightOperand": ["fraud", "analytics", "fraud"]
                            },
                            {
                                "leftOperand": "purpose",
                                "operator": "eq",
                                "rightOperand": "research"
                            }
                        ]
                    }
                ]
            }]
        }]
    });
    let policy_b = serde_json::json!({
        "permission": [{
            "constraint": [{
                "operator": "and",
                "constraints": [
                    {
                        "operator": "or",
                        "constraint": [
                            {
                                "rightOperand": "research",
                                "operator": "eq",
                                "leftOperand": "purpose"
                            },
                            {
                                "operator": "eq",
                                "rightOperand": ["analytics", "fraud"],
                                "leftOperand": "purpose"
                            }
                        ]
                    },
                    {
                        "operator": "eq",
                        "leftOperand": "spatial",
                        "rightOperand": ["EU", "US"]
                    }
                ]
            }],
            "action": ["read", "transfer"],
            "duty": [{
                "constraint": [{"rightOperand": "P30D", "leftOperand": "delete-after"}],
                "action": "delete"
            }]
        }],
        "prohibition": [{
            "action": ["read", "transfer"],
            "constraint": [{
                "rightOperand": ["DE", "AT"],
                "operator": "eq",
                "leftOperand": "spatial"
            }]
        }],
        "obligation": [{
            "constraint": [{
                "operator": "eq",
                "rightOperand": ["FR", "DE"],
                "leftOperand": "spatial"
            }],
            "action": "notify"
        }],
        "lsdcTruthfulnessMode": "strict"
    });

    assert_eq!(
        canonical_policy_json(&policy_a),
        canonical_policy_json(&policy_b)
    );
}

#[test]
fn normalize_policy_accepts_prohibitions_obligations_and_logical_constraints() {
    let policy = serde_json::json!({
        "permission": [{
            "action": "read",
            "constraint": [{
                "operator": "and",
                "constraint": [
                    {
                        "leftOperand": "spatial",
                        "operator": "eq",
                        "rightOperand": ["US", "EU", "EU"]
                    },
                    {
                        "operator": "or",
                        "constraints": [
                            {
                                "leftOperand": "purpose",
                                "operator": "eq",
                                "rightOperand": ["fraud", "analytics", "fraud"]
                            },
                            {
                                "leftOperand": "purpose",
                                "operator": "eq",
                                "rightOperand": "research"
                            }
                        ]
                    }
                ]
            }]
        }],
        "prohibition": [{
            "action": "transfer",
            "constraint": [{
                "leftOperand": "spatial",
                "operator": "eq",
                "rightOperand": ["DE", "AT", "DE"]
            }]
        }],
        "obligation": [{
            "action": "notify",
            "constraint": [{
                "leftOperand": "spatial",
                "operator": "eq",
                "rightOperand": ["FR", "DE", "FR"]
            }]
        }]
    });

    let normalized = normalize_policy(&policy).expect("policy should normalize");
    assert_eq!(normalized.permissions.len(), 1);
    assert_eq!(normalized.prohibitions.len(), 1);
    assert_eq!(normalized.obligations.len(), 1);

    let top_level = normalized.permissions[0]
        .constraints
        .iter()
        .find_map(|constraint| match constraint {
            NormalizedConstraint::Logical {
                operator: NormalizedLogicalOperator::And,
                constraints,
            } => Some(constraints),
            _ => None,
        })
        .expect("and constraint group");

    let spatial = top_level
        .iter()
        .find_map(|constraint| match constraint {
            NormalizedConstraint::Simple {
                clause_id,
                right_operand,
                ..
            } if clause_id == "spatial" => Some(right_operand.clone()),
            _ => None,
        })
        .expect("spatial leaf");
    assert_eq!(spatial, serde_json::json!(["EU", "US"]));

    let disjunction = top_level
        .iter()
        .find_map(|constraint| match constraint {
            NormalizedConstraint::Logical {
                operator: NormalizedLogicalOperator::Or,
                constraints,
            } => Some(constraints),
            _ => None,
        })
        .expect("or constraint group");
    assert_eq!(disjunction.len(), 2);

    let prohibition_spatial = match &normalized.prohibitions[0].constraints[0] {
        NormalizedConstraint::Simple { right_operand, .. } => right_operand.clone(),
        _ => panic!("expected simple prohibition constraint"),
    };
    assert_eq!(prohibition_spatial, serde_json::json!(["AT", "DE"]));
}

#[test]
fn capability_solver_surfaces_prohibitions_and_disjunctions_truthfully() {
    let policy = serde_json::json!({
        "lsdcTruthfulnessMode": "strict",
        "permission": [{
            "action": "read",
            "constraint": [{
                "operator": "or",
                "constraint": [
                    {"leftOperand": "purpose", "operator": "eq", "rightOperand": "analytics"},
                    {"leftOperand": "purpose", "operator": "eq", "rightOperand": "research"}
                ]
            }]
        }],
        "prohibition": [{
            "action": "transfer",
            "constraint": [{
                "leftOperand": "spatial",
                "operator": "eq",
                "rightOperand": ["EU"]
            }]
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
        attested_key_release_supported: true,
        attested_teardown_supported: true,
    };

    let realizations = capabilities.clause_realizations(&normalized, &[EvidenceRequirement::PriceApproval]);

    let logical_or = realizations
        .iter()
        .find(|item| item.clause_id == "logical.or")
        .expect("logical.or clause");
    let prohibition_action = realizations
        .iter()
        .find(|item| item.clause_id == "prohibition.transfer")
        .expect("prohibition action clause");
    let prohibition_spatial = realizations
        .iter()
        .find(|item| item.clause_id == "prohibition.spatial")
        .expect("prohibition spatial clause");

    assert_eq!(logical_or.status, PolicyClauseStatus::Rejected);
    assert_eq!(
        logical_or.reason_code.as_deref(),
        Some("logical_disjunction_modeled_only")
    );
    assert_eq!(prohibition_action.status, PolicyClauseStatus::Rejected);
    assert_eq!(
        prohibition_action.reason_code.as_deref(),
        Some("prohibitions_not_enforced")
    );
    assert_eq!(prohibition_spatial.status, PolicyClauseStatus::Rejected);
    assert_eq!(
        prohibition_spatial.reason_code.as_deref(),
        Some("prohibitions_not_enforced")
    );
}
