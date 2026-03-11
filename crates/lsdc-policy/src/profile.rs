use crate::error::{LsdcError, Result};
use crate::execution::{PolicyClauseStatus, ProofBackend, TeeBackend, TransportBackend};
use crate::liquid::EvidenceRequirement;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum TruthfulnessMode {
    #[default]
    Permissive,
    Strict,
}

pub const LSDC_PROFILE_OPERANDS: &[&str] = &[
    "teeImageSha384",
    "attestationFreshnessSeconds",
    "proofKind",
    "keyReleaseProfile",
    "maxEgressBytes",
    "deletionMode",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedLogicalOperator {
    And,
    Or,
    Xone,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NormalizedConstraint {
    Simple {
        clause_id: String,
        operator: String,
        right_operand: Value,
    },
    Logical {
        operator: NormalizedLogicalOperator,
        constraints: Vec<NormalizedConstraint>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedDuty {
    pub action: String,
    pub constraints: Vec<NormalizedConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedPermission {
    pub actions: Vec<String>,
    pub constraints: Vec<NormalizedConstraint>,
    pub duties: Vec<NormalizedDuty>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedProhibition {
    pub actions: Vec<String>,
    pub constraints: Vec<NormalizedConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedPolicy {
    pub permissions: Vec<NormalizedPermission>,
    pub prohibitions: Vec<NormalizedProhibition>,
    pub obligations: Vec<NormalizedDuty>,
    pub truthfulness_mode: TruthfulnessMode,
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClauseRealization {
    pub clause_id: String,
    pub status: PolicyClauseStatus,
    pub required_primitives: Vec<String>,
    pub required_evidence: Vec<String>,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    pub transport_backend: TransportBackend,
    pub proof_backend: ProofBackend,
    pub tee_backend: TeeBackend,
    pub transparency_supported: bool,
    pub strict_mode_supported: bool,
    pub dev_backends_allowed: bool,
    pub attested_key_release_supported: bool,
    pub attested_teardown_supported: bool,
}

impl RuntimeCapabilities {
    pub fn clause_realizations(
        &self,
        normalized_policy: &NormalizedPolicy,
        evidence_requirements: &[EvidenceRequirement],
    ) -> Vec<ClauseRealization> {
        let mut clauses = Vec::new();

        for permission in &normalized_policy.permissions {
            self.collect_constraint_realizations(
                &permission.constraints,
                normalized_policy.truthfulness_mode,
                false,
                &mut clauses,
            );
            for duty in &permission.duties {
                self.collect_duty_realizations(duty, normalized_policy.truthfulness_mode, &mut clauses);
            }
        }

        for prohibition in &normalized_policy.prohibitions {
            for action in &prohibition.actions {
                clauses.push(apply_truthfulness_mode(
                    normalized_policy.truthfulness_mode,
                    ClauseRealization {
                        clause_id: format!("prohibition.{action}"),
                        status: PolicyClauseStatus::MetadataOnly,
                        required_primitives: Vec::new(),
                        required_evidence: Vec::new(),
                        reason_code: Some("prohibitions_not_enforced".into()),
                    },
                ));
            }
            self.collect_constraint_realizations(
                &prohibition.constraints,
                normalized_policy.truthfulness_mode,
                true,
                &mut clauses,
            );
        }

        for duty in &normalized_policy.obligations {
            self.collect_duty_realizations(duty, normalized_policy.truthfulness_mode, &mut clauses);
        }

        if evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::PriceApproval)
        {
            clauses.push(apply_truthfulness_mode(
                normalized_policy.truthfulness_mode,
                ClauseRealization {
                    clause_id: "pricing.autonomous_mutation".into(),
                    status: PolicyClauseStatus::MetadataOnly,
                    required_primitives: vec!["pricing.oracle".into()],
                    required_evidence: vec!["price_decision".into()],
                    reason_code: Some("pricing_advisory_only".into()),
                },
            ));
        }

        clauses
    }

    fn collect_constraint_realizations(
        &self,
        constraints: &[NormalizedConstraint],
        truthfulness_mode: TruthfulnessMode,
        prohibition_context: bool,
        clauses: &mut Vec<ClauseRealization>,
    ) {
        for constraint in constraints {
            match constraint {
                NormalizedConstraint::Simple {
                    clause_id,
                    right_operand,
                    ..
                } => {
                    let realization = if prohibition_context {
                        ClauseRealization {
                            clause_id: format!("prohibition.{clause_id}"),
                            status: PolicyClauseStatus::MetadataOnly,
                            required_primitives: Vec::new(),
                            required_evidence: Vec::new(),
                            reason_code: Some("prohibitions_not_enforced".into()),
                        }
                    } else {
                        self.leaf_clause_realization(clause_id, right_operand)
                    };
                    clauses.push(apply_truthfulness_mode(truthfulness_mode, realization));
                }
                NormalizedConstraint::Logical {
                    operator,
                    constraints: children,
                } => {
                    self.collect_constraint_realizations(
                        children,
                        truthfulness_mode,
                        prohibition_context,
                        clauses,
                    );
                    clauses.push(apply_truthfulness_mode(
                        truthfulness_mode,
                        self.logical_clause_realization(*operator, prohibition_context),
                    ));
                }
            }
        }
    }

    fn collect_duty_realizations(
        &self,
        duty: &NormalizedDuty,
        truthfulness_mode: TruthfulnessMode,
        clauses: &mut Vec<ClauseRealization>,
    ) {
        if !matches!(duty.action.as_str(), "delete" | "anonymize") {
            clauses.push(apply_truthfulness_mode(
                truthfulness_mode,
                ClauseRealization {
                    clause_id: format!("duty.{}", duty.action),
                    status: PolicyClauseStatus::MetadataOnly,
                    required_primitives: Vec::new(),
                    required_evidence: Vec::new(),
                    reason_code: Some("duty_action_modeled_only".into()),
                },
            ));
        }

        for constraint in &duty.constraints {
            match constraint {
                NormalizedConstraint::Simple {
                    clause_id,
                    right_operand,
                    ..
                } => {
                    clauses.push(apply_truthfulness_mode(
                        truthfulness_mode,
                        self.duty_clause_realization(&duty.action, clause_id, right_operand),
                    ));
                }
                NormalizedConstraint::Logical {
                    operator,
                    constraints: children,
                } => {
                    self.collect_duty_realizations(
                        &NormalizedDuty {
                            action: duty.action.clone(),
                            constraints: children.clone(),
                        },
                        truthfulness_mode,
                        clauses,
                    );
                    clauses.push(apply_truthfulness_mode(
                        truthfulness_mode,
                        self.logical_clause_realization(*operator, false),
                    ));
                }
            }
        }
    }

    fn leaf_clause_realization(
        &self,
        clause_id: &str,
        right_operand: &Value,
    ) -> ClauseRealization {
        match clause_id {
            "count" => ClauseRealization {
                clause_id: clause_id.into(),
                status: PolicyClauseStatus::Executable,
                required_primitives: vec!["transport.packet_cap".into()],
                required_evidence: Vec::new(),
                reason_code: None,
            },
            "maxEgressBytes" => ClauseRealization {
                clause_id: clause_id.into(),
                status: PolicyClauseStatus::Executable,
                required_primitives: vec!["transport.byte_cap".into()],
                required_evidence: Vec::new(),
                reason_code: None,
            },
            "purpose" => ClauseRealization {
                clause_id: clause_id.into(),
                status: PolicyClauseStatus::Executable,
                required_primitives: vec!["transform.manifest".into()],
                required_evidence: Vec::new(),
                reason_code: None,
            },
            "spatial" => ClauseRealization {
                clause_id: clause_id.into(),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: Vec::new(),
                required_evidence: Vec::new(),
                reason_code: Some("transport_geofencing_unavailable".into()),
            },
            "proofKind" => ClauseRealization {
                clause_id: clause_id.into(),
                status: if self.proof_backend == ProofBackend::None {
                    PolicyClauseStatus::Rejected
                } else {
                    PolicyClauseStatus::Executable
                },
                required_primitives: vec!["proof.receipt".into()],
                required_evidence: vec!["provenance_receipt".into()],
                reason_code: (self.proof_backend == ProofBackend::None)
                    .then(|| "proof_backend_missing".into()),
            },
            "teeImageSha384" | "attestationFreshnessSeconds" => ClauseRealization {
                clause_id: clause_id.into(),
                status: if self.tee_backend == TeeBackend::None {
                    PolicyClauseStatus::Rejected
                } else {
                    PolicyClauseStatus::Executable
                },
                required_primitives: vec!["attestation.verifier".into()],
                required_evidence: vec!["attestation_result".into()],
                reason_code: (self.tee_backend == TeeBackend::None)
                    .then(|| "tee_backend_missing".into()),
            },
            "keyReleaseProfile" => {
                let executable = self.tee_backend == TeeBackend::NitroLive
                    && self.attested_key_release_supported
                    && right_operand.as_str() == Some("kms-attested");
                let reason_code = match right_operand.as_str() {
                    Some("kms-attested") if self.tee_backend != TeeBackend::NitroLive => {
                        Some("nitro_live_required".into())
                    }
                    Some("kms-attested") if !self.attested_key_release_supported => {
                        Some("attested_key_release_unavailable".into())
                    }
                    Some("kms-attested") => None,
                    _ => Some("unsupported_key_release_profile".into()),
                };
                ClauseRealization {
                    clause_id: clause_id.into(),
                    status: if executable {
                        PolicyClauseStatus::Executable
                    } else {
                        PolicyClauseStatus::MetadataOnly
                    },
                    required_primitives: vec!["key_broker".into()],
                    required_evidence: vec!["key_erasure_evidence".into()],
                    reason_code: (!executable).then_some(reason_code).flatten(),
                }
            }
            "deletionMode" => {
                let executable = match right_operand.as_str() {
                    Some("dev_deletion") => self.dev_backends_allowed,
                    Some("kms_erasure") => {
                        self.tee_backend == TeeBackend::NitroLive
                            && self.attested_teardown_supported
                    }
                    _ => false,
                };
                let reason_code = match right_operand.as_str() {
                    Some("dev_deletion") if !self.dev_backends_allowed => {
                        Some("dev_teardown_unavailable".into())
                    }
                    Some("kms_erasure") if self.tee_backend != TeeBackend::NitroLive => {
                        Some("nitro_live_required".into())
                    }
                    Some("kms_erasure") if !self.attested_teardown_supported => {
                        Some("attested_teardown_unavailable".into())
                    }
                    Some("dev_deletion" | "kms_erasure") => None,
                    _ => Some("unsupported_teardown_mode".into()),
                };
                ClauseRealization {
                    clause_id: clause_id.into(),
                    status: if executable {
                        PolicyClauseStatus::Executable
                    } else {
                        PolicyClauseStatus::MetadataOnly
                    },
                    required_primitives: vec!["teardown.evidence".into()],
                    required_evidence: vec!["teardown_evidence".into()],
                    reason_code: (!executable).then_some(reason_code).flatten(),
                }
            }
            _ => ClauseRealization {
                clause_id: clause_id.into(),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: Vec::new(),
                required_evidence: Vec::new(),
                reason_code: Some("clause_modeled_only".into()),
            },
        }
    }

    fn duty_clause_realization(
        &self,
        action: &str,
        clause_id: &str,
        right_operand: &Value,
    ) -> ClauseRealization {
        match (action, clause_id) {
            ("delete", "delete-after") => ClauseRealization {
                clause_id: clause_id.into(),
                status: if self.tee_backend == TeeBackend::None {
                    PolicyClauseStatus::Rejected
                } else {
                    PolicyClauseStatus::Executable
                },
                required_primitives: vec!["teardown.evidence".into()],
                required_evidence: vec!["teardown_evidence".into()],
                reason_code: (self.tee_backend == TeeBackend::None)
                    .then(|| "tee_backend_missing".into()),
            },
            ("anonymize", "transform-required") => ClauseRealization {
                clause_id: clause_id.into(),
                status: PolicyClauseStatus::Executable,
                required_primitives: vec!["transform.manifest".into()],
                required_evidence: Vec::new(),
                reason_code: right_operand
                    .as_str()
                    .filter(|value| {
                        !matches!(
                            *value,
                            "drop_columns" | "redact_columns" | "hash_columns" | "row_filter"
                        )
                    })
                    .map(|_| "unsupported_transform_required_op".into()),
            },
            _ if LSDC_PROFILE_OPERANDS.contains(&clause_id) => {
                self.leaf_clause_realization(clause_id, right_operand)
            }
            _ => ClauseRealization {
                clause_id: format!("duty.{action}.{clause_id}"),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: Vec::new(),
                required_evidence: Vec::new(),
                reason_code: Some("duty_constraint_modeled_only".into()),
            },
        }
    }

    fn logical_clause_realization(
        &self,
        operator: NormalizedLogicalOperator,
        prohibition_context: bool,
    ) -> ClauseRealization {
        let (status, reason_code) = if prohibition_context {
            (
                PolicyClauseStatus::MetadataOnly,
                Some("prohibitions_not_enforced".into()),
            )
        } else {
            match operator {
                NormalizedLogicalOperator::And => (PolicyClauseStatus::Executable, None),
                NormalizedLogicalOperator::Or | NormalizedLogicalOperator::Xone => (
                    PolicyClauseStatus::MetadataOnly,
                    Some("logical_disjunction_modeled_only".into()),
                ),
            }
        };

        ClauseRealization {
            clause_id: format!("logical.{}", logical_operator_label(operator)),
            status,
            required_primitives: Vec::new(),
            required_evidence: Vec::new(),
            reason_code,
        }
    }
}

pub fn normalize_policy(policy: &Value) -> Result<NormalizedPolicy> {
    let permissions = normalize_item_list(policy.get("permission"), normalize_permission)?;
    let prohibitions = normalize_item_list(policy.get("prohibition"), normalize_prohibition)?;
    let obligations = normalize_item_list(
        policy.get("obligation").or_else(|| policy.get("duty")),
        normalize_duty,
    )?;

    if permissions.is_empty() && prohibitions.is_empty() && obligations.is_empty() {
        return Err(LsdcError::OdrlParse(
            "ODRL policy must contain a permission, prohibition, or obligation".into(),
        ));
    }

    let truthfulness_mode = match policy
        .get("lsdcTruthfulnessMode")
        .or_else(|| policy.get("truthfulnessMode"))
        .and_then(Value::as_str)
    {
        Some("strict") => TruthfulnessMode::Strict,
        _ => TruthfulnessMode::Permissive,
    };

    let valid_until = policy
        .get("validUntil")
        .and_then(Value::as_str)
        .map(parse_datetime)
        .transpose()?;

    Ok(NormalizedPolicy {
        permissions: sorted_unique_by_canonical(permissions),
        prohibitions: sorted_unique_by_canonical(prohibitions),
        obligations: sorted_unique_by_canonical(obligations),
        truthfulness_mode,
        valid_until,
    })
}

pub fn canonical_policy_json(policy: &Value) -> Value {
    normalize_policy(policy)
        .and_then(|normalized| serde_json::to_value(normalized).map_err(LsdcError::from))
        .unwrap_or_else(|_| canonicalize_json(policy))
}

fn normalize_permission(permission: &Value) -> Result<NormalizedPermission> {
    Ok(NormalizedPermission {
        actions: normalize_actions(permission.get("action"), true)?,
        constraints: normalize_constraint_list(permission.get("constraint"))?,
        duties: normalize_item_list(permission.get("duty"), normalize_duty)?,
    })
}

fn normalize_prohibition(prohibition: &Value) -> Result<NormalizedProhibition> {
    Ok(NormalizedProhibition {
        actions: normalize_actions(prohibition.get("action"), true)?,
        constraints: normalize_constraint_list(prohibition.get("constraint"))?,
    })
}

fn normalize_duty(duty: &Value) -> Result<NormalizedDuty> {
    Ok(NormalizedDuty {
        action: normalize_action(
            duty.get("action")
                .ok_or_else(|| LsdcError::OdrlParse("duty missing action".into()))?,
        )?,
        constraints: normalize_constraint_list(duty.get("constraint"))?,
    })
}

fn normalize_actions(value: Option<&Value>, required: bool) -> Result<Vec<String>> {
    let Some(value) = value else {
        return if required {
            Err(LsdcError::OdrlParse(
                "rule must declare at least one action".into(),
            ))
        } else {
            Ok(Vec::new())
        };
    };

    let actions = match value {
        Value::Array(items) => items.iter().map(normalize_action).collect::<Result<Vec<_>>>()?,
        other => vec![normalize_action(other)?],
    };

    Ok(sorted_unique_strings(actions))
}

fn normalize_constraint_list(value: Option<&Value>) -> Result<Vec<NormalizedConstraint>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let constraints = match value {
        Value::Array(items) => items
            .iter()
            .map(normalize_constraint)
            .collect::<Result<Vec<_>>>()?,
        other => vec![normalize_constraint(other)?],
    };

    Ok(sorted_unique_by_canonical(constraints))
}

fn normalize_constraint(constraint: &Value) -> Result<NormalizedConstraint> {
    if let Some((operator, children)) = parse_logical_constraint(constraint)? {
        let constraints = normalize_constraint_list(Some(children))?;
        if constraints.is_empty() {
            return Err(LsdcError::OdrlParse(
                "logical constraint groups must contain at least one child".into(),
            ));
        }
        return Ok(NormalizedConstraint::Logical {
            operator,
            constraints,
        });
    }

    let clause_id = constraint
        .get("leftOperand")
        .and_then(Value::as_str)
        .ok_or_else(|| LsdcError::OdrlParse("constraint missing leftOperand".into()))?
        .to_string();
    let operator = constraint
        .get("operator")
        .and_then(Value::as_str)
        .unwrap_or("eq")
        .to_ascii_lowercase();
    let right_operand = normalize_right_operand(
        &clause_id,
        constraint.get("rightOperand").unwrap_or(&Value::Null),
    );

    Ok(NormalizedConstraint::Simple {
        clause_id,
        operator,
        right_operand,
    })
}

fn parse_logical_constraint(
    constraint: &Value,
) -> Result<Option<(NormalizedLogicalOperator, &Value)>> {
    let Value::Object(map) = constraint else {
        return Ok(None);
    };

    for (field, operator) in [
        ("and", NormalizedLogicalOperator::And),
        ("or", NormalizedLogicalOperator::Or),
        ("xone", NormalizedLogicalOperator::Xone),
    ] {
        if let Some(children) = map.get(field) {
            return Ok(Some((operator, children)));
        }
    }

    let Some(operator_value) = map.get("operator").and_then(Value::as_str) else {
        return Ok(None);
    };
    if map.get("leftOperand").is_some() {
        return Ok(None);
    }
    let Some(operator) = parse_logical_operator(operator_value) else {
        return Ok(None);
    };
    let children = map
        .get("constraint")
        .or_else(|| map.get("constraints"))
        .ok_or_else(|| {
            LsdcError::OdrlParse(
                "logical constraint groups must declare `constraint` or `constraints`".into(),
            )
        })?;
    Ok(Some((operator, children)))
}

fn normalize_right_operand(clause_id: &str, value: &Value) -> Value {
    let normalized = canonicalize_json(value);
    match (clause_id, normalized) {
        ("purpose" | "spatial", Value::Array(items)) => {
            Value::Array(sorted_unique_json(items))
        }
        (_, other) => other,
    }
}

fn normalize_action(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.to_ascii_lowercase()),
        Value::Object(map) => map
            .get("type")
            .or_else(|| map.get("value"))
            .and_then(Value::as_str)
            .map(|value| value.to_ascii_lowercase())
            .ok_or_else(|| LsdcError::OdrlParse("action object missing `type` or `value`".into())),
        _ => Err(LsdcError::OdrlParse(
            "action must be a string or object".into(),
        )),
    }
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| LsdcError::OdrlParse(format!("invalid RFC3339 datetime `{value}`: {err}")))
}

fn parse_logical_operator(value: &str) -> Option<NormalizedLogicalOperator> {
    match value.to_ascii_lowercase().as_str() {
        "and" => Some(NormalizedLogicalOperator::And),
        "or" => Some(NormalizedLogicalOperator::Or),
        "xone" => Some(NormalizedLogicalOperator::Xone),
        _ => None,
    }
}

fn logical_operator_label(value: NormalizedLogicalOperator) -> &'static str {
    match value {
        NormalizedLogicalOperator::And => "and",
        NormalizedLogicalOperator::Or => "or",
        NormalizedLogicalOperator::Xone => "xone",
    }
}

fn apply_truthfulness_mode(
    truthfulness_mode: TruthfulnessMode,
    mut realization: ClauseRealization,
) -> ClauseRealization {
    if truthfulness_mode == TruthfulnessMode::Strict
        && realization.status == PolicyClauseStatus::MetadataOnly
    {
        realization.status = PolicyClauseStatus::Rejected;
    }
    realization
}

fn normalize_item_list<T, F>(value: Option<&Value>, mut mapper: F) -> Result<Vec<T>>
where
    T: Serialize,
    F: FnMut(&Value) -> Result<T>,
{
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let items = match value {
        Value::Array(values) => values.iter().map(&mut mapper).collect::<Result<Vec<_>>>()?,
        other => vec![mapper(other)?],
    };

    Ok(sorted_unique_by_canonical(items))
}

fn sorted_unique_by_canonical<T>(values: Vec<T>) -> Vec<T>
where
    T: Serialize,
{
    let mut keyed = values
        .into_iter()
        .map(|item| (canonical_json_string(&item), item))
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    keyed.into_iter().map(|(_, item)| item).collect()
}

fn sorted_unique_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn sorted_unique_json(values: Vec<Value>) -> Vec<Value> {
    let mut keyed = values
        .into_iter()
        .map(|value| (canonical_json_string(&value), value))
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    keyed.into_iter().map(|(_, value)| value).collect()
}

fn canonical_json_string<T>(value: &T) -> String
where
    T: Serialize,
{
    serde_json::to_string(&canonicalize_json(
        &serde_json::to_value(value).expect("normalized values should serialize"),
    ))
    .expect("canonical policy values should serialize")
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();

            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize_json(&map[&key]));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}
