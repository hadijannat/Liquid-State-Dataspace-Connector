use crate::error::{LsdcError, Result};
use crate::execution::{PolicyClauseStatus, ProofBackend, TeeBackend, TransportBackend};
use crate::liquid::EvidenceRequirement;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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

pub const LSDC_POLICY_COMMITMENT_PROFILE_V1: &str = "lsdc.policy.v1";
pub const LSDC_POLICY_COMMITMENT_PROFILE_V2: &str = "lsdc.policy.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedExtensionFragment {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedLogicalOperator {
    And,
    Or,
    Xone,
    AndSequence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedConstraintLeaf {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub clause_id: String,
    pub left_operand: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_operand: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_operand_reference: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<NormalizedExtensionFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedLogicalConstraint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub clause_id: String,
    pub op: NormalizedLogicalOperator,
    pub children: Vec<NormalizedConstraintExpr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<NormalizedExtensionFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedConstraintExpr {
    Leaf(NormalizedConstraintLeaf),
    Logical(NormalizedLogicalConstraint),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedDuty {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub clause_id: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<NormalizedConstraintExpr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<NormalizedExtensionFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub clause_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<NormalizedConstraintExpr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duties: Vec<NormalizedDuty>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<NormalizedExtensionFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedPolicyV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub commitment_profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<NormalizedRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibitions: Vec<NormalizedRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<NormalizedDuty>,
    pub truthfulness_mode: TruthfulnessMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<NormalizedExtensionFragment>,
}

pub type NormalizedPolicy = NormalizedPolicyV2;
pub type NormalizedConstraint = NormalizedConstraintLeaf;
pub type NormalizedPermission = NormalizedRule;

impl NormalizedConstraintExpr {
    fn collect_leaf_constraints<'a>(&'a self, output: &mut Vec<&'a NormalizedConstraintLeaf>) {
        match self {
            Self::Leaf(leaf) => output.push(leaf),
            Self::Logical(logical) => {
                for child in &logical.children {
                    child.collect_leaf_constraints(output);
                }
            }
        }
    }
}

impl NormalizedDuty {
    pub fn constraint_leaves(&self) -> Vec<&NormalizedConstraintLeaf> {
        let mut leaves = Vec::new();
        for constraint in &self.constraints {
            constraint.collect_leaf_constraints(&mut leaves);
        }
        leaves
    }
}

impl NormalizedRule {
    pub fn constraint_leaves(&self) -> Vec<&NormalizedConstraintLeaf> {
        let mut leaves = Vec::new();
        for constraint in &self.constraints {
            constraint.collect_leaf_constraints(&mut leaves);
        }
        for duty in &self.duties {
            for constraint in &duty.constraints {
                constraint.collect_leaf_constraints(&mut leaves);
            }
        }
        leaves
    }
}

impl NormalizedPolicyV2 {
    pub fn constraint_leaves(&self) -> Vec<&NormalizedConstraintLeaf> {
        let mut leaves = Vec::new();
        for rule in &self.permissions {
            leaves.extend(rule.constraint_leaves());
        }
        for rule in &self.prohibitions {
            leaves.extend(rule.constraint_leaves());
        }
        for obligation in &self.obligations {
            leaves.extend(obligation.constraint_leaves());
        }
        leaves
    }

    pub fn constraint_leaves_by_operand(&self, operand: &str) -> Vec<&NormalizedConstraintLeaf> {
        self.constraint_leaves()
            .into_iter()
            .filter(|leaf| leaf.left_operand == operand)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClauseRealization {
    pub clause_id: String,
    pub semantic_key: String,
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

        if normalized_policy.truthfulness_mode == TruthfulnessMode::Strict
            && !self.strict_mode_supported
        {
            clauses.push(ClauseRealization {
                clause_id: "overlay.truthfulness_mode".into(),
                semantic_key: "overlay.truthfulness_mode".into(),
                status: PolicyClauseStatus::Rejected,
                required_primitives: Vec::new(),
                required_evidence: Vec::new(),
                reason_code: Some("strict_mode_unsupported".into()),
            });
        }

        for rule in &normalized_policy.permissions {
            self.collect_rule_realizations(
                rule,
                RuleKind::Permission,
                normalized_policy.truthfulness_mode,
                &mut clauses,
            );
        }
        for rule in &normalized_policy.prohibitions {
            self.collect_rule_realizations(
                rule,
                RuleKind::Prohibition,
                normalized_policy.truthfulness_mode,
                &mut clauses,
            );
        }
        for obligation in &normalized_policy.obligations {
            self.collect_duty_realizations(
                obligation,
                RuleKind::Obligation,
                normalized_policy.truthfulness_mode,
                &mut clauses,
            );
        }

        if evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::PriceApproval)
        {
            clauses.push(self.apply_truthfulness(ClauseRealization {
                clause_id: "pricing.autonomous_mutation".into(),
                semantic_key: "pricing.autonomous_mutation".into(),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: vec!["pricing.oracle".into()],
                required_evidence: vec!["price_decision".into()],
                reason_code: Some("pricing_advisory_only".into()),
            }, normalized_policy.truthfulness_mode));
        }

        clauses.sort_by(|left, right| {
            left.semantic_key
                .cmp(&right.semantic_key)
                .then(left.clause_id.cmp(&right.clause_id))
        });
        clauses
    }

    fn collect_rule_realizations(
        &self,
        rule: &NormalizedRule,
        kind: RuleKind,
        truthfulness_mode: TruthfulnessMode,
        clauses: &mut Vec<ClauseRealization>,
    ) {
        if matches!(kind, RuleKind::Prohibition) {
            clauses.push(self.apply_truthfulness(
                ClauseRealization {
                    clause_id: rule.clause_id.clone(),
                    semantic_key: "prohibition.rule".into(),
                    status: PolicyClauseStatus::MetadataOnly,
                    required_primitives: Vec::new(),
                    required_evidence: Vec::new(),
                    reason_code: Some("prohibition_modeled_only".into()),
                },
                truthfulness_mode,
            ));
        }

        for constraint in &rule.constraints {
            self.collect_constraint_realizations(constraint, truthfulness_mode, clauses);
        }
        for duty in &rule.duties {
            self.collect_duty_realizations(duty, kind, truthfulness_mode, clauses);
        }
    }

    fn collect_duty_realizations(
        &self,
        duty: &NormalizedDuty,
        kind: RuleKind,
        truthfulness_mode: TruthfulnessMode,
        clauses: &mut Vec<ClauseRealization>,
    ) {
        if !matches!(duty.action.as_str(), "delete" | "anonymize") || matches!(kind, RuleKind::Obligation)
        {
            clauses.push(self.apply_truthfulness(
                ClauseRealization {
                    clause_id: duty.clause_id.clone(),
                    semantic_key: format!("duty.{}", duty.action),
                    status: PolicyClauseStatus::MetadataOnly,
                    required_primitives: Vec::new(),
                    required_evidence: Vec::new(),
                    reason_code: Some(if matches!(kind, RuleKind::Obligation) {
                        "obligation_modeled_only".into()
                    } else {
                        "duty_modeled_only".into()
                    }),
                },
                truthfulness_mode,
            ));
        }

        for constraint in &duty.constraints {
            self.collect_constraint_realizations(constraint, truthfulness_mode, clauses);
        }
    }

    fn collect_constraint_realizations(
        &self,
        constraint: &NormalizedConstraintExpr,
        truthfulness_mode: TruthfulnessMode,
        clauses: &mut Vec<ClauseRealization>,
    ) {
        match constraint {
            NormalizedConstraintExpr::Leaf(leaf) => {
                clauses.push(self.apply_truthfulness(
                    self.realize_constraint_leaf(leaf),
                    truthfulness_mode,
                ));
            }
            NormalizedConstraintExpr::Logical(logical) => {
                clauses.push(self.apply_truthfulness(
                    ClauseRealization {
                        clause_id: logical.clause_id.clone(),
                        semantic_key: format!("logical.{:?}", logical.op).to_ascii_lowercase(),
                        status: PolicyClauseStatus::MetadataOnly,
                        required_primitives: Vec::new(),
                        required_evidence: Vec::new(),
                        reason_code: Some("logical_constraint_modeled_only".into()),
                    },
                    truthfulness_mode,
                ));
                for child in &logical.children {
                    self.collect_constraint_realizations(child, truthfulness_mode, clauses);
                }
            }
        }
    }

    fn realize_constraint_leaf(&self, leaf: &NormalizedConstraintLeaf) -> ClauseRealization {
        if !LSDC_PROFILE_OPERANDS.contains(&leaf.left_operand.as_str()) {
            return ClauseRealization {
                clause_id: leaf.clause_id.clone(),
                semantic_key: leaf.left_operand.clone(),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: Vec::new(),
                required_evidence: Vec::new(),
                reason_code: Some("overlay_operand_unhandled".into()),
            };
        }

        match leaf.left_operand.as_str() {
            "maxEgressBytes" => ClauseRealization {
                clause_id: leaf.clause_id.clone(),
                semantic_key: leaf.left_operand.clone(),
                status: PolicyClauseStatus::Executable,
                required_primitives: vec!["transport.byte_cap".into()],
                required_evidence: Vec::new(),
                reason_code: None,
            },
            "proofKind" => ClauseRealization {
                clause_id: leaf.clause_id.clone(),
                semantic_key: leaf.left_operand.clone(),
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
                clause_id: leaf.clause_id.clone(),
                semantic_key: leaf.left_operand.clone(),
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
                    && leaf.right_operand.as_ref().and_then(Value::as_str) == Some("kms-attested");
                let reason_code = match leaf.right_operand.as_ref().and_then(Value::as_str) {
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
                    clause_id: leaf.clause_id.clone(),
                    semantic_key: leaf.left_operand.clone(),
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
                let executable = match leaf.right_operand.as_ref().and_then(Value::as_str) {
                    Some("dev_deletion") => self.dev_backends_allowed,
                    Some("kms_erasure") => {
                        self.tee_backend == TeeBackend::NitroLive
                            && self.attested_teardown_supported
                    }
                    _ => false,
                };
                let reason_code = match leaf.right_operand.as_ref().and_then(Value::as_str) {
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
                    clause_id: leaf.clause_id.clone(),
                    semantic_key: leaf.left_operand.clone(),
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
                clause_id: leaf.clause_id.clone(),
                semantic_key: leaf.left_operand.clone(),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: Vec::new(),
                required_evidence: Vec::new(),
                reason_code: Some("overlay_operand_unhandled".into()),
            },
        }
    }

    fn apply_truthfulness(
        &self,
        mut realization: ClauseRealization,
        truthfulness_mode: TruthfulnessMode,
    ) -> ClauseRealization {
        if truthfulness_mode == TruthfulnessMode::Strict
            && realization.status == PolicyClauseStatus::MetadataOnly
        {
            realization.status = PolicyClauseStatus::Rejected;
        }
        realization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Permission,
    Prohibition,
    Obligation,
}

pub fn normalize_policy(policy: &Value) -> Result<NormalizedPolicy> {
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

    let mut permissions = extract_rule_array(policy.get("permission"), normalize_rule)?;
    let mut prohibitions = extract_rule_array(policy.get("prohibition"), normalize_rule)?;
    let mut obligations = Vec::new();
    obligations.extend(extract_rule_array(policy.get("obligation"), normalize_duty)?);
    obligations.extend(extract_rule_array(policy.get("duty"), normalize_duty)?);

    if permissions.is_empty() && prohibitions.is_empty() && obligations.is_empty() {
        return Err(LsdcError::OdrlParse(
            "ODRL policy must contain permission, prohibition, or duty/obligation rules".into(),
        ));
    }

    permissions.sort_by_key(rule_sort_key);
    prohibitions.sort_by_key(rule_sort_key);
    obligations.sort_by_key(duty_sort_key);

    let mut normalized = NormalizedPolicyV2 {
        uid: optional_string(policy.get("uid")),
        commitment_profile: LSDC_POLICY_COMMITMENT_PROFILE_V2.into(),
        permissions,
        prohibitions,
        obligations,
        truthfulness_mode,
        valid_until,
        extensions: extract_extensions(
            policy,
            &[
                "@context",
                "uid",
                "permission",
                "prohibition",
                "obligation",
                "duty",
                "validUntil",
                "lsdcTruthfulnessMode",
                "truthfulnessMode",
            ],
        ),
    };
    uniquify_policy_clause_ids(&mut normalized);
    Ok(normalized)
}

pub fn canonical_policy_json(policy: &Value) -> Value {
    canonicalize_json(policy)
}

pub fn canonical_normalized_policy_bytes(
    normalized_policy: &NormalizedPolicy,
) -> std::result::Result<Vec<u8>, serde_json::Error> {
    serde_json::to_value(normalized_policy).and_then(|value| serde_json::to_vec(&canonicalize_json(&value)))
}

fn normalize_rule(rule: &Value) -> Result<NormalizedRule> {
    let mut actions = match rule.get("action") {
        Some(Value::Array(items)) => items
            .iter()
            .map(normalize_action)
            .collect::<Result<Vec<_>>>()?,
        Some(value) => vec![normalize_action(value)?],
        None => Vec::new(),
    };
    actions.sort();
    actions.dedup();

    let mut constraints = extract_expr_array(rule.get("constraint"))?;
    constraints.sort_by_key(expr_sort_key);

    let mut duties = extract_rule_array(rule.get("duty"), normalize_duty)?;
    duties.sort_by_key(duty_sort_key);

    let uid = optional_string(rule.get("uid"));
    let mut normalized = NormalizedRule {
        clause_id: String::new(),
        uid: uid.clone(),
        actions,
        constraints,
        duties,
        extensions: extract_extensions(rule, &["uid", "action", "constraint", "duty"]),
    };
    normalized.clause_id = uid.unwrap_or_else(|| format!("rule:{}", rule_sort_key(&normalized)));
    Ok(normalized)
}

fn normalize_duty(duty: &Value) -> Result<NormalizedDuty> {
    let action = duty
        .get("action")
        .ok_or_else(|| LsdcError::OdrlParse("duty missing action".into()))
        .and_then(normalize_action)?;
    let mut constraints = extract_expr_array(duty.get("constraint"))?;
    constraints.sort_by_key(expr_sort_key);
    let uid = optional_string(duty.get("uid"));
    let mut normalized = NormalizedDuty {
        clause_id: String::new(),
        uid: uid.clone(),
        action,
        constraints,
        extensions: extract_extensions(duty, &["uid", "action", "constraint"]),
    };
    normalized.clause_id = uid.unwrap_or_else(|| format!("duty:{}", duty_sort_key(&normalized)));
    Ok(normalized)
}

fn extract_rule_array<T, F>(value: Option<&Value>, mut normalize: F) -> Result<Vec<T>>
where
    F: FnMut(&Value) -> Result<T>,
{
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().map(&mut normalize).collect())
        .transpose()
        .map(Option::unwrap_or_default)
}

fn extract_expr_array(value: Option<&Value>) -> Result<Vec<NormalizedConstraintExpr>> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().map(normalize_constraint_expr).collect())
        .transpose()
        .map(Option::unwrap_or_default)
}

fn normalize_constraint_expr(value: &Value) -> Result<NormalizedConstraintExpr> {
    let object = value
        .as_object()
        .ok_or_else(|| LsdcError::OdrlParse("constraint must be a JSON object".into()))?;

    let logical_keys = ["and", "or", "xone", "andSequence"]
        .into_iter()
        .filter(|key| object.contains_key(*key))
        .collect::<Vec<_>>();
    if logical_keys.len() > 1 {
        return Err(LsdcError::OdrlParse(
            "logical constraint must declare exactly one logical operator".into(),
        ));
    }

    if let Some(logical_key) = logical_keys.first() {
        return normalize_logical_constraint(object, logical_key);
    }

    normalize_constraint_leaf(object)
}

fn normalize_logical_constraint(
    object: &Map<String, Value>,
    logical_key: &str,
) -> Result<NormalizedConstraintExpr> {
    let op = match logical_key {
        "and" => NormalizedLogicalOperator::And,
        "or" => NormalizedLogicalOperator::Or,
        "xone" => NormalizedLogicalOperator::Xone,
        "andSequence" => NormalizedLogicalOperator::AndSequence,
        _ => unreachable!("unsupported logical operator"),
    };

    let children = object
        .get(logical_key)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            LsdcError::OdrlParse(format!("logical constraint `{logical_key}` must be an array"))
        })?;

    let mut children = children
        .iter()
        .map(normalize_constraint_expr)
        .collect::<Result<Vec<_>>>()?;
    if op != NormalizedLogicalOperator::AndSequence {
        children.sort_by_key(expr_sort_key);
    }

    let uid = optional_string(object.get("uid"));
    let mut normalized = NormalizedLogicalConstraint {
        clause_id: String::new(),
        uid: uid.clone(),
        op,
        children,
        extensions: extract_extensions_from_object(object, &["uid", "and", "or", "xone", "andSequence"]),
    };
    normalized.clause_id =
        uid.unwrap_or_else(|| format!("logical:{}", logical_sort_key(&normalized)));
    Ok(NormalizedConstraintExpr::Logical(normalized))
}

fn normalize_constraint_leaf(object: &Map<String, Value>) -> Result<NormalizedConstraintExpr> {
    let left_operand = object
        .get("leftOperand")
        .and_then(Value::as_str)
        .ok_or_else(|| LsdcError::OdrlParse("constraint missing leftOperand".into()))?
        .to_string();
    let operator = object
        .get("operator")
        .and_then(Value::as_str)
        .unwrap_or("eq")
        .to_ascii_lowercase();
    let uid = optional_string(object.get("uid"));
    let right_operand = object
        .get("rightOperand")
        .cloned()
        .map(|value| normalize_right_operand(&left_operand, value));
    let mut leaf = NormalizedConstraintLeaf {
        clause_id: String::new(),
        uid: uid.clone(),
        left_operand,
        operator,
        right_operand,
        right_operand_reference: object
            .get("rightOperandReference")
            .cloned()
            .map(|value| canonicalize_json(&value)),
        unit: object.get("unit").cloned().map(|value| canonicalize_json(&value)),
        data_type: object
            .get("dataType")
            .cloned()
            .map(|value| canonicalize_json(&value)),
        status: object
            .get("status")
            .cloned()
            .map(|value| canonicalize_json(&value)),
        extensions: extract_extensions_from_object(
            object,
            &[
                "uid",
                "leftOperand",
                "operator",
                "rightOperand",
                "rightOperandReference",
                "unit",
                "dataType",
                "status",
            ],
        ),
    };
    leaf.clause_id = uid.unwrap_or_else(|| format!("constraint:{}", leaf_sort_key(&leaf)));
    Ok(NormalizedConstraintExpr::Leaf(leaf))
}

fn normalize_right_operand(left_operand: &str, value: Value) -> Value {
    match value {
        Value::Array(items) if matches!(left_operand, "spatial" | "purpose") => {
            let mut items = items.into_iter().map(|item| canonicalize_json(&item)).collect::<Vec<_>>();
            items.sort_by_key(value_sort_key);
            items.dedup();
            Value::Array(items)
        }
        other => canonicalize_json(&other),
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

fn optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_string)
}

fn extract_extensions(value: &Value, known_keys: &[&str]) -> Vec<NormalizedExtensionFragment> {
    value.as_object()
        .map(|object| extract_extensions_from_object(object, known_keys))
        .unwrap_or_default()
}

fn extract_extensions_from_object(
    object: &Map<String, Value>,
    known_keys: &[&str],
) -> Vec<NormalizedExtensionFragment> {
    let mut extensions = object
        .iter()
        .filter(|(key, _)| !known_keys.contains(&key.as_str()))
        .map(|(key, value)| NormalizedExtensionFragment {
            key: key.clone(),
            value: canonicalize_json(value),
        })
        .collect::<Vec<_>>();
    extensions.sort_by(|left, right| left.key.cmp(&right.key));
    extensions
}

fn uniquify_policy_clause_ids(policy: &mut NormalizedPolicyV2) {
    let mut seen = BTreeMap::new();
    for rule in &mut policy.permissions {
        uniquify_rule_clause_ids(rule, &mut seen);
    }
    for rule in &mut policy.prohibitions {
        uniquify_rule_clause_ids(rule, &mut seen);
    }
    for obligation in &mut policy.obligations {
        uniquify_duty_clause_ids(obligation, &mut seen);
    }
}

fn uniquify_rule_clause_ids(rule: &mut NormalizedRule, seen: &mut BTreeMap<String, usize>) {
    uniquify_clause_id(&mut rule.clause_id, seen);
    for constraint in &mut rule.constraints {
        uniquify_expr_clause_ids(constraint, seen);
    }
    for duty in &mut rule.duties {
        uniquify_duty_clause_ids(duty, seen);
    }
}

fn uniquify_duty_clause_ids(duty: &mut NormalizedDuty, seen: &mut BTreeMap<String, usize>) {
    uniquify_clause_id(&mut duty.clause_id, seen);
    for constraint in &mut duty.constraints {
        uniquify_expr_clause_ids(constraint, seen);
    }
}

fn uniquify_expr_clause_ids(
    expr: &mut NormalizedConstraintExpr,
    seen: &mut BTreeMap<String, usize>,
) {
    match expr {
        NormalizedConstraintExpr::Leaf(leaf) => uniquify_clause_id(&mut leaf.clause_id, seen),
        NormalizedConstraintExpr::Logical(logical) => {
            uniquify_clause_id(&mut logical.clause_id, seen);
            for child in &mut logical.children {
                uniquify_expr_clause_ids(child, seen);
            }
        }
    }
}

fn uniquify_clause_id(clause_id: &mut String, seen: &mut BTreeMap<String, usize>) {
    let count = seen.entry(clause_id.clone()).or_insert(0);
    *count += 1;
    if *count > 1 {
        *clause_id = format!("{clause_id}:{}", *count);
    }
}

fn rule_sort_key(rule: &NormalizedRule) -> String {
    stable_hex_json(&serde_json::json!({
        "uid": rule.uid,
        "actions": rule.actions,
        "constraints": rule.constraints.iter().map(expr_sort_key).collect::<Vec<_>>(),
        "duties": rule.duties.iter().map(duty_sort_key).collect::<Vec<_>>(),
        "extensions": rule.extensions,
    }))
}

fn duty_sort_key(duty: &NormalizedDuty) -> String {
    stable_hex_json(&serde_json::json!({
        "uid": duty.uid,
        "action": duty.action,
        "constraints": duty.constraints.iter().map(expr_sort_key).collect::<Vec<_>>(),
        "extensions": duty.extensions,
    }))
}

fn expr_sort_key(expr: &NormalizedConstraintExpr) -> String {
    match expr {
        NormalizedConstraintExpr::Leaf(leaf) => leaf_sort_key(leaf),
        NormalizedConstraintExpr::Logical(logical) => logical_sort_key(logical),
    }
}

fn logical_sort_key(logical: &NormalizedLogicalConstraint) -> String {
    stable_hex_json(&serde_json::json!({
        "uid": logical.uid,
        "op": logical.op,
        "children": logical.children.iter().map(expr_sort_key).collect::<Vec<_>>(),
        "extensions": logical.extensions,
    }))
}

fn leaf_sort_key(leaf: &NormalizedConstraintLeaf) -> String {
    stable_hex_json(&serde_json::json!({
        "uid": leaf.uid,
        "left_operand": leaf.left_operand,
        "operator": leaf.operator,
        "right_operand": leaf.right_operand,
        "right_operand_reference": leaf.right_operand_reference,
        "unit": leaf.unit,
        "data_type": leaf.data_type,
        "status": leaf.status,
        "extensions": leaf.extensions,
    }))
}

fn value_sort_key(value: &Value) -> String {
    stable_hex_json(value)
}

fn stable_hex_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(&canonicalize_json(value))
        .expect("canonical JSON serialization should succeed");
    hex::encode(Sha256::digest(bytes))
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
