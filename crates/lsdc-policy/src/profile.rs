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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedConstraint {
    pub clause_id: String,
    pub operator: String,
    pub right_operand: Value,
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
pub struct NormalizedPolicy {
    pub permissions: Vec<NormalizedPermission>,
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
            for constraint in &permission.constraints {
                if !LSDC_PROFILE_OPERANDS.contains(&constraint.clause_id.as_str()) {
                    continue;
                }

                let mut realization = match constraint.clause_id.as_str() {
                    "maxEgressBytes" => ClauseRealization {
                        clause_id: constraint.clause_id.clone(),
                        status: PolicyClauseStatus::Executable,
                        required_primitives: vec!["transport.byte_cap".into()],
                        required_evidence: Vec::new(),
                        reason_code: None,
                    },
                    "proofKind" => ClauseRealization {
                        clause_id: constraint.clause_id.clone(),
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
                        clause_id: constraint.clause_id.clone(),
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
                            && constraint.right_operand.as_str() == Some("kms-attested");
                        let reason_code = match constraint.right_operand.as_str() {
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
                            clause_id: constraint.clause_id.clone(),
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
                        let executable = match constraint.right_operand.as_str() {
                            Some("dev_deletion") => self.dev_backends_allowed,
                            Some("kms_erasure") => {
                                self.tee_backend == TeeBackend::NitroLive
                                    && self.attested_teardown_supported
                            }
                            _ => false,
                        };
                        let reason_code = match constraint.right_operand.as_str() {
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
                            clause_id: constraint.clause_id.clone(),
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
                        clause_id: constraint.clause_id.clone(),
                        status: PolicyClauseStatus::MetadataOnly,
                        required_primitives: Vec::new(),
                        required_evidence: Vec::new(),
                        reason_code: Some("overlay_operand_unhandled".into()),
                    },
                };

                if normalized_policy.truthfulness_mode == TruthfulnessMode::Strict
                    && realization.status == PolicyClauseStatus::MetadataOnly
                {
                    realization.status = PolicyClauseStatus::Rejected;
                }

                clauses.push(realization);
            }
        }

        if evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::PriceApproval)
        {
            clauses.push(ClauseRealization {
                clause_id: "pricing.autonomous_mutation".into(),
                status: PolicyClauseStatus::MetadataOnly,
                required_primitives: vec!["pricing.oracle".into()],
                required_evidence: vec!["price_decision".into()],
                reason_code: Some("pricing_advisory_only".into()),
            });
        }

        clauses
    }
}

pub fn normalize_policy(policy: &Value) -> Result<NormalizedPolicy> {
    let permissions = policy
        .get("permission")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            LsdcError::OdrlParse("ODRL policy must contain a permission array".into())
        })?;

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

    let permissions = permissions
        .iter()
        .map(normalize_permission)
        .collect::<Result<Vec<_>>>()?;

    Ok(NormalizedPolicy {
        permissions,
        truthfulness_mode,
        valid_until,
    })
}

pub fn canonical_policy_json(policy: &Value) -> Value {
    canonicalize_json(policy)
}

fn normalize_permission(permission: &Value) -> Result<NormalizedPermission> {
    let actions = match permission.get("action") {
        Some(Value::Array(items)) => items
            .iter()
            .map(normalize_action)
            .collect::<Result<Vec<_>>>()?,
        Some(value) => vec![normalize_action(value)?],
        None => Vec::new(),
    };
    let constraints = permission
        .get("constraint")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(normalize_constraint).collect())
        .transpose()?
        .unwrap_or_default();
    let duties = permission
        .get("duty")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(normalize_duty).collect())
        .transpose()?
        .unwrap_or_default();

    Ok(NormalizedPermission {
        actions,
        constraints,
        duties,
    })
}

fn normalize_duty(duty: &Value) -> Result<NormalizedDuty> {
    let action = duty
        .get("action")
        .ok_or_else(|| LsdcError::OdrlParse("duty missing action".into()))
        .and_then(normalize_action)?;
    let constraints = duty
        .get("constraint")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(normalize_constraint).collect())
        .transpose()?
        .unwrap_or_default();
    Ok(NormalizedDuty {
        action,
        constraints,
    })
}

fn normalize_constraint(constraint: &Value) -> Result<NormalizedConstraint> {
    let clause_id = constraint
        .get("leftOperand")
        .and_then(Value::as_str)
        .ok_or_else(|| LsdcError::OdrlParse("constraint missing leftOperand".into()))?
        .to_string();
    let operator = constraint
        .get("operator")
        .and_then(Value::as_str)
        .unwrap_or("eq")
        .to_string();
    let right_operand = constraint
        .get("rightOperand")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(NormalizedConstraint {
        clause_id,
        operator,
        right_operand,
    })
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
