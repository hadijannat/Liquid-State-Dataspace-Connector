use super::ast::PolicyAgreement;
use crate::error::{LsdcError, Result};
use crate::liquid::{
    CsvTransformOpKind, EvidenceRequirement, LiquidPolicyIr, RuntimeGuard, TransformGuard,
    TransportGuard, TransportProtocol,
};
use crate::profile::{normalize_policy, NormalizedConstraint, NormalizedLogicalOperator};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn parse_legacy_policy_json(json: &str) -> Result<PolicyAgreement> {
    serde_json::from_str(json).map_err(|e| LsdcError::OdrlParse(e.to_string()))
}

pub fn parse_policy_json(json: &str) -> Result<Value> {
    serde_json::from_str(json).map_err(|e| LsdcError::OdrlParse(e.to_string()))
}

pub fn policy_hash_hex(policy: &Value) -> Result<String> {
    let digest = Sha256::digest(canonical_json_bytes(policy).map_err(LsdcError::from)?);
    Ok(hex::encode(digest))
}

pub fn lower_policy(
    policy: &Value,
    evidence_requirements: &[EvidenceRequirement],
) -> Result<LiquidPolicyIr> {
    let normalized = normalize_policy(policy)?;

    if !normalized.prohibitions.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "executable lowering does not support prohibition rules".into(),
        ));
    }
    if !normalized.obligations.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "executable lowering does not support top-level obligations".into(),
        ));
    }

    let mut allow_read = false;
    let mut allow_transfer = false;
    let mut allow_anonymize = false;
    let mut packet_caps = Vec::new();
    let mut byte_caps = Vec::new();
    let mut allowed_regions = Vec::new();
    let mut allowed_purposes = Vec::new();
    let mut required_ops = Vec::new();
    let mut delete_after_seconds = Vec::new();

    for permission in &normalized.permissions {
        for action in &permission.actions {
            match action.as_str() {
                "read" => allow_read = true,
                "transfer" => allow_transfer = true,
                "anonymize" => allow_anonymize = true,
                _ => {}
            }
        }

        for constraint in &permission.constraints {
            collect_constraint_values(
                constraint,
                &mut packet_caps,
                &mut byte_caps,
                &mut allowed_regions,
                &mut allowed_purposes,
            )?;
        }

        for duty in &permission.duties {
            collect_duty_values(
                duty.action.as_str(),
                &duty.constraints,
                &mut allow_anonymize,
                &mut required_ops,
                &mut delete_after_seconds,
            )?;
        }
    }

    let valid_until = match policy.get("validUntil") {
        Some(value) => Some(parse_datetime_value(value)?),
        None => None,
    };

    if !allow_read && !allow_transfer && !allow_anonymize {
        return Err(LsdcError::PolicyCompile(
            "ODRL policy must authorize read, transfer, or anonymize".into(),
        ));
    }

    Ok(LiquidPolicyIr {
        transport_guard: TransportGuard {
            allow_read,
            allow_transfer,
            packet_cap: packet_caps.into_iter().min(),
            byte_cap: byte_caps.into_iter().min(),
            allowed_regions,
            valid_until,
            protocol: TransportProtocol::Udp,
            session_port: None,
        },
        transform_guard: TransformGuard {
            allow_anonymize,
            allowed_purposes,
            required_ops: dedupe_vec(required_ops),
        },
        runtime_guard: RuntimeGuard {
            delete_after_seconds: delete_after_seconds.into_iter().min(),
            evidence_requirements: dedupe_vec(evidence_requirements.to_vec()),
            approval_required: evidence_requirements
                .iter()
                .any(|item| item == &EvidenceRequirement::PriceApproval),
        },
    })
}

fn collect_constraint_values(
    constraint: &NormalizedConstraint,
    packet_caps: &mut Vec<u64>,
    byte_caps: &mut Vec<u64>,
    allowed_regions: &mut Vec<String>,
    allowed_purposes: &mut Vec<String>,
) -> Result<()> {
    match constraint {
        NormalizedConstraint::Simple {
            clause_id,
            right_operand,
            ..
        } => match clause_id.as_str() {
            "count" => packet_caps.push(parse_u64_value(right_operand)?),
            "maxEgressBytes" => byte_caps.push(parse_u64_value(right_operand)?),
            "spatial" => extend_unique(allowed_regions, parse_string_list_value(right_operand)?),
            "purpose" => extend_unique(allowed_purposes, parse_string_list_value(right_operand)?),
            _ => {}
        },
        NormalizedConstraint::Logical {
            operator,
            constraints,
        } => {
            if *operator != NormalizedLogicalOperator::And {
                return Err(LsdcError::PolicyCompile(format!(
                    "executable lowering does not support logical `{}` groups",
                    logical_operator_name(*operator)
                )));
            }
            for child in constraints {
                collect_constraint_values(
                    child,
                    packet_caps,
                    byte_caps,
                    allowed_regions,
                    allowed_purposes,
                )?;
            }
        }
    }

    Ok(())
}

fn collect_duty_values(
    action: &str,
    constraints: &[NormalizedConstraint],
    allow_anonymize: &mut bool,
    required_ops: &mut Vec<CsvTransformOpKind>,
    delete_after_seconds: &mut Vec<u64>,
) -> Result<()> {
    match action {
        "anonymize" => *allow_anonymize = true,
        "delete" => {}
        other => {
            return Err(LsdcError::PolicyCompile(format!(
                "unsupported executable duty action `{other}`"
            )))
        }
    }

    for constraint in constraints {
        match constraint {
            NormalizedConstraint::Simple {
                clause_id,
                right_operand,
                ..
            } => match (action, clause_id.as_str()) {
                ("delete", "delete-after") => {
                    delete_after_seconds.push(parse_duration_value(right_operand)?);
                }
                ("anonymize", "transform-required") => {
                    if let Some(value) = right_operand.as_str() {
                        required_ops.push(parse_transform_kind(value)?);
                    }
                }
                _ => {}
            },
            NormalizedConstraint::Logical {
                operator,
                constraints,
            } => {
                if *operator != NormalizedLogicalOperator::And {
                    return Err(LsdcError::PolicyCompile(format!(
                        "executable lowering does not support logical `{}` groups",
                        logical_operator_name(*operator)
                    )));
                }
                collect_duty_values(
                    action,
                    constraints,
                    allow_anonymize,
                    required_ops,
                    delete_after_seconds,
                )?;
            }
        }
    }

    Ok(())
}

fn canonical_json_bytes(value: &Value) -> std::result::Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&canonicalize_json(value))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
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

fn parse_string_list_value(value: &Value) -> Result<Vec<String>> {
    match value {
        Value::String(item) => Ok(vec![item.to_owned()]),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    LsdcError::OdrlParse("string array expected for constraint value".into())
                })
            })
            .collect(),
        _ => Err(LsdcError::OdrlParse(
            "constraint value must be a string or array of strings".into(),
        )),
    }
}

fn parse_u64_value(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| LsdcError::OdrlParse("constraint value must be an unsigned integer".into()))
}

fn parse_datetime_value(value: &Value) -> Result<DateTime<Utc>> {
    let timestamp = value
        .as_str()
        .ok_or_else(|| LsdcError::OdrlParse("`validUntil` must be an RFC3339 string".into()))?;
    DateTime::parse_from_rfc3339(timestamp)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| LsdcError::OdrlParse(format!("invalid `validUntil`: {err}")))
}

fn parse_transform_kind(value: &str) -> Result<CsvTransformOpKind> {
    match value {
        "drop_columns" => Ok(CsvTransformOpKind::DropColumns),
        "redact_columns" => Ok(CsvTransformOpKind::RedactColumns),
        "hash_columns" => Ok(CsvTransformOpKind::HashColumns),
        "row_filter" => Ok(CsvTransformOpKind::RowFilter),
        other => Err(LsdcError::PolicyCompile(format!(
            "unsupported transform-required op `{other}`"
        ))),
    }
}

fn logical_operator_name(operator: NormalizedLogicalOperator) -> &'static str {
    match operator {
        NormalizedLogicalOperator::And => "and",
        NormalizedLogicalOperator::Or => "or",
        NormalizedLogicalOperator::Xone => "xone",
    }
}

fn parse_duration_value(value: &Value) -> Result<u64> {
    let duration = value
        .as_str()
        .ok_or_else(|| LsdcError::OdrlParse("duration duty values must be strings".into()))?;
    parse_duration_seconds(duration)
}

fn parse_duration_seconds(value: &str) -> Result<u64> {
    if let Some(days) = value
        .strip_prefix('P')
        .and_then(|rest| rest.strip_suffix('D'))
        .and_then(|number| number.parse::<u64>().ok())
    {
        return Ok(days * 24 * 60 * 60);
    }

    if let Some(hours) = value
        .strip_prefix("PT")
        .and_then(|rest| rest.strip_suffix('H'))
        .and_then(|number| number.parse::<u64>().ok())
    {
        return Ok(hours * 60 * 60);
    }

    if let Some(minutes) = value
        .strip_prefix("PT")
        .and_then(|rest| rest.strip_suffix('M'))
        .and_then(|number| number.parse::<u64>().ok())
    {
        return Ok(minutes * 60);
    }

    if let Some(seconds) = value
        .strip_prefix("PT")
        .and_then(|rest| rest.strip_suffix('S'))
        .and_then(|number| number.parse::<u64>().ok())
    {
        return Ok(seconds);
    }

    Err(LsdcError::PolicyCompile(format!(
        "unsupported ISO-8601 duration `{value}`"
    )))
}

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn dedupe_vec<T>(items: Vec<T>) -> Vec<T>
where
    T: PartialEq,
{
    let mut deduped = Vec::new();
    for item in items {
        if !deduped.iter().any(|existing| existing == &item) {
            deduped.push(item);
        }
    }
    deduped
}
