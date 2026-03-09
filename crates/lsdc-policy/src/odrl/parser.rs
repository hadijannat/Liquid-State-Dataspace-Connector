use super::ast::PolicyAgreement;
use crate::error::{LsdcError, Result};
use crate::liquid::{
    CsvTransformOpKind, EvidenceRequirement, LiquidPolicyIr, RuntimeGuard, TransformGuard,
    TransportGuard, TransportProtocol,
};
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
    let permissions = policy
        .get("permission")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            LsdcError::OdrlParse("ODRL policy must contain a permission array".into())
        })?;

    if permissions.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "ODRL policy must contain at least one permission".into(),
        ));
    }

    if policy
        .get("prohibition")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        return Err(LsdcError::PolicyCompile(
            "prototype ODRL subset does not support prohibitions".into(),
        ));
    }

    let mut allow_read = false;
    let mut allow_transfer = false;
    let mut allow_anonymize = false;
    let mut packet_caps = Vec::new();
    let mut allowed_regions = Vec::new();
    let mut allowed_purposes = Vec::new();
    let mut required_ops = Vec::new();
    let mut delete_after_seconds = None;

    for permission in permissions {
        for action in parse_actions(permission.get("action"))? {
            match action.as_str() {
                "read" => allow_read = true,
                "transfer" => allow_transfer = true,
                "anonymize" => allow_anonymize = true,
                other => {
                    return Err(LsdcError::PolicyCompile(format!(
                        "unsupported ODRL action `{other}`"
                    )))
                }
            }
        }

        if let Some(constraints) = permission.get("constraint").and_then(Value::as_array) {
            for constraint in constraints {
                let operand = required_string(constraint, "leftOperand")?;
                match operand.as_str() {
                    "count" => packet_caps.push(parse_u64_right_operand(constraint)?),
                    "spatial" => extend_unique(
                        &mut allowed_regions,
                        parse_string_list_right_operand(constraint)?,
                    ),
                    "purpose" => extend_unique(
                        &mut allowed_purposes,
                        parse_string_list_right_operand(constraint)?,
                    ),
                    other => {
                        return Err(LsdcError::PolicyCompile(format!(
                            "unsupported ODRL constraint `{other}`"
                        )))
                    }
                }
            }
        }

        if let Some(duties) = permission.get("duty").and_then(Value::as_array) {
            for duty in duties {
                let action = parse_action_value(duty.get("action"))?;
                match action.as_str() {
                    "delete" => {
                        let constraint = duty
                            .get("constraint")
                            .and_then(Value::as_array)
                            .and_then(|items| items.first())
                            .ok_or_else(|| {
                                LsdcError::PolicyCompile(
                                    "delete duty must contain a constraint".into(),
                                )
                            })?;
                        let operand = required_string(constraint, "leftOperand")?;
                        if operand != "delete-after" {
                            return Err(LsdcError::PolicyCompile(format!(
                                "unsupported delete duty operand `{operand}`"
                            )));
                        }
                        delete_after_seconds = Some(parse_duration_seconds(&required_string(
                            constraint,
                            "rightOperand",
                        )?)?);
                    }
                    "anonymize" => {
                        allow_anonymize = true;
                        let constraint = duty
                            .get("constraint")
                            .and_then(Value::as_array)
                            .and_then(|items| items.first())
                            .ok_or_else(|| {
                                LsdcError::PolicyCompile(
                                    "anonymize duty must contain a constraint".into(),
                                )
                            })?;
                        let operand = required_string(constraint, "leftOperand")?;
                        if operand != "transform-required" {
                            return Err(LsdcError::PolicyCompile(format!(
                                "unsupported anonymize duty operand `{operand}`"
                            )));
                        }
                        required_ops.push(parse_transform_kind(&required_string(
                            constraint,
                            "rightOperand",
                        )?)?);
                    }
                    other => {
                        return Err(LsdcError::PolicyCompile(format!(
                            "unsupported ODRL duty action `{other}`"
                        )))
                    }
                }
            }
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
            byte_cap: None,
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
            delete_after_seconds,
            evidence_requirements: dedupe_vec(evidence_requirements.to_vec()),
            approval_required: evidence_requirements
                .iter()
                .any(|item| item == &EvidenceRequirement::PriceApproval),
        },
    })
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

fn parse_actions(value: Option<&Value>) -> Result<Vec<String>> {
    let value = value.ok_or_else(|| {
        LsdcError::OdrlParse("permission must declare an action in the prototype subset".into())
    })?;

    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| parse_action_value(Some(item)))
            .collect(),
        _ => Ok(vec![parse_action_value(Some(value))?]),
    }
}

fn parse_action_value(value: Option<&Value>) -> Result<String> {
    let value = value.ok_or_else(|| LsdcError::OdrlParse("missing action value".into()))?;
    match value {
        Value::String(action) => Ok(action.to_ascii_lowercase()),
        Value::Object(map) => {
            if let Some(action) = map.get("type").and_then(Value::as_str) {
                Ok(action.to_ascii_lowercase())
            } else if let Some(action) = map.get("value").and_then(Value::as_str) {
                Ok(action.to_ascii_lowercase())
            } else {
                Err(LsdcError::OdrlParse(
                    "action objects must declare `type` or `value`".into(),
                ))
            }
        }
        _ => Err(LsdcError::OdrlParse(
            "action must be a string or action object".into(),
        )),
    }
}

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| LsdcError::OdrlParse(format!("missing string field `{field}`")))
}

fn parse_string_list_right_operand(value: &Value) -> Result<Vec<String>> {
    let right_operand = value
        .get("rightOperand")
        .ok_or_else(|| LsdcError::OdrlParse("missing `rightOperand`".into()))?;

    match right_operand {
        Value::String(item) => Ok(vec![item.to_owned()]),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    LsdcError::OdrlParse("string array expected for `rightOperand`".into())
                })
            })
            .collect(),
        _ => Err(LsdcError::OdrlParse(
            "`rightOperand` must be a string or array of strings".into(),
        )),
    }
}

fn parse_u64_right_operand(value: &Value) -> Result<u64> {
    value
        .get("rightOperand")
        .and_then(Value::as_u64)
        .ok_or_else(|| LsdcError::OdrlParse("`rightOperand` must be an unsigned integer".into()))
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
