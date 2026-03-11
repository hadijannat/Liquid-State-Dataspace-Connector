use super::ast::PolicyAgreement;
use crate::error::{LsdcError, Result};
use crate::liquid::{
    CsvTransformOpKind, EvidenceRequirement, LiquidPolicyIr, RuntimeGuard, TransformGuard,
    TransportGuard, TransportProtocol,
};
use crate::profile::{
    canonical_policy_json, normalize_policy, NormalizedConstraintExpr, NormalizedConstraintLeaf,
    NormalizedDuty, NormalizedLogicalOperator, NormalizedPolicy, NormalizedRule,
};
use serde_json::Value;
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
    lower_normalized_policy(&normalized, evidence_requirements)
}

pub fn lower_normalized_policy(
    normalized_policy: &NormalizedPolicy,
    evidence_requirements: &[EvidenceRequirement],
) -> Result<LiquidPolicyIr> {
    if !normalized_policy.prohibitions.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "executable lowering does not support prohibition rules".into(),
        ));
    }
    if !normalized_policy.obligations.is_empty() {
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
    let mut delete_after_seconds = None;

    for permission in &normalized_policy.permissions {
        lower_permission_actions(
            permission,
            &mut allow_read,
            &mut allow_transfer,
            &mut allow_anonymize,
        );
        lower_permission_constraints(
            permission,
            &mut packet_caps,
            &mut byte_caps,
            &mut allowed_regions,
            &mut allowed_purposes,
        )?;
        lower_permission_duties(
            permission,
            &mut allow_anonymize,
            &mut required_ops,
            &mut delete_after_seconds,
        )?;
    }

    allowed_regions.sort();
    allowed_regions.dedup();
    allowed_purposes.sort();
    allowed_purposes.dedup();

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
            valid_until: normalized_policy.valid_until,
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

fn lower_permission_actions(
    permission: &NormalizedRule,
    allow_read: &mut bool,
    allow_transfer: &mut bool,
    allow_anonymize: &mut bool,
) {
    for action in &permission.actions {
        match action.as_str() {
            "read" => *allow_read = true,
            "transfer" => *allow_transfer = true,
            "anonymize" => *allow_anonymize = true,
            _ => {}
        }
    }
}

fn lower_permission_constraints(
    permission: &NormalizedRule,
    packet_caps: &mut Vec<u64>,
    byte_caps: &mut Vec<u64>,
    allowed_regions: &mut Vec<String>,
    allowed_purposes: &mut Vec<String>,
) -> Result<()> {
    for constraint in &permission.constraints {
        collect_constraint_values(
            constraint,
            packet_caps,
            byte_caps,
            allowed_regions,
            allowed_purposes,
        )?;
    }
    Ok(())
}

fn collect_constraint_values(
    constraint: &NormalizedConstraintExpr,
    packet_caps: &mut Vec<u64>,
    byte_caps: &mut Vec<u64>,
    allowed_regions: &mut Vec<String>,
    allowed_purposes: &mut Vec<String>,
) -> Result<()> {
    match constraint {
        NormalizedConstraintExpr::Leaf(leaf) => match leaf.left_operand.as_str() {
            "count" => packet_caps.push(parse_u64_operand(leaf)?),
            "maxEgressBytes" => byte_caps.push(parse_u64_operand(leaf)?),
            "spatial" => extend_unique(allowed_regions, parse_string_list_operand(leaf)?),
            "purpose" => extend_unique(allowed_purposes, parse_string_list_operand(leaf)?),
            _ => {}
        },
        NormalizedConstraintExpr::Logical(logical) => {
            if logical.op != NormalizedLogicalOperator::And {
                return Err(LsdcError::PolicyCompile(format!(
                    "executable lowering does not support logical `{}` groups",
                    logical_operator_name(logical.op)
                )));
            }
            for child in &logical.children {
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

fn lower_permission_duties(
    permission: &NormalizedRule,
    allow_anonymize: &mut bool,
    required_ops: &mut Vec<CsvTransformOpKind>,
    delete_after_seconds: &mut Option<u64>,
) -> Result<()> {
    for duty in &permission.duties {
        lower_duty(duty, allow_anonymize, required_ops, delete_after_seconds)?;
    }
    Ok(())
}

fn lower_duty(
    duty: &NormalizedDuty,
    allow_anonymize: &mut bool,
    required_ops: &mut Vec<CsvTransformOpKind>,
    delete_after_seconds: &mut Option<u64>,
) -> Result<()> {
    match duty.action.as_str() {
        "anonymize" => *allow_anonymize = true,
        "delete" => {}
        other => {
            return Err(LsdcError::PolicyCompile(format!(
                "unsupported executable duty action `{other}`"
            )))
        }
    }

    collect_duty_values(
        duty.action.as_str(),
        &duty.constraints,
        allow_anonymize,
        required_ops,
        delete_after_seconds,
    )
}

fn collect_duty_values(
    action: &str,
    constraints: &[NormalizedConstraintExpr],
    allow_anonymize: &mut bool,
    required_ops: &mut Vec<CsvTransformOpKind>,
    delete_after_seconds: &mut Option<u64>,
) -> Result<()> {
    if action == "anonymize" {
        *allow_anonymize = true;
    }

    for constraint in constraints {
        match constraint {
            NormalizedConstraintExpr::Leaf(leaf) => match (action, leaf.left_operand.as_str()) {
                ("delete", "delete-after") => {
                    let duration = parse_duration_seconds(&parse_string_operand(leaf)?)?;
                    *delete_after_seconds = Some(match *delete_after_seconds {
                        Some(current) => current.min(duration),
                        None => duration,
                    });
                }
                ("anonymize", "transform-required") => {
                    required_ops.push(parse_transform_kind(&parse_string_operand(leaf)?)?);
                }
                _ => {}
            },
            NormalizedConstraintExpr::Logical(logical) => {
                if logical.op != NormalizedLogicalOperator::And {
                    return Err(LsdcError::PolicyCompile(format!(
                        "executable lowering does not support logical `{}` groups",
                        logical_operator_name(logical.op)
                    )));
                }
                collect_duty_values(
                    action,
                    &logical.children,
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
    serde_json::to_vec(&canonical_policy_json(value))
}

fn parse_u64_operand(leaf: &NormalizedConstraintLeaf) -> Result<u64> {
    leaf.right_operand
        .as_ref()
        .and_then(Value::as_u64)
        .ok_or_else(|| LsdcError::OdrlParse("`rightOperand` must be an unsigned integer".into()))
}

fn parse_string_operand(leaf: &NormalizedConstraintLeaf) -> Result<String> {
    leaf.right_operand
        .as_ref()
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            LsdcError::OdrlParse("`rightOperand` must be a string for this operand".into())
        })
}

fn parse_string_list_operand(leaf: &NormalizedConstraintLeaf) -> Result<Vec<String>> {
    let right_operand = leaf
        .right_operand
        .as_ref()
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
        NormalizedLogicalOperator::AndSequence => "andSequence",
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
