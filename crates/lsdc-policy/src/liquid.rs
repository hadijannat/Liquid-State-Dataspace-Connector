use crate::error::{LsdcError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRequirement {
    ProvenanceReceipt,
    AttestationDocument,
    ProofOfForgetting,
    PriceApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidPolicyIr {
    pub transport_guard: TransportGuard,
    pub transform_guard: TransformGuard,
    pub runtime_guard: RuntimeGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportGuard {
    pub allow_read: bool,
    pub allow_transfer: bool,
    pub packet_cap: Option<u64>,
    pub byte_cap: Option<u64>,
    pub allowed_regions: Vec<String>,
    pub valid_until: Option<DateTime<Utc>>,
    pub protocol: TransportProtocol,
    pub session_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransformGuard {
    pub allow_anonymize: bool,
    pub allowed_purposes: Vec<String>,
    pub required_ops: Vec<CsvTransformOpKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeGuard {
    pub delete_after_seconds: Option<u64>,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CsvTransformOpKind {
    DropColumns,
    RedactColumns,
    HashColumns,
    RowFilter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CsvTransformOp {
    DropColumns {
        columns: Vec<String>,
    },
    RedactColumns {
        columns: Vec<String>,
        replacement: String,
    },
    HashColumns {
        columns: Vec<String>,
        salt: String,
    },
    RowFilter {
        column: String,
        equals: String,
    },
}

impl CsvTransformOp {
    pub fn kind(&self) -> CsvTransformOpKind {
        match self {
            Self::DropColumns { .. } => CsvTransformOpKind::DropColumns,
            Self::RedactColumns { .. } => CsvTransformOpKind::RedactColumns,
            Self::HashColumns { .. } => CsvTransformOpKind::HashColumns,
            Self::RowFilter { .. } => CsvTransformOpKind::RowFilter,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsvTransformManifest {
    pub dataset_id: String,
    pub purpose: String,
    pub ops: Vec<CsvTransformOp>,
}

pub fn validate_transform_manifest(
    policy: &LiquidPolicyIr,
    manifest: &CsvTransformManifest,
) -> Result<()> {
    if !policy.transform_guard.allowed_purposes.is_empty()
        && !policy
            .transform_guard
            .allowed_purposes
            .iter()
            .any(|purpose| purpose == &manifest.purpose)
    {
        return Err(LsdcError::PolicyCompile(format!(
            "purpose `{}` is not allowed by the policy",
            manifest.purpose
        )));
    }

    if !manifest.ops.is_empty() && !policy.transform_guard.allow_anonymize {
        return Err(LsdcError::PolicyCompile(
            "the policy does not allow anonymize transforms".into(),
        ));
    }

    let actual_kinds: Vec<CsvTransformOpKind> =
        manifest.ops.iter().map(CsvTransformOp::kind).collect();
    for required in &policy.transform_guard.required_ops {
        if !actual_kinds.iter().any(|kind| kind == required) {
            return Err(LsdcError::PolicyCompile(format!(
                "required transform `{required:?}` is missing from the manifest"
            )));
        }
    }

    Ok(())
}
