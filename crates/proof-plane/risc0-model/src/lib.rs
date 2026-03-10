use lsdc_common::crypto::{ReceiptKind, Sha256Hash};
use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};
use lsdc_common::proof::CsvTransformProofJournal as LegacyCsvTransformProofJournal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Risc0ReceiptMethod {
    LegacyTransform,
    RecursiveTransform,
    Composition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptAssumptionWitness {
    pub method: Risc0ReceiptMethod,
    pub image_id: [u32; 8],
    pub journal_bytes: Vec<u8>,
    pub receipt_bytes: Vec<u8>,
    pub receipt_hash: Sha256Hash,
    pub receipt_kind: ReceiptKind,
    pub recursion_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Risc0CsvTransformOp {
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

impl From<&CsvTransformOp> for Risc0CsvTransformOp {
    fn from(value: &CsvTransformOp) -> Self {
        match value {
            CsvTransformOp::DropColumns { columns } => Self::DropColumns {
                columns: columns.clone(),
            },
            CsvTransformOp::RedactColumns {
                columns,
                replacement,
            } => Self::RedactColumns {
                columns: columns.clone(),
                replacement: replacement.clone(),
            },
            CsvTransformOp::HashColumns { columns, salt } => Self::HashColumns {
                columns: columns.clone(),
                salt: salt.clone(),
            },
            CsvTransformOp::RowFilter { column, equals } => Self::RowFilter {
                column: column.clone(),
                equals: equals.clone(),
            },
        }
    }
}

impl From<Risc0CsvTransformOp> for CsvTransformOp {
    fn from(value: Risc0CsvTransformOp) -> Self {
        match value {
            Risc0CsvTransformOp::DropColumns { columns } => Self::DropColumns { columns },
            Risc0CsvTransformOp::RedactColumns {
                columns,
                replacement,
            } => Self::RedactColumns {
                columns,
                replacement,
            },
            Risc0CsvTransformOp::HashColumns { columns, salt } => {
                Self::HashColumns { columns, salt }
            }
            Risc0CsvTransformOp::RowFilter { column, equals } => Self::RowFilter { column, equals },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risc0CsvTransformManifest {
    pub dataset_id: String,
    pub purpose: String,
    pub ops: Vec<Risc0CsvTransformOp>,
}

impl From<&CsvTransformManifest> for Risc0CsvTransformManifest {
    fn from(value: &CsvTransformManifest) -> Self {
        Self {
            dataset_id: value.dataset_id.clone(),
            purpose: value.purpose.clone(),
            ops: value.ops.iter().map(Risc0CsvTransformOp::from).collect(),
        }
    }
}

impl From<Risc0CsvTransformManifest> for CsvTransformManifest {
    fn from(value: Risc0CsvTransformManifest) -> Self {
        Self {
            dataset_id: value.dataset_id,
            purpose: value.purpose,
            ops: value.ops.into_iter().map(CsvTransformOp::from).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveCsvTransformProofInput {
    pub agreement_id: String,
    pub manifest: Risc0CsvTransformManifest,
    pub input_csv: Vec<u8>,
    pub policy_hash: Sha256Hash,
    pub agreement_commitment_hash: Option<Sha256Hash>,
    pub session_id: Option<String>,
    pub challenge_nonce_hash: Option<Sha256Hash>,
    pub selector_hash: Option<Sha256Hash>,
    pub attestation_result_hash: Option<Sha256Hash>,
    pub capability_commitment_hash: Option<Sha256Hash>,
    pub transparency_statement_hash: Option<Sha256Hash>,
    pub prior_receipt: Option<ReceiptAssumptionWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCompositionContext {
    pub agreement_id: String,
    pub agreement_commitment_hash: Option<Sha256Hash>,
    pub session_id: Option<String>,
    pub selector_hash: Option<Sha256Hash>,
    pub capability_commitment_hash: Option<Sha256Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCompositionProofInput {
    pub context: ReceiptCompositionContext,
    pub child_receipts: Vec<ReceiptAssumptionWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveCsvTransformProofJournal {
    pub agreement_id: String,
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub policy_hash: Sha256Hash,
    pub transform_manifest_hash: Sha256Hash,
    pub prior_receipt_hash: Option<Sha256Hash>,
    pub agreement_commitment_hash: Option<Sha256Hash>,
    pub session_id: Option<String>,
    pub challenge_nonce_hash: Option<Sha256Hash>,
    pub selector_hash: Option<Sha256Hash>,
    pub attestation_result_hash: Option<Sha256Hash>,
    pub capability_commitment_hash: Option<Sha256Hash>,
    pub transparency_statement_hash: Option<Sha256Hash>,
    pub parent_receipt_hashes: Vec<Sha256Hash>,
    pub recursion_depth: u32,
    pub receipt_kind: ReceiptKind,
}

impl From<LegacyCsvTransformProofJournal> for RecursiveCsvTransformProofJournal {
    fn from(value: LegacyCsvTransformProofJournal) -> Self {
        Self {
            agreement_id: value.agreement_id,
            input_hash: value.input_hash,
            output_hash: value.output_hash,
            policy_hash: value.policy_hash,
            transform_manifest_hash: value.transform_manifest_hash,
            prior_receipt_hash: None,
            agreement_commitment_hash: value.agreement_commitment_hash,
            session_id: value.session_id,
            challenge_nonce_hash: value.challenge_nonce_hash,
            selector_hash: value.selector_hash,
            attestation_result_hash: value.attestation_result_hash,
            capability_commitment_hash: value.capability_commitment_hash,
            transparency_statement_hash: value.transparency_statement_hash,
            parent_receipt_hashes: value.parent_receipt_hashes,
            recursion_depth: value.recursion_depth,
            receipt_kind: value.receipt_kind,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedWitnessReceipt {
    pub method: Risc0ReceiptMethod,
    pub journal: RecursiveCsvTransformProofJournal,
    pub receipt_hash: Sha256Hash,
}
