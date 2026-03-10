use crate::crypto::{ReceiptKind, Sha256Hash};
use lsdc_policy::CsvTransformManifest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvTransformProofInput {
    pub agreement_id: String,
    pub odrl_policy: Value,
    pub manifest: CsvTransformManifest,
    pub input_csv: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement_commitment_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_nonce_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_result_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_commitment_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_statement_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_receipt_hashes: Vec<Sha256Hash>,
    #[serde(default)]
    pub recursion_depth: u32,
    #[serde(default)]
    pub receipt_kind: ReceiptKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvTransformProofJournal {
    pub agreement_id: String,
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub policy_hash: Sha256Hash,
    pub transform_manifest_hash: Sha256Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement_commitment_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_nonce_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_result_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_commitment_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_statement_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_receipt_hashes: Vec<Sha256Hash>,
    #[serde(default)]
    pub recursion_depth: u32,
    #[serde(default)]
    pub receipt_kind: ReceiptKind,
}
