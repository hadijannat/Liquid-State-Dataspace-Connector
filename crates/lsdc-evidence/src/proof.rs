use crate::crypto::Sha256Hash;
use lsdc_policy::CsvTransformManifest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvTransformProofInput {
    pub agreement_id: String,
    pub odrl_policy: Value,
    pub manifest: CsvTransformManifest,
    pub input_csv: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvTransformProofJournal {
    pub agreement_id: String,
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub policy_hash: Sha256Hash,
    pub transform_manifest_hash: Sha256Hash,
    pub output_csv: Vec<u8>,
}
