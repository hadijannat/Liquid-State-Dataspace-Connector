use crate::execution::{PricingMode, ProofBackend};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Hash(pub [u8; 32]);

impl Sha256Hash {
    pub fn digest_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut output = [0_u8; 32];
        output.copy_from_slice(&digest);
        Self(output)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Display for Sha256Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

pub fn canonical_json_bytes(value: &Value) -> std::result::Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&canonicalize_json(value))
}

pub fn hash_json(value: &Value) -> std::result::Result<Sha256Hash, serde_json::Error> {
    canonical_json_bytes(value).map(|bytes| Sha256Hash::digest_bytes(&bytes))
}

pub fn sign_bytes(secret: &str, bytes: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts all key sizes");
    mac.update(bytes);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_signature(secret: &str, bytes: &[u8], signature_hex: &str) -> bool {
    let Ok(signature) = hex::decode(signature_hex) else {
        return false;
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts all key sizes");
    mac.update(bytes);
    mac.verify_slice(&signature).is_ok()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceReceipt {
    pub agreement_id: String,
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub policy_hash: Sha256Hash,
    pub transform_manifest_hash: Sha256Hash,
    pub prior_receipt_hash: Option<Sha256Hash>,
    pub receipt_hash: Sha256Hash,
    pub proof_backend: ProofBackend,
    pub receipt_format_version: String,
    pub proof_method_id: String,
    pub receipt_bytes: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMeasurements {
    pub image_hash: Sha256Hash,
    pub pcrs: BTreeMap<u16, String>,
    pub debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub enclave_id: String,
    pub platform: String,
    pub binary_hash: Sha256Hash,
    pub measurements: AttestationMeasurements,
    pub document_hash: Sha256Hash,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub raw_attestation_document: Vec<u8>,
    pub certificate_chain_pem: Vec<String>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfForgetting {
    pub attestation: AttestationDocument,
    pub destruction_timestamp: chrono::DateTime<chrono::Utc>,
    pub data_hash: Sha256Hash,
    pub proof_hash: Sha256Hash,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub proof_backend: ProofBackend,
    pub receipt_format_version: String,
    pub proof_method_id: String,
    pub prior_receipt_hash: Option<Sha256Hash>,
    pub raw_receipt_bytes: Vec<u8>,
    pub provenance_receipt: ProvenanceReceipt,
    pub attestation: AttestationDocument,
    pub proof_of_forgetting: ProofOfForgetting,
    pub job_audit_hash: Sha256Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsWindow {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingAuditContext {
    pub dataset_id: String,
    pub transformed_asset_hash: String,
    pub proof_receipt_hash: Option<Sha256Hash>,
    pub model_run_id: String,
    pub metrics_window: MetricsWindow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapleyValue {
    pub dataset_id: String,
    pub transformed_asset_hash: String,
    pub marginal_contribution: f64,
    pub confidence: f64,
    pub algorithm_version: String,
    pub audit_context: PricingAuditContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceDecision {
    pub agreement_id: String,
    pub dataset_id: String,
    pub original_price: f64,
    pub adjusted_price: f64,
    pub approval_required: bool,
    pub pricing_mode: PricingMode,
    pub shapley_value: ShapleyValue,
    pub signed_by: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionProposal {
    pub subject_id: String,
    pub agreement_id: String,
    pub reason: String,
    pub approval_required: bool,
    pub evidence_hash: Sha256Hash,
}
