use crate::canonical::{AttestedTeardownEvidence, DevDeletionEvidence};
use hmac::{Hmac, Mac};
use lsdc_policy::{PricingMode, ProofBackend};
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

    pub fn from_hex(hex_value: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_value).map_err(|err| err.to_string())?;
        if bytes.len() != 32 {
            return Err("sha256 hex must decode to 32 bytes".into());
        }

        let mut output = [0_u8; 32];
        output.copy_from_slice(&bytes);
        Ok(Self(output))
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
    pub receipt_hash: Sha256Hash,
    pub proof_backend: ProofBackend,
    pub receipt_format_version: String,
    pub proof_method_id: String,
    pub receipt_bytes: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    #[default]
    Transform,
    Composition,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data_hash: Option<Sha256Hash>,
    pub document_hash: Sha256Hash,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub raw_attestation_document: Vec<u8>,
    pub certificate_chain_pem: Vec<String>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppraisalStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub profile: String,
    pub doc_hash: Sha256Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub image_sha384: String,
    pub pcrs: BTreeMap<u8, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data_hash: Option<Sha256Hash>,
    pub cert_chain_verified: bool,
    pub freshness_ok: bool,
    pub appraisal: AppraisalStatus,
}

#[derive(Debug, Serialize)]
struct AttestationResultBinding<'a> {
    profile: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_sha384: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data_hash: Option<&'a Sha256Hash>,
    cert_chain_verified: bool,
    freshness_ok: bool,
    appraisal: AppraisalStatus,
}

pub fn attestation_result_binding_hash(
    result: &AttestationResult,
) -> std::result::Result<Sha256Hash, serde_json::Error> {
    let image_sha384 = if result.profile == "aws-nitro-live" {
        Some(result.image_sha384.as_str())
    } else {
        None
    };

    hash_json(&serde_json::to_value(AttestationResultBinding {
        profile: &result.profile,
        session_id: result.session_id.as_ref(),
        nonce: result.nonce.as_ref(),
        image_sha384,
        public_key: result.public_key.as_ref(),
        user_data_hash: result.user_data_hash.as_ref(),
        cert_chain_verified: result.cert_chain_verified,
        freshness_ok: result.freshness_ok,
        appraisal: result.appraisal,
    })?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub evidence_profile: String,
    pub document: AttestationDocument,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErasureMode {
    SessionTeardown,
    KeyRevocation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Dev,
    Attested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyErasureEvidence {
    pub session_id: String,
    pub attestation_result_hash: Sha256Hash,
    pub released_key_id: String,
    pub erasure_mode: ErasureMode,
    pub teardown_timestamp: chrono::DateTime<chrono::Utc>,
    pub evidence_class: EvidenceClass,
    pub evidence_hash: Sha256Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "evidence")]
pub enum TeardownEvidence {
    DevDeletion(DevDeletionEvidence),
    KeyErasure(KeyErasureEvidence),
    AttestedTeardown(AttestedTeardownEvidence),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_result: Option<AttestationResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_evidence: Option<TeardownEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_erasure_evidence: Option<KeyErasureEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_root_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_receipt_hash: Option<Sha256Hash>,
    pub job_audit_hash: Sha256Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidenceBundle {
    pub attestation_evidence: AttestationEvidence,
    pub provenance_receipt: ProvenanceReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_result: Option<AttestationResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_evidence: Option<TeardownEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_receipt_hash: Option<Sha256Hash>,
    pub evidence_root_hash: Sha256Hash,
    pub job_audit_hash: Sha256Hash,
}

impl ExecutionEvidenceBundle {
    pub fn into_legacy_proof_bundle(self) -> ProofBundle {
        let legacy_deletion_evidence = match self.teardown_evidence.clone() {
            Some(TeardownEvidence::DevDeletion(evidence)) => evidence,
            Some(TeardownEvidence::KeyErasure(evidence)) => DevDeletionEvidence {
                attestation: self.attestation_evidence.document.clone(),
                destruction_timestamp: evidence.teardown_timestamp,
                data_hash: self.provenance_receipt.input_hash.clone(),
                proof_hash: evidence.evidence_hash.clone(),
                signature_hex: evidence.evidence_hash.to_hex(),
            },
            Some(TeardownEvidence::AttestedTeardown(evidence)) => DevDeletionEvidence {
                attestation: evidence.attestation,
                destruction_timestamp: evidence.teardown_timestamp,
                data_hash: evidence.data_hash,
                proof_hash: evidence.teardown_hash,
                signature_hex: evidence.attestation_anchor.unwrap_or_default(),
            },
            None => DevDeletionEvidence {
                attestation: self.attestation_evidence.document.clone(),
                destruction_timestamp: chrono::Utc::now(),
                data_hash: self.provenance_receipt.input_hash.clone(),
                proof_hash: self.job_audit_hash.clone(),
                signature_hex: self.job_audit_hash.to_hex(),
            },
        };
        let proof_of_forgetting = ProofOfForgetting {
            attestation: legacy_deletion_evidence.attestation.clone(),
            destruction_timestamp: legacy_deletion_evidence.destruction_timestamp,
            data_hash: legacy_deletion_evidence.data_hash.clone(),
            proof_hash: legacy_deletion_evidence.proof_hash.clone(),
            signature_hex: legacy_deletion_evidence.signature_hex.clone(),
        };
        let key_erasure_evidence = match self.teardown_evidence.clone() {
            Some(TeardownEvidence::KeyErasure(evidence)) => Some(evidence),
            _ => None,
        };

        ProofBundle {
            proof_backend: self.provenance_receipt.proof_backend,
            receipt_format_version: self.provenance_receipt.receipt_format_version.clone(),
            proof_method_id: self.provenance_receipt.proof_method_id.clone(),
            prior_receipt_hash: self.provenance_receipt.prior_receipt_hash.clone(),
            raw_receipt_bytes: self.provenance_receipt.receipt_bytes.clone(),
            provenance_receipt: self.provenance_receipt,
            attestation: self.attestation_evidence.document,
            proof_of_forgetting,
            attestation_result: self.attestation_result,
            teardown_evidence: self.teardown_evidence,
            key_erasure_evidence,
            evidence_root_hash: Some(self.evidence_root_hash),
            transparency_receipt_hash: self.transparency_receipt_hash,
            job_audit_hash: self.job_audit_hash,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation_result(doc_seed: &[u8]) -> AttestationResult {
        AttestationResult {
            profile: "aws-nitro-dev".into(),
            doc_hash: Sha256Hash::digest_bytes(doc_seed),
            session_id: Some("session-1".into()),
            nonce: Some("nonce-1".into()),
            image_sha384: "11".repeat(48),
            pcrs: BTreeMap::from([(0, "aa".repeat(48))]),
            public_key: Some(vec![1, 2, 3, 4]),
            user_data_hash: Some(Sha256Hash::digest_bytes(b"selector")),
            cert_chain_verified: true,
            freshness_ok: true,
            appraisal: AppraisalStatus::Accepted,
        }
    }

    #[test]
    fn test_attestation_result_binding_hash_ignores_document_hash() {
        let first = attestation_result(b"doc-a");
        let second = attestation_result(b"doc-b");

        assert_ne!(first.doc_hash, second.doc_hash);
        assert_eq!(
            attestation_result_binding_hash(&first).unwrap(),
            attestation_result_binding_hash(&second).unwrap()
        );
    }

    #[test]
    fn test_attestation_result_binding_hash_ignores_dynamic_pcrs() {
        let first = attestation_result(b"doc-a");
        let mut second = attestation_result(b"doc-a");
        second.pcrs.insert(2, "bb".repeat(48));

        assert_ne!(first.pcrs, second.pcrs);
        assert_eq!(
            attestation_result_binding_hash(&first).unwrap(),
            attestation_result_binding_hash(&second).unwrap()
        );
    }

    #[test]
    fn test_attestation_result_binding_hash_ignores_dev_image_projection() {
        let first = attestation_result(b"doc-a");
        let mut second = attestation_result(b"doc-a");
        second.image_sha384 = "22".repeat(48);

        assert_eq!(
            attestation_result_binding_hash(&first).unwrap(),
            attestation_result_binding_hash(&second).unwrap()
        );
    }

    #[test]
    fn test_attestation_result_binding_hash_keeps_live_image_binding() {
        let mut first = attestation_result(b"doc-a");
        first.profile = "aws-nitro-live".into();
        let mut second = first.clone();
        second.image_sha384 = "22".repeat(48);

        assert_ne!(
            attestation_result_binding_hash(&first).unwrap(),
            attestation_result_binding_hash(&second).unwrap()
        );
    }
}
