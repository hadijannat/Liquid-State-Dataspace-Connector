use chrono::{DateTime, Utc};
use lsdc_evidence::{canonical_json_bytes, Sha256Hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const LSDC_EXECUTION_PROTOCOL_VERSION: &str = "lsdc-execution-overlay/v1";
pub const LOCAL_TRANSPARENCY_PROFILE: &str = "local-merkle-log/v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum TruthfulnessMode {
    #[default]
    Permissive,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectorSemantics {
    pub protocol_bound: bool,
    pub session_port_bound: bool,
    pub selector_hash_binding_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCapabilityDescriptor {
    pub protocol_version: String,
    pub attestation_profile: String,
    pub proof_profile: String,
    pub transparency_profile: String,
    pub key_release_profile: String,
    pub selector_semantics: SelectorSemantics,
    pub supported_clause_ids: Vec<String>,
    pub required_clause_set_hash: Sha256Hash,
}

impl ExecutionCapabilityDescriptor {
    pub fn canonical_hash(&self) -> Result<Sha256Hash, serde_json::Error> {
        hash_canonical(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOverlayCommitment {
    pub truthfulness_mode: TruthfulnessMode,
    pub policy_canonical_hash: Sha256Hash,
    pub capability_descriptor_hash: Sha256Hash,
    pub evidence_requirements_hash: Sha256Hash,
    pub agreement_commitment_hash: Sha256Hash,
    pub capability_descriptor: ExecutionCapabilityDescriptor,
}

impl ExecutionOverlayCommitment {
    pub fn build(
        truthfulness_mode: TruthfulnessMode,
        policy_canonical_hash: Sha256Hash,
        capability_descriptor: ExecutionCapabilityDescriptor,
        evidence_requirements_hash: Sha256Hash,
    ) -> Result<Self, serde_json::Error> {
        let capability_descriptor_hash = capability_descriptor.canonical_hash()?;
        let agreement_commitment_hash = hash_canonical(&serde_json::json!({
            "policy_canonical_hash": policy_canonical_hash,
            "capability_descriptor_hash": capability_descriptor_hash,
            "evidence_requirements_hash": evidence_requirements_hash,
            "truthfulness_mode": truthfulness_mode,
        }))?;

        Ok(Self {
            truthfulness_mode,
            policy_canonical_hash,
            capability_descriptor_hash,
            evidence_requirements_hash,
            agreement_commitment_hash,
            capability_descriptor,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSessionState {
    Created,
    Challenged,
    AttestationVerified,
    EvidenceRegistered,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSession {
    pub session_id: Uuid,
    pub agreement_id: String,
    pub agreement_commitment_hash: Sha256Hash,
    pub capability_commitment_hash: Sha256Hash,
    pub selector_hash: Sha256Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requester_ephemeral_pubkey: Vec<u8>,
    pub state: ExecutionSessionState,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSessionChallenge {
    pub agreement_hash: Sha256Hash,
    pub session_id: Uuid,
    pub challenge_nonce_hex: String,
    pub challenge_nonce_hash: Sha256Hash,
    pub selector_hash: Sha256Hash,
    pub requester_ephemeral_pubkey: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSessionResult {
    pub session_id: Uuid,
    pub attestation_result_hash: Sha256Hash,
    pub proof_receipt_hash: Sha256Hash,
    pub transparency_receipt_hash: Option<Sha256Hash>,
    pub capability_commitment_hash: Sha256Hash,
    pub evidence_root_hash: Sha256Hash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatementKind {
    NegotiatedAgreement,
    CapabilityCommitment,
    ExecutionSession,
    AttestationResult,
    ProofReceipt,
    TransparencyReceipt,
    KeyErasureEvidence,
    PriceDecision,
    SettlementRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionStatement {
    pub statement_id: String,
    pub agreement_id: String,
    pub session_id: Option<Uuid>,
    pub kind: ExecutionStatementKind,
    pub subject_hash: Sha256Hash,
    pub parent_hashes: Vec<Sha256Hash>,
    pub created_at: DateTime<Utc>,
    pub payload_hash: Sha256Hash,
}

impl ExecutionStatement {
    pub fn canonical_hash(&self) -> Result<Sha256Hash, serde_json::Error> {
        hash_canonical(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyReceipt {
    pub statement_id: String,
    pub log_id: String,
    pub statement_hash: Sha256Hash,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root_hash: Sha256Hash,
    pub inclusion_path: Vec<Sha256Hash>,
    pub consistency_proof: Vec<Sha256Hash>,
    pub signature_hex: String,
    pub signed_at: DateTime<Utc>,
}

impl TransparencyReceipt {
    pub fn canonical_hash(&self) -> Result<Sha256Hash, serde_json::Error> {
        hash_canonical(self)
    }
}

pub fn clause_set_hash(clauses: &[String]) -> Result<Sha256Hash, serde_json::Error> {
    let mut sorted = clauses.to_vec();
    sorted.sort();
    sorted.dedup();
    hash_canonical(&sorted)
}

pub fn hash_canonical<T: Serialize>(value: &T) -> Result<Sha256Hash, serde_json::Error> {
    Ok(Sha256Hash::digest_bytes(&canonical_json_bytes(
        &serde_json::to_value(value)?,
    )?))
}
