use chrono::{DateTime, Utc};
use lsdc_evidence::{canonical_json_bytes, Sha256Hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const LSDC_EXECUTION_PROTOCOL_VERSION: &str = "lsdc-execution-overlay/v1";
pub const LOCAL_TRANSPARENCY_PROFILE: &str = "lsdc-local-merkle-v1";
pub const HASH_ALGORITHM_SHA256: &str = "sha-256";
pub const LSDC_POLICY_COMMITMENT_PROFILE_V1: &str = "lsdc.policy.v1";
pub const LSDC_POLICY_COMMITMENT_PROFILE_V2: &str = "lsdc.policy.v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum TruthfulnessMode {
    #[default]
    Permissive,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupportLevel {
    Implemented,
    Experimental,
    ModeledOnly,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyMode {
    #[default]
    Required,
    Optional,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProofCompositionMode {
    #[default]
    None,
    Dag,
    Recursive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedProfiles {
    pub attestation_profile: String,
    pub proof_profile: String,
    pub transparency_profile: String,
    pub teardown_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCapabilityDescriptor {
    pub overlay_version: String,
    pub truthfulness_default: TruthfulnessMode,
    pub advertised_profiles: AdvertisedProfiles,
    pub support: BTreeMap<String, CapabilitySupportLevel>,
}

impl ExecutionCapabilityDescriptor {
    pub fn canonical_hash(&self) -> Result<Sha256Hash, serde_json::Error> {
        hash_canonical(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionEvidenceRequirements {
    pub challenge_nonce_required: bool,
    pub selector_hash_binding_required: bool,
    pub transparency_registration_mode: TransparencyMode,
    pub proof_composition_mode: ProofCompositionMode,
}

impl ExecutionEvidenceRequirements {
    pub fn canonical_hash(&self) -> Result<Sha256Hash, serde_json::Error> {
        hash_canonical(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOverlayCommitment {
    pub overlay_version: String,
    pub hash_alg: String,
    pub truthfulness_mode: TruthfulnessMode,
    #[serde(default = "default_policy_commitment_profile")]
    pub policy_commitment_profile: String,
    pub policy_commitment_hash: Sha256Hash,
    pub capability_descriptor_hash: Sha256Hash,
    pub evidence_requirements_hash: Sha256Hash,
    pub agreement_commitment_hash: Sha256Hash,
    pub capability_descriptor: ExecutionCapabilityDescriptor,
    pub evidence_requirements: ExecutionEvidenceRequirements,
}

impl ExecutionOverlayCommitment {
    pub fn build(
        agreement_id: &str,
        truthfulness_mode: TruthfulnessMode,
        policy_commitment_profile: impl Into<String>,
        policy_commitment_hash: Sha256Hash,
        capability_descriptor: ExecutionCapabilityDescriptor,
        evidence_requirements: ExecutionEvidenceRequirements,
    ) -> Result<Self, serde_json::Error> {
        let policy_commitment_profile = policy_commitment_profile.into();
        let capability_descriptor_hash = domain_hash(
            "lsdc.capability-descriptor.v1",
            &[&canonical_bytes(&capability_descriptor)?],
        );
        let evidence_requirements_hash = domain_hash(
            "lsdc.evidence-requirements.v1",
            &[&canonical_bytes(&evidence_requirements)?],
        );
        let agreement_commitment_hash = domain_hash(
            "lsdc.agreement-commitment.v1",
            &[
                agreement_id.as_bytes(),
                LSDC_EXECUTION_PROTOCOL_VERSION.as_bytes(),
                truthfulness_mode_commitment_bytes(truthfulness_mode),
                policy_commitment_profile.as_bytes(),
                &policy_commitment_hash.0,
                &capability_descriptor_hash.0,
                &evidence_requirements_hash.0,
            ],
        );

        Ok(Self {
            overlay_version: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
            hash_alg: HASH_ALGORITHM_SHA256.into(),
            truthfulness_mode,
            policy_commitment_profile,
            policy_commitment_hash,
            capability_descriptor_hash,
            evidence_requirements_hash,
            agreement_commitment_hash,
            capability_descriptor,
            evidence_requirements,
        })
    }
}

fn default_policy_commitment_profile() -> String {
    LSDC_POLICY_COMMITMENT_PROFILE_V1.into()
}

fn truthfulness_mode_commitment_bytes(mode: TruthfulnessMode) -> &'static [u8] {
    match mode {
        TruthfulnessMode::Permissive => br#""permissive""#,
        TruthfulnessMode::Strict => br#""strict""#,
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
#[serde(from = "ExecutionSessionCompat")]
pub struct ExecutionSession {
    pub session_id: Uuid,
    pub agreement_id: String,
    pub agreement_commitment_hash: Sha256Hash,
    pub capability_descriptor_hash: Sha256Hash,
    pub evidence_requirements_hash: Sha256Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_selector_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requester_ephemeral_pubkey: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_attestation_public_key_hash: Option<Sha256Hash>,
    pub state: ExecutionSessionState,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "ExecutionSessionChallengeCompat")]
pub struct ExecutionSessionChallenge {
    pub challenge_id: Uuid,
    pub agreement_hash: Sha256Hash,
    pub session_id: Uuid,
    pub challenge_nonce_hex: String,
    pub challenge_nonce_hash: Sha256Hash,
    pub resolved_selector_hash: Sha256Hash,
    pub requester_ephemeral_pubkey: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_attestation_public_key_hash: Option<Sha256Hash>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExecutionSessionCompat {
    session_id: Uuid,
    agreement_id: String,
    agreement_commitment_hash: Sha256Hash,
    capability_descriptor_hash: Sha256Hash,
    evidence_requirements_hash: Sha256Hash,
    #[serde(default)]
    resolved_selector_hash: Option<Sha256Hash>,
    #[serde(default)]
    requester_ephemeral_pubkey: Vec<u8>,
    #[serde(default)]
    expected_attestation_public_key_hash: Option<Sha256Hash>,
    #[serde(default)]
    expected_attestation_recipient_public_key: Option<Vec<u8>>,
    state: ExecutionSessionState,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl From<ExecutionSessionCompat> for ExecutionSession {
    fn from(value: ExecutionSessionCompat) -> Self {
        Self {
            session_id: value.session_id,
            agreement_id: value.agreement_id,
            agreement_commitment_hash: value.agreement_commitment_hash,
            capability_descriptor_hash: value.capability_descriptor_hash,
            evidence_requirements_hash: value.evidence_requirements_hash,
            resolved_selector_hash: value.resolved_selector_hash,
            requester_ephemeral_pubkey: value.requester_ephemeral_pubkey,
            expected_attestation_public_key_hash: normalize_expected_attestation_public_key_hash(
                value.expected_attestation_public_key_hash,
                value.expected_attestation_recipient_public_key,
            ),
            state: value.state,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ExecutionSessionChallengeCompat {
    challenge_id: Uuid,
    agreement_hash: Sha256Hash,
    session_id: Uuid,
    challenge_nonce_hex: String,
    challenge_nonce_hash: Sha256Hash,
    resolved_selector_hash: Sha256Hash,
    #[serde(default)]
    requester_ephemeral_pubkey: Vec<u8>,
    #[serde(default)]
    expected_attestation_public_key_hash: Option<Sha256Hash>,
    #[serde(default)]
    expected_attestation_recipient_public_key: Option<Vec<u8>>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    #[serde(default)]
    consumed_at: Option<DateTime<Utc>>,
}

impl From<ExecutionSessionChallengeCompat> for ExecutionSessionChallenge {
    fn from(value: ExecutionSessionChallengeCompat) -> Self {
        Self {
            challenge_id: value.challenge_id,
            agreement_hash: value.agreement_hash,
            session_id: value.session_id,
            challenge_nonce_hex: value.challenge_nonce_hex,
            challenge_nonce_hash: value.challenge_nonce_hash,
            resolved_selector_hash: value.resolved_selector_hash,
            requester_ephemeral_pubkey: value.requester_ephemeral_pubkey,
            expected_attestation_public_key_hash: normalize_expected_attestation_public_key_hash(
                value.expected_attestation_public_key_hash,
                value.expected_attestation_recipient_public_key,
            ),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            consumed_at: value.consumed_at,
        }
    }
}

impl ExecutionSessionChallenge {
    pub fn issue(
        session: &ExecutionSession,
        resolved_selector_hash: Sha256Hash,
        now: DateTime<Utc>,
    ) -> Self {
        let raw_nonce = format!(
            "{}:{}:{}",
            session.session_id,
            Uuid::new_v4(),
            now.timestamp_nanos_opt().unwrap_or_default()
        )
        .into_bytes();

        Self {
            challenge_id: Uuid::new_v4(),
            agreement_hash: session.agreement_commitment_hash.clone(),
            session_id: session.session_id,
            challenge_nonce_hex: hex::encode(&raw_nonce),
            challenge_nonce_hash: Sha256Hash::digest_bytes(&raw_nonce),
            resolved_selector_hash,
            requester_ephemeral_pubkey: session.requester_ephemeral_pubkey.clone(),
            expected_attestation_public_key_hash: session
                .expected_attestation_public_key_hash
                .clone(),
            issued_at: now,
            expires_at: session
                .expires_at
                .unwrap_or_else(|| now + chrono::Duration::minutes(15)),
            consumed_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSessionResult {
    pub session_id: Uuid,
    pub attestation_result_hash: Sha256Hash,
    pub proof_receipt_hash: Sha256Hash,
    pub transparency_receipt_hash: Option<Sha256Hash>,
    pub capability_descriptor_hash: Sha256Hash,
    pub evidence_root_hash: Sha256Hash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatementKind {
    AgreementCommitted,
    SessionCreated,
    ChallengeIssued,
    AttestationEvidenceReceived,
    AttestationAppraised,
    ProofReceiptRegistered,
    TeardownEvidenceRegistered,
    TransparencyAnchored,
    PriceDecisionRecorded,
    SettlementRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionStatement {
    pub statement_id: String,
    pub statement_hash: Sha256Hash,
    pub statement_kind: ExecutionStatementKind,
    pub agreement_id: String,
    pub session_id: Option<Uuid>,
    pub payload_hash: Sha256Hash,
    pub parent_hashes: Vec<Sha256Hash>,
    pub producer: String,
    pub profile: String,
    pub created_at: DateTime<Utc>,
}

impl ExecutionStatement {
    pub fn canonical_hash(&self) -> Result<Sha256Hash, serde_json::Error> {
        hash_canonical(&serde_json::json!({
            "statement_id": self.statement_id,
            "statement_kind": self.statement_kind,
            "agreement_id": self.agreement_id,
            "session_id": self.session_id,
            "payload_hash": self.payload_hash,
            "parent_hashes": self.parent_hashes,
            "producer": self.producer,
            "profile": self.profile,
            "created_at": self.created_at,
        }))
    }

    pub fn with_computed_hash(mut self) -> Result<Self, serde_json::Error> {
        self.statement_hash = self.canonical_hash()?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyReceipt {
    pub statement_id: String,
    pub receipt_profile: String,
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

pub fn domain_hash(tag: &str, segments: &[&[u8]]) -> Sha256Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tag.as_bytes());
    for segment in segments {
        bytes.extend_from_slice(segment);
    }
    Sha256Hash::digest_bytes(&bytes)
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    canonical_json_bytes(&serde_json::to_value(value)?)
}

pub fn hash_canonical<T: Serialize>(value: &T) -> Result<Sha256Hash, serde_json::Error> {
    Ok(Sha256Hash::digest_bytes(&canonical_bytes(value)?))
}

fn normalize_expected_attestation_public_key_hash(
    hash: Option<Sha256Hash>,
    legacy_public_key: Option<Vec<u8>>,
) -> Option<Sha256Hash> {
    hash.or_else(|| {
        legacy_public_key.map(|public_key| Sha256Hash::digest_bytes(public_key.as_slice()))
    })
}

#[cfg(test)]
mod tests {
    use super::{ExecutionSession, ExecutionSessionChallenge};
    use lsdc_evidence::Sha256Hash;

    fn hash_bytes(fill: u8) -> Vec<u8> {
        vec![fill; 32]
    }

    #[test]
    fn execution_session_accepts_legacy_attestation_pin_field() {
        let legacy_public_key = vec![7, 8, 9];
        let session: ExecutionSession = serde_json::from_value(serde_json::json!({
            "session_id": "5a5926b3-7c26-49b6-a8dd-757ca35a37cd",
            "agreement_id": "agreement-1",
            "agreement_commitment_hash": hash_bytes(0),
            "capability_descriptor_hash": hash_bytes(1),
            "evidence_requirements_hash": hash_bytes(2),
            "requester_ephemeral_pubkey": [1, 2, 3],
            "expected_attestation_recipient_public_key": legacy_public_key,
            "state": "created",
            "created_at": "2026-03-11T00:00:00Z",
            "expires_at": null
        }))
        .expect("legacy session should deserialize");

        assert_eq!(
            session.expected_attestation_public_key_hash,
            Some(Sha256Hash::digest_bytes(&[7, 8, 9]))
        );
    }

    #[test]
    fn execution_session_prefers_explicit_hash_over_legacy_attestation_pin_field() {
        let expected_hash = Sha256Hash::digest_bytes(b"expected-hash");
        let session: ExecutionSession = serde_json::from_value(serde_json::json!({
            "session_id": "5a5926b3-7c26-49b6-a8dd-757ca35a37cd",
            "agreement_id": "agreement-1",
            "agreement_commitment_hash": hash_bytes(0),
            "capability_descriptor_hash": hash_bytes(1),
            "evidence_requirements_hash": hash_bytes(2),
            "requester_ephemeral_pubkey": [1, 2, 3],
            "expected_attestation_public_key_hash": expected_hash,
            "expected_attestation_recipient_public_key": [7, 8, 9],
            "state": "created",
            "created_at": "2026-03-11T00:00:00Z",
            "expires_at": null
        }))
        .expect("session should prefer explicit hash");

        assert_eq!(
            session.expected_attestation_public_key_hash,
            Some(Sha256Hash::digest_bytes(b"expected-hash"))
        );
    }

    #[test]
    fn execution_session_challenge_accepts_legacy_attestation_pin_field() {
        let challenge: ExecutionSessionChallenge = serde_json::from_value(serde_json::json!({
            "challenge_id": "c9d6c1ba-f52f-4466-b585-72d3ff030b32",
            "agreement_hash": hash_bytes(3),
            "session_id": "5a5926b3-7c26-49b6-a8dd-757ca35a37cd",
            "challenge_nonce_hex": "abcd",
            "challenge_nonce_hash": hash_bytes(4),
            "resolved_selector_hash": hash_bytes(5),
            "requester_ephemeral_pubkey": [1, 2, 3],
            "expected_attestation_recipient_public_key": [9, 8, 7],
            "issued_at": "2026-03-11T00:00:00Z",
            "expires_at": "2026-03-11T00:15:00Z",
            "consumed_at": null
        }))
        .expect("legacy challenge should deserialize");

        assert_eq!(
            challenge.expected_attestation_public_key_hash,
            Some(Sha256Hash::digest_bytes(&[9, 8, 7]))
        );
        assert_eq!(challenge.challenge_nonce_hex, "abcd");
        assert_eq!(challenge.consumed_at, None);
    }

    #[test]
    fn execution_session_challenge_prefers_explicit_hash_over_legacy_attestation_pin_field() {
        let expected_hash = Sha256Hash::digest_bytes(b"expected-hash");
        let challenge: ExecutionSessionChallenge = serde_json::from_value(serde_json::json!({
            "challenge_id": "c9d6c1ba-f52f-4466-b585-72d3ff030b32",
            "agreement_hash": hash_bytes(3),
            "session_id": "5a5926b3-7c26-49b6-a8dd-757ca35a37cd",
            "challenge_nonce_hex": "abcd",
            "challenge_nonce_hash": hash_bytes(4),
            "resolved_selector_hash": hash_bytes(5),
            "requester_ephemeral_pubkey": [1, 2, 3],
            "expected_attestation_public_key_hash": expected_hash,
            "expected_attestation_recipient_public_key": [9, 8, 7],
            "issued_at": "2026-03-11T00:00:00Z",
            "expires_at": "2026-03-11T00:15:00Z",
            "consumed_at": null
        }))
        .expect("challenge should prefer explicit hash");

        assert_eq!(
            challenge.expected_attestation_public_key_hash,
            Some(Sha256Hash::digest_bytes(b"expected-hash"))
        );
    }
}
