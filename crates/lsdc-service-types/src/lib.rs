use chrono::{DateTime, Utc};
use lsdc_common::crypto::{
    AttestationEvidence, AttestationResult, PriceDecision, ProofBundle, ProvenanceReceipt,
    SanctionProposal, Sha256Hash,
};
use lsdc_common::dsp::{ContractAgreement, ContractOffer, TransferStart};
use lsdc_common::execution::{
    ActualExecutionProfile, PolicyExecutionClassification, RequestedExecutionProfile,
};
use lsdc_common::execution_overlay::{
    CapabilitySupportLevel, ExecutionCapabilityDescriptor, ExecutionEvidenceRequirements,
    ExecutionSession, ExecutionSessionChallenge, ExecutionStatement, TransparencyReceipt,
};
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::runtime_model::EvidenceDag;
use lsdc_ports::{
    EnforcementHandle, EnforcementRuntimeStatus, EnforcementStatus, ExecutionBindings,
    ResolvedTransportGuard, TrainingMetrics,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeContractResponse {
    pub agreement: ContractAgreement,
    pub requested_profile: RequestedExecutionProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_execution: Option<PolicyExecutionClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_overlay: Option<ExecutionOverlaySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOverlaySummary {
    pub overlay_version: String,
    pub truthfulness_mode: lsdc_common::profile::TruthfulnessMode,
    pub capability_descriptor_hash: Sha256Hash,
    pub agreement_commitment_hash: Sha256Hash,
    pub evidence_requirements_hash: Sha256Hash,
    pub support_summary: std::collections::BTreeMap<String, CapabilitySupportLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCapabilitiesResponse {
    pub capability_descriptor: ExecutionCapabilityDescriptor,
    pub capability_descriptor_hash: Sha256Hash,
    pub evidence_requirements: ExecutionEvidenceRequirements,
    pub evidence_requirements_hash: Sha256Hash,
    pub strict_mode_supported: bool,
    pub dev_backends_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExecutionSessionRequest {
    pub agreement_id: String,
    #[serde(default)]
    pub requester_ephemeral_pubkey: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_attestation_recipient_public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExecutionSessionResponse {
    pub session: ExecutionSession,
    pub execution_overlay: ExecutionOverlaySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueExecutionChallengeResponse {
    pub session: ExecutionSession,
    pub challenge: ExecutionSessionChallenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueExecutionChallengeRequest {
    pub resolved_transport: ResolvedTransportGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAttestationEvidenceRequest {
    pub session_id: String,
    pub attestation_evidence: AttestationEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAttestationEvidenceResponse {
    pub session: ExecutionSession,
    pub attestation_evidence_hash: Sha256Hash,
    pub attestation_result: AttestationResult,
    pub attestation_result_hash: Sha256Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEvidenceStatementRequest {
    pub statement: ExecutionStatement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEvidenceStatementResponse {
    pub statement: ExecutionStatement,
    pub receipt: TransparencyReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEvidenceDagRequest {
    pub dag: EvidenceDag,
    #[serde(default)]
    pub receipts: Vec<TransparencyReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEvidenceDagResponse {
    pub valid: bool,
    pub checked_statement_count: usize,
    pub checked_receipt_count: usize,
    pub evidence_root_hash: Sha256Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStartResponse {
    pub transfer_start: TransferStart,
    pub enforcement_handle: EnforcementHandle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_execution: Option<PolicyExecutionClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_transport: Option<ResolvedTransportGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_runtime: Option<EnforcementRuntimeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageJobRequest {
    pub agreement: ContractAgreement,
    pub iface: Option<String>,
    pub input_csv_utf8: String,
    pub manifest: CsvTransformManifest,
    pub current_price: f64,
    pub metrics: TrainingMetrics,
    pub prior_receipt: Option<ProvenanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_bindings: Option<ExecutionBindings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LineageJobState {
    Pending,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageJobAccepted {
    pub job_id: String,
    pub state: LineageJobState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageJobResult {
    pub agreement_id: String,
    pub actual_execution_profile: ActualExecutionProfile,
    pub enforcement_handle: EnforcementHandle,
    pub enforcement_status: EnforcementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_execution: Option<PolicyExecutionClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_transport: Option<ResolvedTransportGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_runtime: Option<EnforcementRuntimeStatus>,
    pub transformed_csv_utf8: String,
    pub proof_bundle: ProofBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_root_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_receipt_hash: Option<Sha256Hash>,
    pub price_decision: PriceDecision,
    pub sanction_proposal: Option<SanctionProposal>,
    pub settlement_allowed: bool,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageJobRecord {
    pub job_id: String,
    pub agreement_id: String,
    pub state: LineageJobState,
    pub request: LineageJobRequest,
    pub result: Option<LineageJobResult>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerificationRequest {
    pub receipts: Vec<ProvenanceReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerificationResult {
    pub verified_backends: Vec<lsdc_common::execution::ProofBackend>,
    pub checked_receipt_count: usize,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementDecision {
    pub agreement_id: String,
    pub latest_job_id: Option<String>,
    pub settlement_allowed: bool,
    pub actual_execution_profile: Option<ActualExecutionProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_execution: Option<PolicyExecutionClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_transport: Option<ResolvedTransportGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_runtime: Option<EnforcementRuntimeStatus>,
    pub price_decision: Option<PriceDecision>,
    pub sanction_proposal: Option<SanctionProposal>,
    pub proof_bundle: Option<ProofBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_root_hash: Option<Sha256Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_receipt_hash: Option<Sha256Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRequestRecord {
    pub offer: ContractOffer,
    pub requested_profile: RequestedExecutionProfile,
}
