use crate::crypto::{PriceDecision, ProofBundle, ProvenanceReceipt, SanctionProposal};
use crate::dsp::{ContractAgreement, ContractOffer, TransferStart};
use crate::execution::{ActualExecutionProfile, RequestedExecutionProfile};
use crate::liquid::CsvTransformManifest;
use crate::traits::{EnforcementHandle, EnforcementStatus, TrainingMetrics};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeContractResponse {
    pub agreement: ContractAgreement,
    pub requested_profile: RequestedExecutionProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStartResponse {
    pub transfer_start: TransferStart,
    pub enforcement_handle: EnforcementHandle,
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
    pub transformed_csv_utf8: String,
    pub proof_bundle: ProofBundle,
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
    pub proof_backend: crate::execution::ProofBackend,
    pub checked_receipt_count: usize,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementDecision {
    pub agreement_id: String,
    pub latest_job_id: Option<String>,
    pub settlement_allowed: bool,
    pub actual_execution_profile: Option<ActualExecutionProfile>,
    pub price_decision: Option<PriceDecision>,
    pub sanction_proposal: Option<SanctionProposal>,
    pub proof_bundle: Option<ProofBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRequestRecord {
    pub offer: ContractOffer,
    pub requested_profile: RequestedExecutionProfile,
}
