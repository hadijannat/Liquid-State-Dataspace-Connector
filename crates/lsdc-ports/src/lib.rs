use async_trait::async_trait;
use lsdc_common::crypto::{
    PriceDecision, PricingAuditContext, ProofBundle, ProvenanceReceipt, ShapleyValue,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::execution::{ProofBackend, TeeBackend, TransportBackend, TransportSelector};
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::Result;
use lsdc_evidence::{
    AttestationDocument, ChainVerification, DevDeletionEvidence, ReceiptEnvelopeV1, VerifiedClaims,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementIdentity {
    pub agreement_id: String,
    pub enforcement_key: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedTransportGuard {
    pub selector: TransportSelector,
    pub enforcement: EnforcementIdentity,
    pub packet_cap: Option<u64>,
    pub byte_cap: Option<u64>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementRuntimeStatus {
    pub transport_backend: TransportBackend,
    pub rule_active: bool,
    pub kernel_program_attached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementHandle {
    pub id: String,
    pub interface: String,
    pub session_port: u16,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_selector: Option<TransportSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_transport: Option<ResolvedTransportGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<EnforcementRuntimeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementStatus {
    Active {
        packets_processed: u64,
        bytes_processed: u64,
        session_port: u16,
    },
    Expired,
    Revoked,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportExecutionPlan {
    pub agreement_id: String,
    pub enforcement_key: u32,
    pub transport_selector: TransportSelector,
    pub max_packets: Option<u64>,
    pub max_bytes: Option<u64>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TransportExecutionPlan {
    pub fn session_port(&self) -> u16 {
        self.transport_selector.port
    }

    pub fn resolved_transport(&self) -> ResolvedTransportGuard {
        ResolvedTransportGuard {
            selector: self.transport_selector.clone(),
            enforcement: EnforcementIdentity {
                agreement_id: self.agreement_id.clone(),
                enforcement_key: self.enforcement_key,
            },
            packet_cap: self.max_packets,
            byte_cap: self.max_bytes,
            expires_at: self.expires_at,
        }
    }
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    async fn enforce(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle>;
    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()>;
    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus>;
}

pub trait TransportPlanner: Send + Sync {
    fn plan(&self, agreement: &ContractAgreement) -> Result<TransportExecutionPlan>;
}

#[async_trait]
pub trait TransportRealizer: Send + Sync {
    async fn enforce(
        &self,
        plan: &TransportExecutionPlan,
        iface: &str,
    ) -> Result<EnforcementHandle>;
    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()>;
    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofExecutionResult {
    pub output_csv: Vec<u8>,
    pub receipt: ProvenanceReceipt,
    pub recursion_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformOutput {
    pub output_bytes: Vec<u8>,
    pub media_type: String,
}

pub trait TransformKernel: Send + Sync {
    fn execute(
        &self,
        input_bytes: &[u8],
        manifest: &CsvTransformManifest,
    ) -> Result<TransformOutput>;
}

pub struct ProofContext<'a> {
    pub agreement: &'a ContractAgreement,
    pub input_bytes: &'a [u8],
    pub output_bytes: &'a [u8],
    pub manifest: &'a CsvTransformManifest,
    pub prior_receipt: Option<&'a ReceiptEnvelopeV1>,
}

#[async_trait]
pub trait ReceiptBackend: Send + Sync {
    fn proof_backend(&self) -> ProofBackend;
    async fn prove(&self, ctx: ProofContext<'_>) -> Result<ReceiptEnvelopeV1>;
    async fn verify(&self, receipt: &ReceiptEnvelopeV1) -> Result<VerifiedClaims>;
    async fn verify_chain(&self, chain: &[ReceiptEnvelopeV1]) -> Result<ChainVerification>;
}

#[async_trait]
pub trait ProofEngine: Send + Sync {
    fn proof_backend(&self) -> ProofBackend;
    async fn execute_csv_transform(
        &self,
        agreement: &ContractAgreement,
        input_csv: &[u8],
        manifest: &CsvTransformManifest,
        prior_receipt: Option<&ProvenanceReceipt>,
    ) -> Result<ProofExecutionResult>;
    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool>;
    async fn verify_chain(&self, chain: &[ProvenanceReceipt]) -> Result<bool>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveJobRequest {
    pub agreement: ContractAgreement,
    pub input_csv: Vec<u8>,
    pub manifest: CsvTransformManifest,
    pub prior_receipt: Option<ProvenanceReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveJobResult {
    pub output_csv: Vec<u8>,
    pub proof_bundle: ProofBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub agreement_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveSession {
    pub session_id: String,
    pub tee_backend: TeeBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadRequest {
    pub agreement: ContractAgreement,
    pub input_bytes: Vec<u8>,
    pub manifest: CsvTransformManifest,
    pub prior_receipt: Option<ReceiptEnvelopeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadResult {
    pub output_bytes: Vec<u8>,
    pub attestation: Option<AttestationDocument>,
    pub deletion_evidence: Option<DevDeletionEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyEvidence {
    pub attestation: Option<AttestationDocument>,
    pub deletion_evidence: Option<DevDeletionEvidence>,
}

#[async_trait]
pub trait EnclaveSessionManager: Send + Sync {
    fn tee_backend(&self) -> TeeBackend;
    async fn open(&self, request: SessionRequest) -> Result<EnclaveSession>;
    async fn run(
        &self,
        session: &EnclaveSession,
        workload: WorkloadRequest,
    ) -> Result<WorkloadResult>;
    async fn destroy(&self, session: EnclaveSession) -> Result<DestroyEvidence>;
}

#[async_trait]
pub trait EnclaveManager: Send + Sync {
    fn tee_backend(&self) -> TeeBackend;
    async fn run_csv_job(&self, request: EnclaveJobRequest) -> Result<EnclaveJobResult>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetrics {
    pub loss_with_dataset: f64,
    pub loss_without_dataset: f64,
    pub accuracy_with_dataset: f64,
    pub accuracy_without_dataset: f64,
    pub model_run_id: String,
    pub metrics_window_started_at: chrono::DateTime<chrono::Utc>,
    pub metrics_window_ended_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PricingOracle: Send + Sync {
    async fn evaluate_utility(
        &self,
        audit_context: &PricingAuditContext,
        metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue>;
    async fn decide_price(
        &self,
        agreement_id: &str,
        current_price: f64,
        value: &ShapleyValue,
    ) -> Result<PriceDecision>;
}
