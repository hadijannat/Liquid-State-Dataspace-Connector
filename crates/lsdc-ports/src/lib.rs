use async_trait::async_trait;
use lsdc_common::crypto::{
    PriceDecision, PricingAuditContext, ProofBundle, ProvenanceReceipt, ShapleyValue,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::execution::{ProofBackend, TeeBackend};
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementHandle {
    pub id: String,
    pub interface: String,
    pub session_port: u16,
    pub active: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofExecutionResult {
    pub output_csv: Vec<u8>,
    pub receipt: ProvenanceReceipt,
    pub recursion_used: bool,
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
