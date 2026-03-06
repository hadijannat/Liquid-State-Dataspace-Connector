use crate::crypto::{
    AttestationDocument, PriceAdjustment, ProofOfForgetting, ProvenanceReceipt, ShapleyValue,
};
use crate::error::Result;
use crate::odrl::ast::PolicyAgreement;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementHandle {
    pub id: String,
    pub interface: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementStatus {
    Active { packets_processed: u64 },
    Expired,
    Revoked,
    Error(String),
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    async fn enforce(&self, policy: &PolicyAgreement, iface: &str) -> Result<EnforcementHandle>;
    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()>;
    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformSpec {
    pub name: String,
    pub description: String,
}

#[async_trait]
pub trait ProofEngine: Send + Sync {
    async fn prove_transform(
        &self,
        input_hash: &[u8; 32],
        policy: &PolicyAgreement,
        transform: &TransformSpec,
    ) -> Result<ProvenanceReceipt>;
    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool>;
    async fn verify_chain(&self, chain: &[ProvenanceReceipt]) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct EnclaveSession {
    pub id: String,
    pub binary_hash: [u8; 32],
}

#[async_trait]
pub trait EnclaveManager: Send + Sync {
    async fn create_enclave(&self, binary_hash: &[u8; 32]) -> Result<EnclaveSession>;
    async fn attest(&self, session: &EnclaveSession) -> Result<AttestationDocument>;
    async fn destroy_and_prove(&self, session: EnclaveSession) -> Result<ProofOfForgetting>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetrics {
    pub loss_with_dataset: f64,
    pub loss_without_dataset: f64,
    pub accuracy_with_dataset: f64,
    pub accuracy_without_dataset: f64,
}

#[async_trait]
pub trait PricingOracle: Send + Sync {
    async fn evaluate_utility(
        &self,
        dataset_id: &str,
        metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue>;
    async fn renegotiate(
        &self,
        agreement_id: &str,
        value: &ShapleyValue,
    ) -> Result<PriceAdjustment>;
}
