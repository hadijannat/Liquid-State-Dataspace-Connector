use lsdc_policy::{AgreementExecutionView, LiquidPolicyIr, PolicyId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use lsdc_policy::{EvidenceRequirement, TransportProtocol};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DspMessage {
    CatalogRequest(CatalogRequest),
    ContractRequest(ContractRequest),
    ContractOffer(ContractOffer),
    ContractAgreement(ContractAgreement),
    TransferRequest(TransferRequest),
    TransferStart(TransferStart),
    TransferCompletion(TransferCompletion),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogRequest {
    pub consumer_id: String,
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRequest {
    pub consumer_id: String,
    pub provider_id: String,
    pub offer_id: String,
    pub asset_id: String,
    pub odrl_policy: Value,
    pub policy_hash: String,
    pub evidence_requirements: Vec<EvidenceRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractOffer {
    pub provider_id: String,
    pub consumer_id: String,
    pub offer_id: String,
    pub asset_id: String,
    pub odrl_policy: Value,
    pub policy_hash: String,
    pub evidence_requirements: Vec<EvidenceRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAgreement {
    pub agreement_id: PolicyId,
    pub asset_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub odrl_policy: Value,
    pub policy_hash: String,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub liquid_policy: LiquidPolicyIr,
}

impl AgreementExecutionView for ContractAgreement {
    fn liquid_policy(&self) -> &LiquidPolicyIr {
        &self.liquid_policy
    }

    fn evidence_requirements(&self) -> &[EvidenceRequirement] {
        &self.evidence_requirements
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub agreement_id: PolicyId,
    pub data_address: String,
    pub protocol: TransportProtocol,
    pub session_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStart {
    pub transfer_id: String,
    pub agreement_id: PolicyId,
    pub protocol: TransportProtocol,
    pub session_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCompletion {
    pub transfer_id: String,
}
