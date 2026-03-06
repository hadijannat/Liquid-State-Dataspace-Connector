use crate::odrl::ast::{PolicyAgreement, PolicyId};
use serde::{Deserialize, Serialize};

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
    pub offer_id: String,
    pub policy: PolicyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractOffer {
    pub provider_id: String,
    pub offer_id: String,
    pub policy: PolicyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAgreement {
    pub agreement_id: PolicyId,
    pub policy: PolicyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub agreement_id: PolicyId,
    pub data_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStart {
    pub transfer_id: String,
    pub agreement_id: PolicyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCompletion {
    pub transfer_id: String,
}
