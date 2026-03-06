use lsdc_common::dsp::{ContractAgreement, ContractOffer, ContractRequest};
use lsdc_common::error::Result;
use lsdc_common::odrl::ast::PolicyId;

/// Handles Dataspace Protocol contract negotiation.
#[derive(Default)]
pub struct NegotiationEngine;

impl NegotiationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Process an incoming contract request from a consumer.
    pub async fn handle_request(&self, request: ContractRequest) -> Result<ContractOffer> {
        tracing::info!(
            consumer = %request.consumer_id,
            "Received contract request"
        );

        Ok(ContractOffer {
            provider_id: request.policy.provider.clone(),
            offer_id: uuid::Uuid::new_v4().to_string(),
            policy: request.policy,
        })
    }

    /// Finalize a contract agreement.
    pub async fn finalize(&self, offer: ContractOffer) -> Result<ContractAgreement> {
        let agreement_id = PolicyId::new();
        tracing::info!(agreement_id = %agreement_id.0, "Contract finalized");

        Ok(ContractAgreement {
            agreement_id,
            policy: offer.policy,
        })
    }
}
