use crate::negotiation::{NegotiatedAgreement, NegotiationEngine};
use lsdc_common::dsp::{ContractAgreement, ContractOffer, ContractRequest};
use lsdc_common::error::Result;

#[derive(Default)]
pub struct AgreementService {
    negotiation: NegotiationEngine,
}

impl AgreementService {
    pub fn new() -> Self {
        Self {
            negotiation: NegotiationEngine::new(),
        }
    }

    pub async fn handle_request(&self, request: ContractRequest) -> Result<ContractOffer> {
        self.negotiation.handle_request(request).await
    }

    pub async fn finalize(&self, offer: ContractOffer) -> Result<ContractAgreement> {
        self.negotiation.finalize(offer).await
    }

    pub async fn finalize_profiled(&self, offer: ContractOffer) -> Result<NegotiatedAgreement> {
        self.negotiation.finalize_profiled(offer).await
    }
}
