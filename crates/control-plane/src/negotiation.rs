use lsdc_common::dsp::{ContractAgreement, ContractOffer, ContractRequest};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::ExecutionProfile;
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::odrl::parser::{lower_policy, policy_hash_hex};

#[derive(Default)]
pub struct NegotiationEngine;

pub struct NegotiatedAgreement {
    pub agreement: ContractAgreement,
    pub execution_profile: ExecutionProfile,
}

impl NegotiationEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn handle_request(&self, request: ContractRequest) -> Result<ContractOffer> {
        let computed_hash = policy_hash_hex(&request.odrl_policy)?;
        if !request.policy_hash.is_empty() && request.policy_hash != computed_hash {
            return Err(LsdcError::PolicyCompile(
                "request policy hash does not match raw ODRL JSON".into(),
            ));
        }

        lower_policy(&request.odrl_policy, &request.evidence_requirements)?;

        Ok(ContractOffer {
            provider_id: request.provider_id,
            consumer_id: request.consumer_id,
            offer_id: uuid::Uuid::new_v4().to_string(),
            asset_id: request.asset_id,
            odrl_policy: request.odrl_policy,
            policy_hash: computed_hash,
            evidence_requirements: request.evidence_requirements,
        })
    }

    pub async fn finalize(&self, offer: ContractOffer) -> Result<ContractAgreement> {
        Ok(self.finalize_profiled(offer).await?.agreement)
    }

    pub async fn finalize_profiled(&self, offer: ContractOffer) -> Result<NegotiatedAgreement> {
        let agreement_id = PolicyId::new();
        let liquid_policy = lower_policy(&offer.odrl_policy, &offer.evidence_requirements)?;
        let agreement = ContractAgreement {
            agreement_id,
            asset_id: offer.asset_id,
            provider_id: offer.provider_id,
            consumer_id: offer.consumer_id,
            odrl_policy: offer.odrl_policy,
            policy_hash: offer.policy_hash,
            evidence_requirements: offer.evidence_requirements,
            liquid_policy,
        };

        Ok(NegotiatedAgreement {
            execution_profile: ExecutionProfile::from_agreement(&agreement),
            agreement,
        })
    }
}
