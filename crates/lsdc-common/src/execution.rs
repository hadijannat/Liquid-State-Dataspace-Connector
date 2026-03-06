use crate::dsp::{ContractAgreement, EvidenceRequirement};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TransportBackend {
    AyaXdp,
    Simulated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackend {
    None,
    DevReceipt,
    RiscZero,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TeeBackend {
    None,
    NitroDev,
    NitroLive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PricingMode {
    Disabled,
    Advisory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProfile {
    pub transport_backend: TransportBackend,
    pub proof_backend: ProofBackend,
    pub tee_backend: TeeBackend,
    pub pricing_mode: PricingMode,
}

impl ExecutionProfile {
    pub fn from_agreement(agreement: &ContractAgreement) -> Self {
        let has_transport = agreement.liquid_policy.transport_guard.allow_read
            || agreement.liquid_policy.transport_guard.allow_transfer;

        let has_provenance = agreement
            .evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::ProvenanceReceipt);
        let has_attestation = agreement.evidence_requirements.iter().any(|item| {
            matches!(
                item,
                EvidenceRequirement::AttestationDocument | EvidenceRequirement::ProofOfForgetting
            )
        });
        let has_pricing = agreement
            .evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::PriceApproval);

        Self {
            transport_backend: if has_transport {
                TransportBackend::AyaXdp
            } else {
                TransportBackend::Simulated
            },
            proof_backend: if has_provenance {
                ProofBackend::RiscZero
            } else {
                ProofBackend::None
            },
            tee_backend: if has_attestation {
                TeeBackend::NitroLive
            } else {
                TeeBackend::None
            },
            pricing_mode: if has_pricing {
                PricingMode::Advisory
            } else {
                PricingMode::Disabled
            },
        }
    }
}
