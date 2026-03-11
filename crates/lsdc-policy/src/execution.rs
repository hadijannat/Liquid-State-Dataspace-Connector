use crate::liquid::{EvidenceRequirement, LiquidPolicyIr, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub trait AgreementExecutionView {
    fn liquid_policy(&self) -> &LiquidPolicyIr;
    fn evidence_requirements(&self) -> &[EvidenceRequirement];
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TransportSelector {
    pub protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClauseStatus {
    Executable,
    MetadataOnly,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyClauseClassification {
    pub clause: String,
    pub status: PolicyClauseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyExecutionClassification {
    pub clauses: Vec<PolicyClauseClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActualExecutionProfile {
    pub transport_backend: TransportBackend,
    pub proof_backend: ProofBackend,
    pub tee_backend: TeeBackend,
    pub pricing_mode: PricingMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedExecutionProfile {
    pub transport_profile: RequestedTransportProfile,
    pub proof_profile: RequestedProofProfile,
    pub tee_profile: RequestedTeeProfile,
    pub pricing_mode: PricingMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RequestedTransportProfile {
    None,
    GuardedTransfer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RequestedProofProfile {
    None,
    ProvenanceReceipt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RequestedTeeProfile {
    None,
    AttestedExecution,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCapabilityContext {
    pub transport_backend: TransportBackend,
    pub proof_backend: ProofBackend,
    pub tee_backend: TeeBackend,
    pub dev_backends_allowed: bool,
    pub attested_key_release_supported: bool,
    pub attested_teardown_supported: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCapabilityLevel {
    Implemented,
    Experimental,
    ModeledOnly,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProofCompositionMode {
    #[default]
    None,
    Dag,
    Recursive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAdvertisedProfiles {
    pub attestation_profile: String,
    pub proof_profile: String,
    pub transparency_profile: String,
    pub teardown_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCapabilitySemantics {
    pub support: BTreeMap<String, RuntimeCapabilityLevel>,
    pub advertised_profiles: RuntimeAdvertisedProfiles,
    pub proof_composition_mode: RuntimeProofCompositionMode,
    pub classification: PolicyExecutionClassification,
}

impl RequestedExecutionProfile {
    pub fn from_policy(
        policy: &LiquidPolicyIr,
        evidence_requirements: &[EvidenceRequirement],
    ) -> Self {
        let has_transport =
            policy.transport_guard.allow_read || policy.transport_guard.allow_transfer;

        let has_provenance = evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::ProvenanceReceipt);
        let has_attestation = evidence_requirements.iter().any(|item| {
            matches!(
                item,
                EvidenceRequirement::AttestationDocument | EvidenceRequirement::ProofOfForgetting
            )
        });
        let has_pricing = evidence_requirements
            .iter()
            .any(|item| item == &EvidenceRequirement::PriceApproval);

        Self {
            transport_profile: if has_transport {
                RequestedTransportProfile::GuardedTransfer
            } else {
                RequestedTransportProfile::None
            },
            proof_profile: if has_provenance {
                RequestedProofProfile::ProvenanceReceipt
            } else {
                RequestedProofProfile::None
            },
            tee_profile: if has_attestation {
                RequestedTeeProfile::AttestedExecution
            } else {
                RequestedTeeProfile::None
            },
            pricing_mode: if has_pricing {
                PricingMode::Advisory
            } else {
                PricingMode::Disabled
            },
        }
    }

    pub fn from_agreement(agreement: &impl AgreementExecutionView) -> Self {
        Self::from_policy(agreement.liquid_policy(), agreement.evidence_requirements())
    }
}

impl PolicyExecutionClassification {
    pub fn classify_policy(
        policy: &LiquidPolicyIr,
        evidence_requirements: &[EvidenceRequirement],
        transport_backend: TransportBackend,
        proof_backend: ProofBackend,
        tee_backend: TeeBackend,
    ) -> Self {
        let mut classification = Self::default();
        let transport = &policy.transport_guard;
        let transform = &policy.transform_guard;
        let runtime = &policy.runtime_guard;

        classification.push_when(
            transport.allow_read,
            "transport.allow_read",
            PolicyClauseStatus::Executable,
            Some("enforced through admission on the resolved transport selector"),
        );
        classification.push_when(
            transport.allow_transfer,
            "transport.allow_transfer",
            PolicyClauseStatus::Executable,
            Some("enforced through admission on the resolved transport selector"),
        );
        classification.push_when(
            transport.packet_cap.is_some(),
            "transport.packet_cap",
            PolicyClauseStatus::Executable,
            Some("compiled into transport counters"),
        );
        classification.push_when(
            transport.byte_cap.is_some(),
            "transport.byte_cap",
            PolicyClauseStatus::Executable,
            Some("compiled into transport counters"),
        );
        classification.push_when(
            transport.valid_until.is_some(),
            "transport.valid_until",
            PolicyClauseStatus::Executable,
            Some("drives enforcement expiry teardown"),
        );
        classification.push_when(
            transport.allow_read || transport.allow_transfer,
            "transport.protocol",
            PolicyClauseStatus::Executable,
            Some(match transport_backend {
                TransportBackend::AyaXdp => "resolved into a protocol-aware XDP selector",
                TransportBackend::Simulated => "resolved into a protocol-aware simulated selector",
            }),
        );
        classification.push_when(
            transport.allow_read || transport.allow_transfer,
            "transport.session_port",
            PolicyClauseStatus::Executable,
            Some("explicit when negotiated, otherwise derived at transfer activation"),
        );
        classification.push_when(
            !transport.allowed_regions.is_empty(),
            "transport.allowed_regions",
            PolicyClauseStatus::MetadataOnly,
            Some("negotiated metadata only; current transport backends do not geofence traffic"),
        );

        classification.push_when(
            transform.allow_anonymize,
            "transform.allow_anonymize",
            PolicyClauseStatus::Executable,
            Some("bounded to deterministic CSV manifest execution"),
        );
        classification.push_when(
            !transform.allowed_purposes.is_empty(),
            "transform.allowed_purposes",
            PolicyClauseStatus::Executable,
            Some("validated before protected transform execution"),
        );
        classification.push_when(
            !transform.required_ops.is_empty(),
            "transform.required_ops",
            PolicyClauseStatus::Executable,
            Some("validated against the submitted transform manifest"),
        );

        classification.push_when(
            runtime.delete_after_seconds.is_some(),
            "runtime.delete_after_seconds",
            if tee_backend == TeeBackend::None {
                PolicyClauseStatus::Rejected
            } else {
                PolicyClauseStatus::Executable
            },
            Some(match tee_backend {
                TeeBackend::None => "requested forgetting proof cannot run without a TEE backend",
                TeeBackend::NitroDev => {
                    "enforced via dev attestation and bounded proof-of-forgetting evidence"
                }
                TeeBackend::NitroLive => {
                    "enforced via Nitro-oriented proof-of-forgetting evidence with pinned measurements"
                }
            }),
        );

        for requirement in evidence_requirements {
            let clause = match requirement {
                EvidenceRequirement::ProvenanceReceipt => "runtime.evidence.provenance_receipt",
                EvidenceRequirement::AttestationDocument => "runtime.evidence.attestation_document",
                EvidenceRequirement::ProofOfForgetting => "runtime.evidence.proof_of_forgetting",
                EvidenceRequirement::PriceApproval => "runtime.evidence.price_approval",
            };
            let (status, detail) = match requirement {
                EvidenceRequirement::ProvenanceReceipt => {
                    if proof_backend == ProofBackend::None {
                        (
                            PolicyClauseStatus::Rejected,
                            "requested provenance evidence has no proof backend",
                        )
                    } else {
                        (
                            PolicyClauseStatus::Executable,
                            "receipt emitted by the configured proof backend",
                        )
                    }
                }
                EvidenceRequirement::AttestationDocument
                | EvidenceRequirement::ProofOfForgetting => {
                    if tee_backend == TeeBackend::None {
                        (
                            PolicyClauseStatus::Rejected,
                            "requested attestation evidence has no TEE backend",
                        )
                    } else {
                        (
                            PolicyClauseStatus::Executable,
                            "emitted by the configured TEE backend",
                        )
                    }
                }
                EvidenceRequirement::PriceApproval => (
                    PolicyClauseStatus::MetadataOnly,
                    "pricing remains advisory-only in this phase",
                ),
            };
            classification.push(clause, status, Some(detail));
        }

        if runtime.approval_required {
            classification.push(
                "runtime.approval_required",
                PolicyClauseStatus::MetadataOnly,
                Some("approval signals are recorded but do not mutate contracts or billing"),
            );
        }

        classification.push(
            "pricing.autonomous_mutation",
            PolicyClauseStatus::MetadataOnly,
            Some("pricing decisions are advisory-only and do not mutate contracts or ledgers"),
        );

        classification
    }

    pub fn classify_agreement(
        agreement: &impl AgreementExecutionView,
        transport_backend: TransportBackend,
        proof_backend: ProofBackend,
        tee_backend: TeeBackend,
    ) -> Self {
        Self::classify_policy(
            agreement.liquid_policy(),
            agreement.evidence_requirements(),
            transport_backend,
            proof_backend,
            tee_backend,
        )
    }

    pub fn for_runtime_capabilities(
        transport_backend: TransportBackend,
        proof_backend: ProofBackend,
        tee_backend: TeeBackend,
    ) -> Self {
        Self::from_runtime_capability_context(RuntimeCapabilityContext {
            transport_backend,
            proof_backend,
            tee_backend,
            dev_backends_allowed: false,
            attested_key_release_supported: false,
            attested_teardown_supported: false,
        })
    }

    pub fn from_runtime_capability_context(context: RuntimeCapabilityContext) -> Self {
        runtime_capability_semantics(context).classification
    }

    fn push(
        &mut self,
        clause: impl Into<String>,
        status: PolicyClauseStatus,
        detail: Option<&str>,
    ) {
        self.clauses.push(PolicyClauseClassification {
            clause: clause.into(),
            status,
            detail: detail.map(ToOwned::to_owned),
        });
    }

    fn push_when(
        &mut self,
        condition: bool,
        clause: impl Into<String>,
        status: PolicyClauseStatus,
        detail: Option<&str>,
    ) {
        if condition {
            self.push(clause, status, detail);
        }
    }
}

pub fn runtime_capability_semantics(context: RuntimeCapabilityContext) -> RuntimeCapabilitySemantics {
    use RuntimeCapabilityLevel::{Experimental, Implemented, ModeledOnly, Unsupported};

    let risc0_recursive_supported = context.proof_backend == ProofBackend::RiscZero;
    let support = BTreeMap::from([
        (
            "attestation.nitro_dev".into(),
            if context.tee_backend == TeeBackend::NitroDev {
                Implemented
            } else {
                Unsupported
            },
        ),
        (
            "attestation.nitro_live_verified".into(),
            if context.tee_backend == TeeBackend::NitroLive {
                Experimental
            } else {
                Unsupported
            },
        ),
        (
            "key_release.kms_attested".into(),
            if context.attested_key_release_supported {
                Experimental
            } else if context.tee_backend == TeeBackend::NitroLive {
                ModeledOnly
            } else {
                Unsupported
            },
        ),
        (
            "proof.dev_receipt_dag".into(),
            if context.proof_backend == ProofBackend::DevReceipt {
                Implemented
            } else {
                Unsupported
            },
        ),
        (
            "proof.risc0_single_hop".into(),
            if risc0_recursive_supported {
                Implemented
            } else {
                Unsupported
            },
        ),
        (
            "proof.risc0_recursive".into(),
            if risc0_recursive_supported {
                Implemented
            } else {
                Unsupported
            },
        ),
        ("transparency.local_merkle".into(), Implemented),
        (
            "teardown.dev_deletion".into(),
            if context.dev_backends_allowed {
                Implemented
            } else {
                Experimental
            },
        ),
        (
            "teardown.kms_erasure".into(),
            if context.attested_teardown_supported {
                Experimental
            } else if context.tee_backend == TeeBackend::NitroLive {
                ModeledOnly
            } else {
                Unsupported
            },
        ),
    ]);

    let proof_composition_mode = match context.proof_backend {
        ProofBackend::DevReceipt => RuntimeProofCompositionMode::Dag,
        ProofBackend::RiscZero => RuntimeProofCompositionMode::Recursive,
        ProofBackend::None => RuntimeProofCompositionMode::None,
    };

    let advertised_profiles = RuntimeAdvertisedProfiles {
        attestation_profile: match context.tee_backend {
            TeeBackend::NitroDev => "nitro-dev-attestation-result-v1",
            TeeBackend::NitroLive => "nitro-live-attestation-result-v1",
            TeeBackend::None => "none",
        }
        .into(),
        proof_profile: match context.proof_backend {
            ProofBackend::DevReceipt => "dev-receipt-dag-v1",
            ProofBackend::RiscZero => "risc0-recursive-dag-v1",
            ProofBackend::None => "none",
        }
        .into(),
        transparency_profile: "lsdc-local-merkle-v1".into(),
        teardown_profile: if context.tee_backend == TeeBackend::NitroLive {
            "kms-key-erasure-v1"
        } else {
            "dev-deletion-v1"
        }
        .into(),
    };

    let mut classification = PolicyExecutionClassification::default();
    classification.push(
        "transport.selector",
        PolicyClauseStatus::Executable,
        Some(match context.transport_backend {
            TransportBackend::AyaXdp => {
                "protocol and destination port selectors are enforced by Aya/XDP"
            }
            TransportBackend::Simulated => {
                "protocol and destination port selectors are enforced by the simulated agent"
            }
        }),
    );
    classification.push(
        "transport.packet_cap",
        PolicyClauseStatus::Executable,
        Some("packet counters are supported by all current transport backends"),
    );
    classification.push(
        "transport.byte_cap",
        PolicyClauseStatus::Executable,
        Some("byte counters are supported by all current transport backends"),
    );
    classification.push(
        "transport.valid_until",
        PolicyClauseStatus::Executable,
        Some("agreement expiry dissolves the installed transport guard"),
    );
    classification.push(
        "transport.allowed_regions",
        PolicyClauseStatus::MetadataOnly,
        Some("no current backend provides transport geofencing"),
    );
    classification.push(
        "proof.recursive_rollups",
        match context.proof_backend {
            ProofBackend::RiscZero => PolicyClauseStatus::Executable,
            ProofBackend::DevReceipt => PolicyClauseStatus::MetadataOnly,
            ProofBackend::None => PolicyClauseStatus::Rejected,
        },
        Some(match context.proof_backend {
            ProofBackend::RiscZero => {
                "recursive transform chaining and receipt composition are implemented for the risc0 backend"
            }
            ProofBackend::DevReceipt => {
                "receipt chains verify lineage, but recursive zk rollups are not implemented"
            }
            ProofBackend::None => "no proof backend is configured",
        }),
    );
    classification.push(
        "tee.live_enclave_orchestration",
        PolicyClauseStatus::MetadataOnly,
        Some(match context.tee_backend {
            TeeBackend::NitroLive => {
                "Nitro live mode validates external attestation material and AWS-backed key release but does not orchestrate real enclave lifecycle"
            }
            TeeBackend::NitroDev => "Nitro dev mode emits deterministic local attestation",
            TeeBackend::None => "no TEE backend is configured",
        }),
    );
    classification.push(
        "pricing.autonomous_mutation",
        PolicyClauseStatus::MetadataOnly,
        Some("pricing decisions are advisory-only and do not mutate contracts or ledgers"),
    );
    classification.push(
        "overlay.transparency_receipts",
        PolicyClauseStatus::Executable,
        Some("the execution overlay can anchor local transparency receipts"),
    );
    classification.push(
        "overlay.truthfulness_modes",
        PolicyClauseStatus::Executable,
        Some("permissive and strict overlay truthfulness modes are recognized"),
    );

    RuntimeCapabilitySemantics {
        support,
        advertised_profiles,
        proof_composition_mode,
        classification,
    }
}
