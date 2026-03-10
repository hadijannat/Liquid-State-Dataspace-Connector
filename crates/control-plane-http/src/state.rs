use crate::job_runner::LineageJobRunner;
use control_plane::agreement_service::AgreementService;
use control_plane::orchestrator::Orchestrator;
use control_plane_store::Store;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use lsdc_common::crypto::{
    canonical_json_bytes, AppraisalStatus, AttestationEvidence, PriceDecision, ProvenanceReceipt,
    Sha256Hash,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::execution::{
    ActualExecutionProfile, PolicyExecutionClassification, PricingMode, ProofBackend, TeeBackend,
    TransportBackend,
};
use lsdc_common::execution_overlay::{
    domain_hash, AdvertisedProfiles, CapabilitySupportLevel, ExecutionCapabilityDescriptor,
    ExecutionEvidenceRequirements, ExecutionOverlayCommitment, ExecutionSession,
    ExecutionSessionChallenge, ExecutionSessionState, ExecutionStatement, ExecutionStatementKind,
    ProofCompositionMode, TransparencyMode, TransparencyReceipt,
    TruthfulnessMode as OverlayTruthfulnessMode, LOCAL_TRANSPARENCY_PROFILE,
    LSDC_EXECUTION_PROTOCOL_VERSION,
};
use lsdc_common::profile::{normalize_policy, RuntimeCapabilities, TruthfulnessMode};
use lsdc_common::runtime_model::{
    DependencyType, EvidenceDag, EvidenceEdge, EvidenceNode, NodeStatus,
};
use lsdc_ports::{
    AttestationVerifier, DataPlane, EnclaveManager, PricingOracle, ProofEngine,
    ResolvedTransportGuard,
};
use lsdc_service_types::{
    CreateExecutionSessionRequest, CreateExecutionSessionResponse, ExecutionCapabilitiesResponse,
    ExecutionOverlaySummary, IssueExecutionChallengeRequest, IssueExecutionChallengeResponse,
    SubmitAttestationEvidenceResponse,
};
#[cfg(feature = "risc0")]
use proof_plane_host::Risc0ProofEngine;
use receipt_log::LocalTransparencyLog;
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct BackendSummary {
    pub transport_backend: TransportBackend,
    pub proof_backend: ProofBackend,
    pub tee_backend: TeeBackend,
}

pub struct ApiStateInit {
    pub store: Store,
    pub node_name: String,
    pub liquid_agent: Arc<LiquidAgentGrpcClient>,
    pub proof_engine: Arc<dyn ProofEngine>,
    pub dev_receipt_verifier: Arc<dyn ProofEngine>,
    pub attestation_verifier: Arc<dyn AttestationVerifier>,
    pub enclave_manager: Arc<dyn EnclaveManager>,
    pub pricing_oracle: Arc<dyn PricingOracle>,
    pub default_interface: String,
    pub api_bearer_token: String,
    pub configured_backends: BackendSummary,
    pub actual_transport_backend: TransportBackend,
}

#[derive(Clone)]
pub struct ApiState {
    pub(crate) store: Store,
    pub(crate) node_name: String,
    pub(crate) agreement_service: Arc<AgreementService>,
    pub(crate) orchestrator: Arc<Orchestrator>,
    pub(crate) proof_engine: Arc<dyn ProofEngine>,
    pub(crate) dev_receipt_verifier: Arc<dyn ProofEngine>,
    pub(crate) attestation_verifier: Arc<dyn AttestationVerifier>,
    pub(crate) liquid_agent: Arc<LiquidAgentGrpcClient>,
    pub(crate) default_interface: String,
    pub(crate) api_bearer_token: Arc<str>,
    pub(crate) configured_backends: BackendSummary,
    pub(crate) actual_transport_backend: TransportBackend,
    pub(crate) actual_tee_backend: TeeBackend,
    pub(crate) transparency_log: Arc<LocalTransparencyLog>,
}

impl ApiState {
    pub fn new(init: ApiStateInit) -> Self {
        let ApiStateInit {
            store,
            node_name,
            liquid_agent,
            proof_engine,
            dev_receipt_verifier,
            attestation_verifier,
            enclave_manager,
            pricing_oracle,
            default_interface,
            api_bearer_token,
            configured_backends,
            actual_transport_backend,
        } = init;
        let actual_tee_backend = enclave_manager.tee_backend();
        let data_plane: Arc<dyn DataPlane> = liquid_agent.clone();
        let orchestrator = Arc::new(Orchestrator::with_full_stack(
            data_plane,
            enclave_manager,
            pricing_oracle,
        ));
        let transparency_log = Arc::new(LocalTransparencyLog::new(api_bearer_token.clone()));

        Self {
            store,
            node_name,
            agreement_service: Arc::new(AgreementService::new()),
            orchestrator,
            proof_engine,
            dev_receipt_verifier,
            attestation_verifier,
            liquid_agent,
            default_interface,
            api_bearer_token: api_bearer_token.into(),
            configured_backends,
            actual_transport_backend,
            actual_tee_backend,
            transparency_log,
        }
    }

    pub fn actual_execution_profile(&self, pricing_mode: PricingMode) -> ActualExecutionProfile {
        ActualExecutionProfile {
            transport_backend: self.actual_transport_backend,
            proof_backend: self.proof_engine.proof_backend(),
            tee_backend: self.actual_tee_backend,
            pricing_mode,
        }
    }

    pub fn actual_backends(&self) -> BackendSummary {
        BackendSummary {
            transport_backend: self.actual_transport_backend,
            proof_backend: self.proof_engine.proof_backend(),
            tee_backend: self.actual_tee_backend,
        }
    }

    pub fn policy_execution_for(
        &self,
        agreement: &ContractAgreement,
    ) -> PolicyExecutionClassification {
        PolicyExecutionClassification::classify_agreement(
            agreement,
            self.actual_transport_backend,
            self.proof_engine.proof_backend(),
            self.actual_tee_backend,
        )
    }

    pub fn health_payload(&self) -> serde_json::Value {
        let capabilities = self.execution_capabilities();
        serde_json::json!({
            "status": "ok",
            "node_name": &self.node_name,
            "configured_backends": self.configured_backends,
            "actual_backends": self.actual_backends(),
            "policy_truthfulness": PolicyExecutionClassification::for_runtime_capabilities(
                self.actual_transport_backend,
                self.proof_engine.proof_backend(),
                self.actual_tee_backend,
            ),
            "execution_overlay": capabilities,
            "enabled_features": {
                "risc0": cfg!(feature = "risc0")
            }
        })
    }

    pub fn runtime_capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            transport_backend: self.actual_transport_backend,
            proof_backend: self.proof_engine.proof_backend(),
            tee_backend: self.actual_tee_backend,
            transparency_supported: true,
            strict_mode_supported: true,
            dev_backends_allowed: allow_dev_defaults(),
            attested_key_release_supported: false,
            attested_teardown_supported: false,
        }
    }

    pub fn capability_support_summary(
        &self,
    ) -> std::collections::BTreeMap<String, CapabilitySupportLevel> {
        use CapabilitySupportLevel::{Experimental, Implemented, ModeledOnly, Unsupported};

        std::collections::BTreeMap::from([
            (
                "attestation.nitro_dev".into(),
                if self.actual_tee_backend == TeeBackend::NitroDev {
                    Implemented
                } else {
                    Unsupported
                },
            ),
            (
                "attestation.nitro_live_verified".into(),
                if self.actual_tee_backend == TeeBackend::NitroLive {
                    Experimental
                } else {
                    Unsupported
                },
            ),
            (
                "key_release.kms_attested".into(),
                if self.actual_tee_backend == TeeBackend::NitroLive {
                    ModeledOnly
                } else {
                    Unsupported
                },
            ),
            (
                "proof.dev_receipt_dag".into(),
                if self.proof_engine.proof_backend() == ProofBackend::DevReceipt {
                    Implemented
                } else {
                    Unsupported
                },
            ),
            (
                "proof.risc0_single_hop".into(),
                if self.proof_engine.proof_backend() == ProofBackend::RiscZero {
                    Experimental
                } else {
                    Unsupported
                },
            ),
            ("proof.risc0_recursive".into(), Unsupported),
            ("transparency.local_merkle".into(), Implemented),
            (
                "teardown.dev_deletion".into(),
                if allow_dev_defaults() {
                    Implemented
                } else {
                    Experimental
                },
            ),
            (
                "teardown.kms_erasure".into(),
                if self.actual_tee_backend == TeeBackend::NitroLive {
                    ModeledOnly
                } else {
                    Unsupported
                },
            ),
        ])
    }

    pub fn execution_evidence_requirements(&self) -> ExecutionEvidenceRequirements {
        ExecutionEvidenceRequirements {
            challenge_nonce_required: true,
            selector_hash_binding_required: true,
            transparency_registration_mode: TransparencyMode::Required,
            proof_composition_mode: match self.proof_engine.proof_backend() {
                ProofBackend::DevReceipt => ProofCompositionMode::Dag,
                ProofBackend::RiscZero | ProofBackend::None => ProofCompositionMode::None,
            },
        }
    }

    pub fn execution_capability_descriptor(
        &self,
    ) -> lsdc_common::error::Result<ExecutionCapabilityDescriptor> {
        Ok(ExecutionCapabilityDescriptor {
            overlay_version: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
            truthfulness_default: OverlayTruthfulnessMode::Permissive,
            advertised_profiles: AdvertisedProfiles {
                attestation_profile: match self.actual_tee_backend {
                    TeeBackend::NitroDev => "nitro-dev-attestation-result-v1",
                    TeeBackend::NitroLive => "nitro-live-attestation-result-v1",
                    TeeBackend::None => "none",
                }
                .into(),
                proof_profile: match self.proof_engine.proof_backend() {
                    ProofBackend::DevReceipt => "dev-receipt-dag-v1",
                    ProofBackend::RiscZero => "risc0-single-hop-v1",
                    ProofBackend::None => "none",
                }
                .into(),
                transparency_profile: LOCAL_TRANSPARENCY_PROFILE.into(),
                teardown_profile: if self.actual_tee_backend == TeeBackend::NitroLive {
                    "kms-key-erasure-v1"
                } else {
                    "dev-deletion-v1"
                }
                .into(),
            },
            support: self.capability_support_summary(),
        })
    }

    pub fn execution_capabilities(&self) -> ExecutionCapabilitiesResponse {
        let capability_descriptor = self
            .execution_capability_descriptor()
            .expect("capability descriptor should serialize");
        let capability_descriptor_hash = capability_descriptor
            .canonical_hash()
            .expect("capability descriptor should hash");
        let evidence_requirements = self.execution_evidence_requirements();
        let evidence_requirements_hash = evidence_requirements
            .canonical_hash()
            .expect("evidence requirements should hash");
        let runtime_capabilities = self.runtime_capabilities();

        ExecutionCapabilitiesResponse {
            capability_descriptor,
            capability_descriptor_hash,
            evidence_requirements,
            evidence_requirements_hash,
            strict_mode_supported: runtime_capabilities.strict_mode_supported,
            dev_backends_allowed: runtime_capabilities.dev_backends_allowed,
        }
    }

    pub fn execution_overlay_commitment_for(
        &self,
        agreement: &ContractAgreement,
    ) -> lsdc_common::error::Result<ExecutionOverlayCommitment> {
        let normalized_policy = normalize_policy(&agreement.odrl_policy)?;
        let policy_canonical_bytes = canonical_json_bytes(
            &serde_json::to_value(&normalized_policy)
                .map_err(lsdc_common::error::LsdcError::from)?,
        )
        .map_err(lsdc_common::error::LsdcError::from)?;
        let policy_canonical_hash = domain_hash("lsdc.policy.v1", &[&policy_canonical_bytes]);
        let capability_descriptor = self.execution_capability_descriptor()?;
        let evidence_requirements = self.execution_evidence_requirements();

        ExecutionOverlayCommitment::build(
            &agreement.agreement_id.0,
            map_truthfulness_mode(normalized_policy.truthfulness_mode),
            policy_canonical_hash,
            capability_descriptor,
            evidence_requirements,
        )
        .map_err(lsdc_common::error::LsdcError::from)
    }

    pub fn execution_overlay_for(
        &self,
        agreement: &ContractAgreement,
    ) -> lsdc_common::error::Result<ExecutionOverlaySummary> {
        let overlay = self.execution_overlay_commitment_for(agreement)?;
        Ok(ExecutionOverlaySummary {
            overlay_version: overlay.overlay_version,
            truthfulness_mode: map_truthfulness_mode_back(overlay.truthfulness_mode),
            capability_descriptor_hash: overlay.capability_descriptor_hash,
            agreement_commitment_hash: overlay.agreement_commitment_hash,
            evidence_requirements_hash: overlay.evidence_requirements_hash,
            support_summary: overlay.capability_descriptor.support,
        })
    }

    pub fn create_execution_session(
        &self,
        request: CreateExecutionSessionRequest,
    ) -> lsdc_common::error::Result<CreateExecutionSessionResponse> {
        let (agreement, _) = self
            .store
            .get_agreement(&request.agreement_id)?
            .ok_or_else(|| lsdc_common::error::LsdcError::Database("agreement not found".into()))?;
        let overlay = self
            .store
            .get_agreement_overlay(&request.agreement_id)?
            .unwrap_or(self.execution_overlay_for(&agreement)?);
        self.store
            .upsert_agreement_overlay(&request.agreement_id, &overlay)?;

        let now = chrono::Utc::now();
        let session = ExecutionSession {
            session_id: uuid::Uuid::new_v4(),
            agreement_id: request.agreement_id,
            agreement_commitment_hash: overlay.agreement_commitment_hash.clone(),
            capability_descriptor_hash: overlay.capability_descriptor_hash.clone(),
            evidence_requirements_hash: overlay.evidence_requirements_hash.clone(),
            resolved_selector_hash: None,
            requester_ephemeral_pubkey: request.requester_ephemeral_pubkey,
            state: ExecutionSessionState::Created,
            created_at: now,
            expires_at: request
                .expires_in_seconds
                .map(|seconds| now + chrono::Duration::seconds(seconds.max(1))),
        };
        self.store.upsert_execution_session(&session, None)?;

        Ok(CreateExecutionSessionResponse {
            session,
            execution_overlay: overlay,
        })
    }

    pub fn issue_execution_challenge(
        &self,
        session_id: &str,
        request: &IssueExecutionChallengeRequest,
    ) -> lsdc_common::error::Result<IssueExecutionChallengeResponse> {
        let (mut session, existing_challenge, _) = self
            .store
            .get_execution_session(session_id)?
            .ok_or_else(|| {
                lsdc_common::error::LsdcError::Database("execution session not found".into())
            })?;
        if existing_challenge.is_some() {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "execution session already has an active challenge".into(),
            ));
        }

        let now = chrono::Utc::now();
        let resolved_selector_hash = resolved_transport_hash(&request.resolved_transport)?;
        session.resolved_selector_hash = Some(resolved_selector_hash.clone());
        let challenge = ExecutionSessionChallenge::issue(&session, resolved_selector_hash, now);
        session.state = ExecutionSessionState::Challenged;
        self.store
            .update_execution_challenge(session_id, &session, &challenge)?;

        Ok(IssueExecutionChallengeResponse { session, challenge })
    }

    pub fn submit_attestation_evidence(
        &self,
        session_id: &str,
        attestation_evidence: &AttestationEvidence,
    ) -> lsdc_common::error::Result<SubmitAttestationEvidenceResponse> {
        let (mut session, challenge, _) = self
            .store
            .get_execution_session(session_id)?
            .ok_or_else(|| {
                lsdc_common::error::LsdcError::Database("execution session not found".into())
            })?;
        let mut challenge = challenge.ok_or_else(|| {
            lsdc_common::error::LsdcError::PolicyCompile(
                "execution session has no active challenge".into(),
            )
        })?;
        if challenge.consumed_at.is_some() {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "execution session challenge has already been consumed".into(),
            ));
        }
        let now = chrono::Utc::now();
        if challenge.expires_at < now {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "execution session challenge has expired".into(),
            ));
        }
        if challenge.agreement_hash != session.agreement_commitment_hash {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "execution session challenge agreement hash mismatch".into(),
            ));
        }
        let attestation_result = self
            .attestation_verifier
            .appraise_attestation_evidence(attestation_evidence, Some(&challenge))?;
        if attestation_result
            .session_id
            .as_deref()
            .is_some_and(|value| value != session_id)
        {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "attestation result session binding mismatch".into(),
            ));
        }
        if attestation_result
            .nonce
            .as_deref()
            .is_some_and(|value| value != challenge.challenge_nonce_hex)
        {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "attestation result nonce mismatch".into(),
            ));
        }
        if !challenge.requester_ephemeral_pubkey.is_empty()
            && attestation_result.public_key.as_deref()
                != Some(challenge.requester_ephemeral_pubkey.as_slice())
        {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "attestation result requester key binding mismatch".into(),
            ));
        }
        if attestation_result.user_data_hash.as_ref() != Some(&challenge.resolved_selector_hash) {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "attestation result resolved transport binding mismatch".into(),
            ));
        }
        if attestation_result.appraisal != AppraisalStatus::Accepted {
            return Err(lsdc_common::error::LsdcError::PolicyCompile(
                "attestation evidence appraisal rejected".into(),
            ));
        }
        let attestation_evidence_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(attestation_evidence)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        let attestation_result_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(&attestation_result)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        session.state = ExecutionSessionState::AttestationVerified;
        challenge.consumed_at = Some(now);
        self.store.save_attestation_evidence_and_result(
            session_id,
            &session,
            &challenge,
            attestation_evidence,
            &attestation_result,
        )?;
        Ok(SubmitAttestationEvidenceResponse {
            session,
            attestation_evidence_hash,
            attestation_result,
            attestation_result_hash,
        })
    }

    pub fn register_execution_statement(
        &self,
        statement: &ExecutionStatement,
    ) -> lsdc_common::error::Result<TransparencyReceipt> {
        let receipt = self.transparency_log.register(statement)?;
        self.store
            .insert_transparency_receipt(statement, &receipt)?;
        Ok(receipt)
    }

    pub fn verify_transparency_receipt(
        &self,
        statement_hash: &Sha256Hash,
        receipt: &TransparencyReceipt,
    ) -> lsdc_common::error::Result<()> {
        self.transparency_log
            .verify_receipt(statement_hash, receipt)
    }

    pub async fn verify_evidence_dag(&self, dag: &EvidenceDag) -> lsdc_common::error::Result<bool> {
        for node in &dag.nodes {
            if node.kind != ExecutionStatementKind::ProofReceiptRegistered {
                continue;
            }

            let receipt: ProvenanceReceipt = serde_json::from_value(node.payload_json.clone())
                .map_err(lsdc_common::error::LsdcError::from)?;
            if !self.verify_receipt_for_backend(&receipt).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn verify_receipt_for_backend(
        &self,
        receipt: &ProvenanceReceipt,
    ) -> lsdc_common::error::Result<bool> {
        match receipt.proof_backend {
            ProofBackend::DevReceipt => self.dev_receipt_verifier.verify_receipt(receipt).await,
            ProofBackend::RiscZero => self.verify_risc0_receipt(receipt).await,
            ProofBackend::None => Ok(false),
        }
    }

    #[cfg(feature = "risc0")]
    async fn verify_risc0_receipt(
        &self,
        receipt: &ProvenanceReceipt,
    ) -> lsdc_common::error::Result<bool> {
        if self.proof_engine.proof_backend() == ProofBackend::RiscZero {
            self.proof_engine.verify_receipt(receipt).await
        } else {
            Risc0ProofEngine::new().verify_receipt(receipt).await
        }
    }

    #[cfg(not(feature = "risc0"))]
    async fn verify_risc0_receipt(
        &self,
        _receipt: &ProvenanceReceipt,
    ) -> lsdc_common::error::Result<bool> {
        Ok(false)
    }

    pub fn build_server_managed_execution_bindings(
        &self,
        agreement: &ContractAgreement,
    ) -> lsdc_common::error::Result<lsdc_ports::ExecutionBindings> {
        let overlay_commitment = self.execution_overlay_commitment_for(agreement)?;
        let created = self.create_execution_session(CreateExecutionSessionRequest {
            agreement_id: agreement.agreement_id.0.clone(),
            requester_ephemeral_pubkey: Vec::new(),
            expires_in_seconds: Some(900),
        })?;

        Ok(lsdc_ports::ExecutionBindings {
            overlay_commitment,
            session: created.session,
            challenge: None,
            resolved_transport: None,
            attestation_result_hash: None,
        })
    }

    pub fn build_evidence_dag_for_lineage(
        &self,
        job_id: &str,
        agreement: &ContractAgreement,
        execution_overlay: &ExecutionOverlaySummary,
        execution_bindings: &lsdc_ports::ExecutionBindings,
        execution_evidence: &lsdc_common::crypto::ExecutionEvidenceBundle,
        price_decision: &PriceDecision,
    ) -> lsdc_common::error::Result<(EvidenceDag, TransparencyReceipt)> {
        let now = chrono::Utc::now();
        let overlay_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(execution_overlay)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        let agreement_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(agreement).map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        let session_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(&execution_bindings.session)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        let challenge_hash = match execution_bindings.challenge.as_ref() {
            Some(challenge) => Some(Sha256Hash::digest_bytes(
                &canonical_json_bytes(
                    &serde_json::to_value(challenge)
                        .map_err(lsdc_common::error::LsdcError::from)?,
                )
                .map_err(lsdc_common::error::LsdcError::from)?,
            )),
            None => None,
        };
        let attestation_evidence_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(&execution_evidence.attestation_evidence)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        let attestation_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(&execution_evidence.attestation_result)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );
        let price_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(
                &serde_json::to_value(price_decision)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            )
            .map_err(lsdc_common::error::LsdcError::from)?,
        );

        let mut nodes = vec![
            EvidenceNode {
                node_id: format!("{job_id}:agreement"),
                kind: ExecutionStatementKind::AgreementCommitted,
                canonical_hash: agreement_hash.clone(),
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(agreement)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
            EvidenceNode {
                node_id: format!("{job_id}:overlay"),
                kind: ExecutionStatementKind::SessionCreated,
                canonical_hash: overlay_hash.clone(),
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(execution_overlay)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
            EvidenceNode {
                node_id: format!("{job_id}:session"),
                kind: ExecutionStatementKind::SessionCreated,
                canonical_hash: session_hash.clone(),
                status: NodeStatus::Realized,
                payload_json: serde_json::to_value(&execution_bindings.session)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
        ];
        if let Some(challenge) = execution_bindings.challenge.as_ref() {
            nodes.push(EvidenceNode {
                node_id: format!("{job_id}:challenge"),
                kind: ExecutionStatementKind::ChallengeIssued,
                canonical_hash: challenge_hash
                    .clone()
                    .expect("challenge hash should exist when challenge does"),
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(challenge)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            });
        }
        nodes.extend([
            EvidenceNode {
                node_id: format!("{job_id}:attestation-evidence"),
                kind: ExecutionStatementKind::AttestationEvidenceReceived,
                canonical_hash: attestation_evidence_hash,
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(&execution_evidence.attestation_evidence)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
            EvidenceNode {
                node_id: format!("{job_id}:attestation-result"),
                kind: ExecutionStatementKind::AttestationAppraised,
                canonical_hash: attestation_hash.clone(),
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(&execution_evidence.attestation_result)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
            EvidenceNode {
                node_id: format!("{job_id}:proof"),
                kind: ExecutionStatementKind::ProofReceiptRegistered,
                canonical_hash: execution_evidence.provenance_receipt.receipt_hash.clone(),
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(&execution_evidence.provenance_receipt)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
            EvidenceNode {
                node_id: format!("{job_id}:price"),
                kind: ExecutionStatementKind::PriceDecisionRecorded,
                canonical_hash: price_hash,
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(price_decision)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            },
        ]);
        if let Some(teardown_evidence) = execution_evidence.teardown_evidence.as_ref() {
            let teardown_hash = Sha256Hash::digest_bytes(
                &canonical_json_bytes(
                    &serde_json::to_value(teardown_evidence)
                        .map_err(lsdc_common::error::LsdcError::from)?,
                )
                .map_err(lsdc_common::error::LsdcError::from)?,
            );
            nodes.push(EvidenceNode {
                node_id: format!("{job_id}:teardown"),
                kind: ExecutionStatementKind::TeardownEvidenceRegistered,
                canonical_hash: teardown_hash,
                status: NodeStatus::Verified,
                payload_json: serde_json::to_value(teardown_evidence)
                    .map_err(lsdc_common::error::LsdcError::from)?,
            });
        }
        let mut edges = vec![
            EvidenceEdge {
                from_node_id: format!("{job_id}:agreement"),
                to_node_id: format!("{job_id}:session"),
                dependency_type: DependencyType::ImplementedBy,
            },
            EvidenceEdge {
                from_node_id: format!("{job_id}:session"),
                to_node_id: format!("{job_id}:attestation-evidence"),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: format!("{job_id}:attestation-evidence"),
                to_node_id: format!("{job_id}:attestation-result"),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: format!("{job_id}:attestation-result"),
                to_node_id: format!("{job_id}:proof"),
                dependency_type: DependencyType::VerifiedBy,
            },
            EvidenceEdge {
                from_node_id: format!("{job_id}:proof"),
                to_node_id: format!("{job_id}:price"),
                dependency_type: DependencyType::DerivedFrom,
            },
        ];
        if execution_bindings.challenge.is_some() {
            edges.push(EvidenceEdge {
                from_node_id: format!("{job_id}:session"),
                to_node_id: format!("{job_id}:challenge"),
                dependency_type: DependencyType::DerivedFrom,
            });
            edges.push(EvidenceEdge {
                from_node_id: format!("{job_id}:challenge"),
                to_node_id: format!("{job_id}:attestation-evidence"),
                dependency_type: DependencyType::VerifiedBy,
            });
        }
        if execution_evidence.teardown_evidence.is_some() {
            edges.push(EvidenceEdge {
                from_node_id: format!("{job_id}:proof"),
                to_node_id: format!("{job_id}:teardown"),
                dependency_type: DependencyType::DerivedFrom,
            });
        }

        let base_dag = EvidenceDag::new(nodes.clone(), edges.clone())
            .map_err(lsdc_common::error::LsdcError::from)?;
        let settlement_statement = ExecutionStatement {
            statement_id: format!("{job_id}:settlement"),
            statement_hash: Sha256Hash::digest_bytes(job_id.as_bytes()),
            statement_kind: ExecutionStatementKind::SettlementRecorded,
            agreement_id: agreement.agreement_id.0.clone(),
            session_id: Some(execution_bindings.session.session_id),
            payload_hash: base_dag.root_hash.clone(),
            parent_hashes: nodes
                .iter()
                .map(|node| node.canonical_hash.clone())
                .collect(),
            producer: self.node_name.clone(),
            profile: execution_overlay.overlay_version.clone(),
            created_at: now,
        }
        .with_computed_hash()
        .map_err(lsdc_common::error::LsdcError::from)?;
        let transparency_receipt = self.register_execution_statement(&settlement_statement)?;
        let transparency_hash = transparency_receipt
            .canonical_hash()
            .map_err(lsdc_common::error::LsdcError::from)?;

        nodes.push(EvidenceNode {
            node_id: settlement_statement.statement_id.clone(),
            kind: settlement_statement.statement_kind,
            canonical_hash: settlement_statement.statement_hash.clone(),
            status: NodeStatus::Anchored,
            payload_json: serde_json::to_value(&settlement_statement)
                .map_err(lsdc_common::error::LsdcError::from)?,
        });
        nodes.push(EvidenceNode {
            node_id: format!("{job_id}:transparency"),
            kind: ExecutionStatementKind::TransparencyAnchored,
            canonical_hash: transparency_hash,
            status: NodeStatus::Anchored,
            payload_json: serde_json::to_value(&transparency_receipt)
                .map_err(lsdc_common::error::LsdcError::from)?,
        });
        edges.push(EvidenceEdge {
            from_node_id: settlement_statement.statement_id.clone(),
            to_node_id: format!("{job_id}:transparency"),
            dependency_type: DependencyType::AnchoredBy,
        });

        let dag = EvidenceDag::new(nodes, edges).map_err(lsdc_common::error::LsdcError::from)?;
        self.store
            .persist_evidence_dag(job_id, &agreement.agreement_id.0, &dag)?;
        Ok((dag, transparency_receipt))
    }

    pub fn actual_backends_summary(&self) -> BackendSummary {
        self.actual_backends()
    }

    pub fn configured_backends_summary(&self) -> BackendSummary {
        self.configured_backends
    }

    pub fn api_bearer_token(&self) -> &str {
        &self.api_bearer_token
    }

    pub fn lineage_job_runner(&self) -> LineageJobRunner {
        LineageJobRunner::new(self.clone())
    }
}

fn allow_dev_defaults() -> bool {
    matches!(std::env::var("LSDC_ALLOW_DEV_DEFAULTS").as_deref(), Ok("1"))
}

fn map_truthfulness_mode(mode: TruthfulnessMode) -> OverlayTruthfulnessMode {
    match mode {
        TruthfulnessMode::Permissive => OverlayTruthfulnessMode::Permissive,
        TruthfulnessMode::Strict => OverlayTruthfulnessMode::Strict,
    }
}

fn map_truthfulness_mode_back(mode: OverlayTruthfulnessMode) -> TruthfulnessMode {
    match mode {
        OverlayTruthfulnessMode::Permissive => TruthfulnessMode::Permissive,
        OverlayTruthfulnessMode::Strict => TruthfulnessMode::Strict,
    }
}

fn resolved_transport_hash(
    resolved_transport: &ResolvedTransportGuard,
) -> lsdc_common::error::Result<Sha256Hash> {
    Ok(domain_hash(
        "lsdc.resolved-selector.v1",
        &[&canonical_json_bytes(
            &serde_json::to_value(resolved_transport)
                .map_err(lsdc_common::error::LsdcError::from)?,
        )
        .map_err(lsdc_common::error::LsdcError::from)?],
    ))
}
