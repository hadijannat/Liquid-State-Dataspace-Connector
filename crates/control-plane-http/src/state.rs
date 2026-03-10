use crate::job_runner::LineageJobRunner;
use control_plane::agreement_service::AgreementService;
use control_plane::orchestrator::Orchestrator;
use control_plane_store::Store;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::execution::{
    ActualExecutionProfile, PolicyExecutionClassification, PricingMode, ProofBackend, TeeBackend,
    TransportBackend,
};
use lsdc_ports::{DataPlane, EnclaveManager, PricingOracle, ProofEngine};
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
    pub(crate) liquid_agent: Arc<LiquidAgentGrpcClient>,
    pub(crate) default_interface: String,
    pub(crate) api_bearer_token: Arc<str>,
    pub(crate) configured_backends: BackendSummary,
    pub(crate) actual_transport_backend: TransportBackend,
    pub(crate) actual_tee_backend: TeeBackend,
}

impl ApiState {
    pub fn new(init: ApiStateInit) -> Self {
        let ApiStateInit {
            store,
            node_name,
            liquid_agent,
            proof_engine,
            dev_receipt_verifier,
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

        Self {
            store,
            node_name,
            agreement_service: Arc::new(AgreementService::new()),
            orchestrator,
            proof_engine,
            dev_receipt_verifier,
            liquid_agent,
            default_interface,
            api_bearer_token: api_bearer_token.into(),
            configured_backends,
            actual_transport_backend,
            actual_tee_backend,
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
            "enabled_features": {
                "risc0": cfg!(feature = "risc0")
            }
        })
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
