use crate::proto::liquid_agent_client::LiquidAgentClient as ProtoLiquidAgentClient;
use crate::proto::{
    ActivateAgreementRequest, GetEnforcementStatusRequest, GetRuntimeInfoRequest,
    RevokeEnforcementRequest,
};
use async_trait::async_trait;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::LsdcError;
use lsdc_common::execution::TransportBackend;
use lsdc_common::Result;
use lsdc_ports::{DataPlane, EnforcementHandle, EnforcementStatus};
use tonic::transport::Channel;

#[derive(Clone)]
pub struct LiquidAgentGrpcClient {
    endpoint: String,
}

impl LiquidAgentGrpcClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    async fn client(&self) -> Result<ProtoLiquidAgentClient<Channel>> {
        ProtoLiquidAgentClient::connect(self.endpoint.clone())
            .await
            .map_err(|err| {
                LsdcError::Enforcement(format!("failed to connect to liquid agent: {err}"))
            })
    }

    pub async fn transport_backend(&self) -> Result<TransportBackend> {
        let mut client = self.client().await?;
        let response = client
            .get_runtime_info(GetRuntimeInfoRequest {})
            .await
            .map_err(agent_transport_error)?
            .into_inner();
        parse_transport_backend(&response.transport_backend)
    }
}

#[async_trait]
impl DataPlane for LiquidAgentGrpcClient {
    async fn enforce(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle> {
        let mut client = self.client().await?;
        let response = client
            .activate_agreement(ActivateAgreementRequest {
                agreement_json: serde_json::to_string(agreement).map_err(LsdcError::from)?,
                iface: iface.to_string(),
            })
            .await
            .map_err(agent_transport_error)?
            .into_inner();

        serde_json::from_str(&response.handle_json).map_err(LsdcError::from)
    }

    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()> {
        let mut client = self.client().await?;
        client
            .revoke_enforcement(RevokeEnforcementRequest {
                handle_json: serde_json::to_string(handle).map_err(LsdcError::from)?,
            })
            .await
            .map_err(agent_transport_error)?;
        Ok(())
    }

    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus> {
        let mut client = self.client().await?;
        let response = client
            .get_enforcement_status(GetEnforcementStatusRequest {
                handle_json: serde_json::to_string(handle).map_err(LsdcError::from)?,
            })
            .await
            .map_err(agent_transport_error)?
            .into_inner();

        serde_json::from_str(&response.status_json).map_err(LsdcError::from)
    }
}

fn agent_transport_error(err: tonic::Status) -> LsdcError {
    LsdcError::Enforcement(format!("liquid agent request failed: {err}"))
}

fn parse_transport_backend(value: &str) -> Result<TransportBackend> {
    match value {
        "simulated" => Ok(TransportBackend::Simulated),
        "aya_xdp" => Ok(TransportBackend::AyaXdp),
        other => Err(LsdcError::Enforcement(format!(
            "liquid agent reported unknown transport backend `{other}`"
        ))),
    }
}
