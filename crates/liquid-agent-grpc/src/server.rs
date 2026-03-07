use crate::proto::liquid_agent_server::{LiquidAgent, LiquidAgentServer};
use crate::proto::{
    ActivateAgreementRequest, ActivateAgreementResponse, GetEnforcementStatusRequest,
    GetEnforcementStatusResponse, GetRuntimeInfoRequest, GetRuntimeInfoResponse,
    RevokeEnforcementRequest, RevokeEnforcementResponse,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::LsdcError;
use lsdc_common::execution::TransportBackend;
use lsdc_common::Result;
use lsdc_ports::{DataPlane, EnforcementHandle};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct LiquidAgentService {
    plane: Arc<dyn DataPlane>,
    transport_backend: TransportBackend,
}

impl LiquidAgentService {
    pub fn new(plane: Arc<dyn DataPlane>, transport_backend: TransportBackend) -> Self {
        Self {
            plane,
            transport_backend,
        }
    }
}

#[tonic::async_trait]
impl LiquidAgent for LiquidAgentService {
    async fn activate_agreement(
        &self,
        request: Request<ActivateAgreementRequest>,
    ) -> std::result::Result<Response<ActivateAgreementResponse>, Status> {
        let request = request.into_inner();
        let agreement: ContractAgreement =
            serde_json::from_str(&request.agreement_json).map_err(serde_status)?;
        let handle = self
            .plane
            .enforce(&agreement, &request.iface)
            .await
            .map_err(lsdc_status)?;

        Ok(Response::new(ActivateAgreementResponse {
            handle_json: serde_json::to_string(&handle).map_err(serde_status)?,
        }))
    }

    async fn revoke_enforcement(
        &self,
        request: Request<RevokeEnforcementRequest>,
    ) -> std::result::Result<Response<RevokeEnforcementResponse>, Status> {
        let request = request.into_inner();
        let handle: EnforcementHandle =
            serde_json::from_str(&request.handle_json).map_err(serde_status)?;
        self.plane.revoke(&handle).await.map_err(lsdc_status)?;
        Ok(Response::new(RevokeEnforcementResponse {}))
    }

    async fn get_enforcement_status(
        &self,
        request: Request<GetEnforcementStatusRequest>,
    ) -> std::result::Result<Response<GetEnforcementStatusResponse>, Status> {
        let request = request.into_inner();
        let handle: EnforcementHandle =
            serde_json::from_str(&request.handle_json).map_err(serde_status)?;
        let status = self.plane.status(&handle).await.map_err(lsdc_status)?;
        Ok(Response::new(GetEnforcementStatusResponse {
            status_json: serde_json::to_string(&status).map_err(serde_status)?,
        }))
    }

    async fn get_runtime_info(
        &self,
        _request: Request<GetRuntimeInfoRequest>,
    ) -> std::result::Result<Response<GetRuntimeInfoResponse>, Status> {
        Ok(Response::new(GetRuntimeInfoResponse {
            transport_backend: match self.transport_backend {
                TransportBackend::AyaXdp => "aya_xdp",
                TransportBackend::Simulated => "simulated",
            }
            .into(),
        }))
    }
}

pub async fn serve(listener: TcpListener, service: LiquidAgentService) -> Result<()> {
    tonic::transport::Server::builder()
        .add_service(LiquidAgentServer::new(service))
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
        .map_err(|err| LsdcError::Enforcement(format!("liquid agent server failed: {err}")))
}

fn lsdc_status(err: LsdcError) -> Status {
    Status::internal(err.to_string())
}

fn serde_status(err: serde_json::Error) -> Status {
    Status::invalid_argument(err.to_string())
}
