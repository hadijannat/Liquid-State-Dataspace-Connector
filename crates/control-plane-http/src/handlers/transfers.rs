use crate::error::{ApiError, ApiResult};
use crate::state::ApiState;
use axum::extract::{Path, State};
use axum::Json;
use lsdc_common::dsp::{TransferCompletion, TransferRequest, TransportProtocol};
use lsdc_service_types::TransferStartResponse;

pub async fn transfer_start(
    State(state): State<ApiState>,
    Json(request): Json<TransferRequest>,
) -> ApiResult<Json<TransferStartResponse>> {
    let (mut agreement, _) = state
        .store
        .get_agreement(&request.agreement_id.0)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("agreement not found"))?;

    let resolved_transport = resolve_transfer_request(&request).map_err(ApiError::bad_request)?;
    agreement.liquid_policy.transport_guard.protocol = resolved_transport.protocol;
    agreement.liquid_policy.transport_guard.session_port = Some(resolved_transport.session_port);

    let handle = state
        .orchestrator
        .activate_agreement(&agreement, &state.default_interface)
        .await
        .map_err(ApiError::internal)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let response = TransferStartResponse {
        transfer_start: lsdc_common::dsp::TransferStart {
            transfer_id: transfer_id.clone(),
            agreement_id: agreement.agreement_id.clone(),
            protocol: resolved_transport.protocol,
            session_port: handle.session_port,
        },
        policy_execution: Some(state.policy_execution_for(&agreement)),
        resolved_transport: handle.resolved_transport.clone(),
        enforcement_runtime: handle.runtime.clone(),
        enforcement_handle: handle,
    };

    state
        .store
        .insert_transfer(&transfer_id, &agreement.agreement_id.0, &request, &response)
        .map_err(ApiError::internal)?;

    Ok(Json(response))
}

pub async fn transfer_complete(
    State(state): State<ApiState>,
    Path(transfer_id): Path<String>,
) -> ApiResult<Json<TransferCompletion>> {
    let handle = state
        .store
        .get_transfer_handle(&transfer_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("transfer session not found"))?;
    state
        .orchestrator
        .revoke_agreement(&handle)
        .await
        .map_err(ApiError::internal)?;
    state
        .store
        .complete_transfer(&transfer_id)
        .map_err(ApiError::internal)?;

    Ok(Json(TransferCompletion { transfer_id }))
}

struct ResolvedTransferRequest {
    protocol: TransportProtocol,
    session_port: u16,
}

fn resolve_transfer_request(
    request: &TransferRequest,
) -> std::result::Result<ResolvedTransferRequest, String> {
    let parsed = parse_transport_address(&request.data_address)?;
    if parsed.protocol != request.protocol {
        return Err(format!(
            "data_address scheme `{}` does not match requested protocol `{}`",
            transport_protocol_name(parsed.protocol),
            transport_protocol_name(request.protocol),
        ));
    }

    let session_port =
        match (request.session_port, parsed.port) {
            (Some(requested), Some(address)) if requested != address => {
                return Err(format!(
                    "session_port `{requested}` does not match data_address port `{address}`"
                ));
            }
            (Some(requested), _) => requested,
            (None, Some(address)) => address,
            (None, None) => return Err(
                "guarded transfer requires a destination port in `data_address` or `session_port`"
                    .into(),
            ),
        };

    Ok(ResolvedTransferRequest {
        protocol: request.protocol,
        session_port,
    })
}

struct ParsedTransportAddress {
    protocol: TransportProtocol,
    port: Option<u16>,
}

fn parse_transport_address(value: &str) -> std::result::Result<ParsedTransportAddress, String> {
    let (scheme, rest) = value.split_once("://").ok_or_else(|| {
        "data_address must use a supported transport scheme like udp:// or tcp://".to_string()
    })?;

    let protocol = match scheme.to_ascii_lowercase().as_str() {
        "udp" => TransportProtocol::Udp,
        "tcp" => TransportProtocol::Tcp,
        other => return Err(format!("unsupported data_address scheme `{other}`")),
    };

    let port = rest
        .rsplit_once(':')
        .map(|(_, port)| {
            port.parse::<u16>()
                .map_err(|_| format!("invalid data_address port `{port}`"))
        })
        .transpose()?;

    Ok(ParsedTransportAddress { protocol, port })
}

fn transport_protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    }
}
