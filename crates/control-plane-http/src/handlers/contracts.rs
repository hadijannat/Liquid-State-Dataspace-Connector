use crate::error::{ApiError, ApiResult};
use crate::state::ApiState;
use axum::extract::State;
use axum::Json;
use lsdc_common::dsp::{ContractOffer, ContractRequest};
use lsdc_service_types::FinalizeContractResponse;

pub async fn health(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(state.health_payload())
}

pub async fn contract_request(
    State(state): State<ApiState>,
    Json(request): Json<ContractRequest>,
) -> ApiResult<Json<ContractOffer>> {
    let offer = state
        .agreement_service
        .handle_request(request)
        .await
        .map_err(ApiError::bad_request)?;
    Ok(Json(offer))
}

pub async fn contract_finalize(
    State(state): State<ApiState>,
    Json(offer): Json<ContractOffer>,
) -> ApiResult<Json<FinalizeContractResponse>> {
    let negotiated = state
        .agreement_service
        .finalize_profiled(offer)
        .await
        .map_err(ApiError::bad_request)?;
    let policy_execution = state.policy_execution_for(&negotiated.agreement);
    state
        .store
        .upsert_agreement(&negotiated.agreement, &negotiated.requested_profile)
        .map_err(ApiError::internal)?;

    Ok(Json(FinalizeContractResponse {
        agreement: negotiated.agreement,
        requested_profile: negotiated.requested_profile,
        policy_execution: Some(policy_execution),
    }))
}
