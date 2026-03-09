use crate::error::{ApiError, ApiResult};
use crate::state::ApiState;
use axum::extract::{Path, State};
use axum::Json;
use lsdc_service_types::SettlementDecision;

pub async fn get_settlement(
    State(state): State<ApiState>,
    Path(agreement_id): Path<String>,
) -> ApiResult<Json<SettlementDecision>> {
    let mut settlement = state
        .store
        .get_settlement(&agreement_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("agreement not found"))?;
    if settlement.policy_execution.is_none() {
        if let Some((agreement, _)) = state
            .store
            .get_agreement(&agreement_id)
            .map_err(ApiError::internal)?
        {
            settlement.policy_execution = Some(state.policy_execution_for(&agreement));
        }
    }
    Ok(Json(settlement))
}
