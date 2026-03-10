use crate::error::{ApiError, ApiResult};
use crate::state::ApiState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use lsdc_common::execution::RequestedExecutionProfile;
use lsdc_service_types::{
    LineageJobAccepted, LineageJobRecord, LineageJobRequest, LineageJobState,
};

pub async fn create_lineage_job(
    State(state): State<ApiState>,
    Json(mut request): Json<LineageJobRequest>,
) -> ApiResult<(StatusCode, Json<LineageJobAccepted>)> {
    let requested_profile = RequestedExecutionProfile::from_agreement(&request.agreement);
    let execution_overlay = state
        .execution_overlay_for(&request.agreement)
        .map_err(ApiError::bad_request)?;
    state
        .store
        .upsert_agreement(&request.agreement, &requested_profile)
        .map_err(ApiError::internal)?;
    state
        .store
        .upsert_agreement_overlay(&request.agreement.agreement_id.0, &execution_overlay)
        .map_err(ApiError::internal)?;
    if request.execution_bindings.is_none() {
        request.execution_bindings = Some(
            state
                .build_server_managed_execution_bindings(&request.agreement)
                .map_err(ApiError::bad_request)?,
        );
    }

    let now = chrono::Utc::now();
    let job_id = uuid::Uuid::new_v4().to_string();
    let record = LineageJobRecord {
        job_id: job_id.clone(),
        agreement_id: request.agreement.agreement_id.0.clone(),
        state: LineageJobState::Pending,
        request: request.clone(),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .insert_job(&record)
        .map_err(ApiError::internal)?;

    state.lineage_job_runner().spawn(job_id.clone(), request);

    Ok((
        StatusCode::ACCEPTED,
        Json(LineageJobAccepted {
            job_id,
            state: LineageJobState::Pending,
        }),
    ))
}

pub async fn get_lineage_job(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
) -> ApiResult<Json<LineageJobRecord>> {
    let record = state
        .store
        .get_job(&job_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("lineage job not found"))?;
    Ok(Json(record))
}
