use crate::error::{ApiError, ApiResult};
use crate::state::ApiState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use lsdc_common::crypto::Sha256Hash;
use lsdc_service_types::{
    CreateExecutionSessionRequest, CreateExecutionSessionResponse, ExecutionCapabilitiesResponse,
    IssueExecutionChallengeResponse, RegisterAttestationResultRequest,
    RegisterAttestationResultResponse, RegisterEvidenceStatementRequest,
    RegisterEvidenceStatementResponse, VerifyEvidenceDagRequest, VerifyEvidenceDagResponse,
};

pub async fn execution_capabilities(
    State(state): State<ApiState>,
) -> ApiResult<Json<ExecutionCapabilitiesResponse>> {
    Ok(Json(state.execution_capabilities()))
}

pub async fn create_execution_session(
    State(state): State<ApiState>,
    Json(request): Json<CreateExecutionSessionRequest>,
) -> ApiResult<(StatusCode, Json<CreateExecutionSessionResponse>)> {
    let response = state
        .create_execution_session(request)
        .map_err(ApiError::bad_request)?;
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn issue_execution_challenge(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<IssueExecutionChallengeResponse>> {
    let response = state
        .issue_execution_challenge(&session_id)
        .map_err(ApiError::bad_request)?;
    Ok(Json(response))
}

pub async fn register_attestation_result(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Json(request): Json<RegisterAttestationResultRequest>,
) -> ApiResult<Json<RegisterAttestationResultResponse>> {
    if request.session_id != session_id {
        return Err(ApiError::bad_request(
            lsdc_common::error::LsdcError::PolicyCompile(
                "session id in path and body must match".into(),
            ),
        ));
    }

    let (session, attestation_result_hash) = state
        .register_attestation_result(&session_id, &request.attestation_result)
        .map_err(ApiError::bad_request)?;

    Ok(Json(RegisterAttestationResultResponse {
        session,
        attestation_result_hash,
    }))
}

pub async fn register_evidence_statement(
    State(state): State<ApiState>,
    Json(request): Json<RegisterEvidenceStatementRequest>,
) -> ApiResult<(StatusCode, Json<RegisterEvidenceStatementResponse>)> {
    let receipt = state
        .register_execution_statement(&request.statement)
        .map_err(ApiError::bad_request)?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterEvidenceStatementResponse {
            statement: request.statement,
            receipt,
        }),
    ))
}

pub async fn get_transparency_receipt(
    State(state): State<ApiState>,
    Path(statement_id): Path<String>,
) -> ApiResult<Json<lsdc_common::execution_overlay::TransparencyReceipt>> {
    let receipt = state
        .store
        .get_transparency_receipt(&statement_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("transparency receipt not found"))?;
    Ok(Json(receipt))
}

pub async fn verify_evidence_dag(
    State(state): State<ApiState>,
    Json(request): Json<VerifyEvidenceDagRequest>,
) -> ApiResult<Json<VerifyEvidenceDagResponse>> {
    let proof_valid = state
        .proof_engine
        .verify_receipt_dag(&request.dag)
        .await
        .map_err(ApiError::internal)?;
    let mut receipt_valid = true;

    for receipt in &request.receipts {
        let statement_hash = find_statement_hash(&request.dag, &receipt.statement_id)
            .ok_or_else(|| ApiError::bad_request(lsdc_common::error::LsdcError::Database(
                format!("statement `{}` not found in DAG", receipt.statement_id),
            )))?;
        if state
            .verify_transparency_receipt(&statement_hash, receipt)
            .is_err()
        {
            receipt_valid = false;
            break;
        }
    }

    Ok(Json(VerifyEvidenceDagResponse {
        valid: proof_valid && receipt_valid,
        checked_statement_count: request.dag.nodes.len(),
        checked_receipt_count: request.receipts.len(),
        evidence_root_hash: request.dag.root_hash,
    }))
}

fn find_statement_hash(
    dag: &lsdc_common::runtime_model::EvidenceDag,
    statement_id: &str,
) -> Option<Sha256Hash> {
    dag.nodes
        .iter()
        .find(|node| node.node_id == statement_id)
        .map(|node| node.canonical_hash.clone())
}
