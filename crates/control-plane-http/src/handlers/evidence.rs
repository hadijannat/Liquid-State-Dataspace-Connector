use crate::error::{ApiError, ApiResult};
use crate::state::ApiState;
use axum::extract::State;
use axum::Json;
use lsdc_common::error::LsdcError;
use lsdc_service_types::{EvidenceVerificationRequest, EvidenceVerificationResult};

pub async fn verify_evidence_chain(
    State(state): State<ApiState>,
    Json(request): Json<EvidenceVerificationRequest>,
) -> ApiResult<Json<EvidenceVerificationResult>> {
    let valid = if request.receipts.is_empty() {
        true
    } else if request
        .receipts
        .iter()
        .any(|receipt| receipt.proof_backend != state.proof_engine.proof_backend())
    {
        false
    } else {
        match state.proof_engine.verify_chain(&request.receipts).await {
            Ok(valid) => valid,
            Err(LsdcError::Unsupported(_)) => false,
            Err(err) => return Err(ApiError::internal(err)),
        }
    };

    Ok(Json(EvidenceVerificationResult {
        proof_backend: state.proof_engine.proof_backend(),
        checked_receipt_count: request.receipts.len(),
        valid,
    }))
}
