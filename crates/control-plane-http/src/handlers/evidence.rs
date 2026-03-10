use crate::error::ApiResult;
use crate::state::ApiState;
use axum::extract::State;
use axum::Json;
use lsdc_common::crypto::ProvenanceReceipt;
use lsdc_common::execution::ProofBackend;
#[cfg(feature = "risc0")]
use lsdc_ports::ProofEngine;
use lsdc_service_types::{EvidenceVerificationRequest, EvidenceVerificationResult};
use proof_plane_core::verify_provenance_receipt_chain;
#[cfg(feature = "risc0")]
use proof_plane_host::Risc0ProofEngine;

pub async fn verify_evidence_chain(
    State(state): State<ApiState>,
    Json(request): Json<EvidenceVerificationRequest>,
) -> ApiResult<Json<EvidenceVerificationResult>> {
    let verified_backends = dedup_backends(&request.receipts);
    let linkage = verify_provenance_receipt_chain(&request.receipts);
    let valid = if request.receipts.is_empty() || !linkage.valid {
        false
    } else {
        let mut all_valid = true;
        for receipt in &request.receipts {
            if !verify_receipt_for_backend(&state, receipt).await {
                all_valid = false;
                break;
            }
        }
        all_valid
    };

    Ok(Json(EvidenceVerificationResult {
        verified_backends,
        checked_receipt_count: request.receipts.len(),
        valid,
    }))
}

async fn verify_receipt_for_backend(state: &ApiState, receipt: &ProvenanceReceipt) -> bool {
    let verification = match receipt.proof_backend {
        ProofBackend::DevReceipt => state.dev_receipt_verifier.verify_receipt(receipt).await,
        ProofBackend::RiscZero => verify_risc0_receipt(state, receipt).await,
        ProofBackend::None => return false,
    };

    match verification {
        Ok(valid) => valid,
        Err(err) => {
            tracing::warn!(
                proof_backend = ?receipt.proof_backend,
                error = %err,
                "receipt verification failed"
            );
            false
        }
    }
}

#[cfg(feature = "risc0")]
async fn verify_risc0_receipt(
    state: &ApiState,
    receipt: &ProvenanceReceipt,
) -> lsdc_common::Result<bool> {
    if state.proof_engine.proof_backend() == ProofBackend::RiscZero {
        return state.proof_engine.verify_receipt(receipt).await;
    }

    Risc0ProofEngine::new().verify_receipt(receipt).await
}

#[cfg(not(feature = "risc0"))]
async fn verify_risc0_receipt(
    _state: &ApiState,
    _receipt: &ProvenanceReceipt,
) -> lsdc_common::Result<bool> {
    Ok(false)
}

fn dedup_backends(receipts: &[ProvenanceReceipt]) -> Vec<ProofBackend> {
    let mut ordered = Vec::new();
    for receipt in receipts {
        if !ordered.contains(&receipt.proof_backend) {
            ordered.push(receipt.proof_backend);
        }
    }
    ordered
}
