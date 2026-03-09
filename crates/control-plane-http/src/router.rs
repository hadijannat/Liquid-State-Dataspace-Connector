use crate::handlers::{contracts, evidence, lineage, settlement, transfers};
use crate::state::ApiState;
use axum::routing::{get, post};
use axum::Router;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(contracts::health))
        .route("/dsp/contracts/request", post(contracts::contract_request))
        .route("/dsp/contracts/finalize", post(contracts::contract_finalize))
        .route("/dsp/transfers/start", post(transfers::transfer_start))
        .route(
            "/dsp/transfers/:transfer_id/complete",
            post(transfers::transfer_complete),
        )
        .route("/lsdc/lineage/jobs", post(lineage::create_lineage_job))
        .route("/lsdc/lineage/jobs/:job_id", get(lineage::get_lineage_job))
        .route("/lsdc/evidence/verify-chain", post(evidence::verify_evidence_chain))
        .route(
            "/lsdc/agreements/:agreement_id/settlement",
            get(settlement::get_settlement),
        )
        .with_state(state)
}
