use crate::error::ApiError;
use crate::handlers::{contracts, evidence, execution, lineage, settlement, transfers};
use crate::state::ApiState;
use axum::body::Body;
use axum::http::{header, Request};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

pub fn router(state: ApiState) -> Router {
    let protected_state = state.clone();
    let protected = Router::new()
        .route("/dsp/contracts/request", post(contracts::contract_request))
        .route(
            "/dsp/contracts/finalize",
            post(contracts::contract_finalize),
        )
        .route("/dsp/transfers/start", post(transfers::transfer_start))
        .route(
            "/dsp/transfers/:transfer_id/complete",
            post(transfers::transfer_complete),
        )
        .route("/lsdc/v1/capabilities", get(execution::execution_capabilities))
        .route("/lsdc/v1/sessions", post(execution::create_execution_session))
        .route(
            "/lsdc/v1/sessions/:session_id/challenges",
            post(execution::issue_execution_challenge),
        )
        .route(
            "/lsdc/v1/sessions/:session_id/attestation-evidence",
            post(execution::submit_attestation_evidence),
        )
        .route(
            "/lsdc/v1/evidence/statements",
            post(execution::register_evidence_statement),
        )
        .route(
            "/lsdc/v1/evidence/statements/:statement_id/receipt",
            get(execution::get_transparency_receipt),
        )
        .route("/lsdc/v1/evidence/verify", post(execution::verify_evidence_dag))
        .route("/lsdc/lineage/jobs", post(lineage::create_lineage_job))
        .route("/lsdc/lineage/jobs/:job_id", get(lineage::get_lineage_job))
        .route(
            "/lsdc/evidence/verify-chain",
            post(evidence::verify_evidence_chain),
        )
        .route(
            "/lsdc/agreements/:agreement_id/settlement",
            get(settlement::get_settlement),
        )
        .route_layer(middleware::from_fn_with_state(
            protected_state,
            require_bearer_auth,
        ));

    Router::new()
        .route("/health", get(contracts::health))
        .merge(protected)
        .with_state(state)
}

async fn require_bearer_auth(
    state: axum::extract::State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let header_value = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let expected = format!("Bearer {}", state.api_bearer_token());

    if header_value != Some(expected.as_str()) {
        return ApiError::unauthorized().into_response();
    }

    next.run(request).await
}
