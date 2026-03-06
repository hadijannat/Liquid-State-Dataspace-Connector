pub mod config;
pub mod store;

use anyhow::{anyhow, Result as AnyhowResult};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use control_plane::negotiation::NegotiationEngine;
use control_plane::orchestrator::{BatchLineageRequest, Orchestrator};
use control_plane::pricing::GrpcPricingOracle;
use liquid_agent::client::LiquidAgentGrpcClient;
use lsdc_common::dsp::{
    ContractOffer, ContractRequest, TransferCompletion, TransferRequest, TransferStart,
};
use lsdc_common::error::LsdcError;
use lsdc_common::execution::{
    ActualExecutionProfile, PricingMode, ProofBackend, RequestedExecutionProfile, TeeBackend,
    TransportBackend,
};
use lsdc_common::service::{
    EvidenceVerificationRequest, EvidenceVerificationResult, FinalizeContractResponse,
    LineageJobAccepted, LineageJobRecord, LineageJobRequest, LineageJobResult, LineageJobState,
    SettlementDecision, TransferStartResponse,
};
use lsdc_common::traits::{DataPlane, EnclaveManager, PricingOracle, ProofEngine};
use proof_plane_host::DevReceiptProofEngine;
#[cfg(feature = "risc0")]
use proof_plane_host::Risc0ProofEngine;
use std::sync::Arc;
use store::Store;
use tee_orchestrator::enclave::{NitroEnclaveManager, NitroLiveAttestationMaterial};

#[derive(Clone)]
pub struct ApiState {
    store: Store,
    negotiation: Arc<NegotiationEngine>,
    orchestrator: Arc<Orchestrator>,
    proof_engine: Arc<dyn ProofEngine>,
    liquid_agent: Arc<LiquidAgentGrpcClient>,
    default_interface: String,
    transport_backend: TransportBackend,
    tee_backend: TeeBackend,
}

impl ApiState {
    pub fn new(
        store: Store,
        liquid_agent: Arc<LiquidAgentGrpcClient>,
        proof_engine: Arc<dyn ProofEngine>,
        enclave_manager: Arc<dyn EnclaveManager>,
        pricing_oracle: Arc<dyn PricingOracle>,
        default_interface: impl Into<String>,
        transport_backend: TransportBackend,
        tee_backend: TeeBackend,
    ) -> Self {
        let data_plane: Arc<dyn DataPlane> = liquid_agent.clone();
        let orchestrator = Arc::new(Orchestrator::with_full_stack(
            data_plane,
            enclave_manager,
            pricing_oracle,
        ));

        Self {
            store,
            negotiation: Arc::new(NegotiationEngine::new()),
            orchestrator,
            proof_engine,
            liquid_agent,
            default_interface: default_interface.into(),
            transport_backend,
            tee_backend,
        }
    }

    fn actual_execution_profile(&self, pricing_mode: PricingMode) -> ActualExecutionProfile {
        ActualExecutionProfile {
            transport_backend: self.transport_backend,
            proof_backend: self.proof_engine.proof_backend(),
            tee_backend: self.tee_backend,
            pricing_mode,
        }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/dsp/contracts/request", post(contract_request))
        .route("/dsp/contracts/finalize", post(contract_finalize))
        .route("/dsp/transfers/start", post(transfer_start))
        .route(
            "/dsp/transfers/:transfer_id/complete",
            post(transfer_complete),
        )
        .route("/lsdc/lineage/jobs", post(create_lineage_job))
        .route("/lsdc/lineage/jobs/:job_id", get(get_lineage_job))
        .route("/lsdc/evidence/verify-chain", post(verify_evidence_chain))
        .route(
            "/lsdc/agreements/:agreement_id/settlement",
            get(get_settlement),
        )
        .with_state(state)
}

pub fn state_from_config(config: &config::ControlPlaneApiConfig) -> AnyhowResult<ApiState> {
    let store = Store::new(&config.database_path)?;
    let liquid_agent = Arc::new(LiquidAgentGrpcClient::new(
        config.liquid_agent_endpoint.clone(),
        config.transport_backend,
    ));
    let proof_engine = build_proof_engine(config.proof_backend)?;
    let enclave_manager = build_enclave_manager(config.tee_backend, proof_engine.clone(), config)?;
    let pricing_oracle: Arc<dyn PricingOracle> =
        Arc::new(GrpcPricingOracle::new(config.pricing_endpoint.clone()));

    Ok(ApiState::new(
        store,
        liquid_agent,
        proof_engine,
        enclave_manager,
        pricing_oracle,
        config.default_interface.clone(),
        config.transport_backend,
        config.tee_backend,
    ))
}

pub async fn serve(listener: tokio::net::TcpListener, state: ApiState) -> AnyhowResult<()> {
    axum::serve(listener, router(state))
        .await
        .map_err(|err| anyhow!("control-plane-api server failed: {err}"))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn contract_request(
    State(state): State<ApiState>,
    Json(request): Json<ContractRequest>,
) -> ApiResult<Json<ContractOffer>> {
    let offer = state
        .negotiation
        .handle_request(request)
        .await
        .map_err(ApiError::bad_request)?;
    Ok(Json(offer))
}

async fn contract_finalize(
    State(state): State<ApiState>,
    Json(offer): Json<ContractOffer>,
) -> ApiResult<Json<FinalizeContractResponse>> {
    let negotiated = state
        .negotiation
        .finalize_profiled(offer)
        .await
        .map_err(ApiError::bad_request)?;
    state
        .store
        .upsert_agreement(&negotiated.agreement, &negotiated.requested_profile)
        .map_err(ApiError::internal)?;

    Ok(Json(FinalizeContractResponse {
        agreement: negotiated.agreement,
        requested_profile: negotiated.requested_profile,
    }))
}

async fn transfer_start(
    State(state): State<ApiState>,
    Json(request): Json<TransferRequest>,
) -> ApiResult<Json<TransferStartResponse>> {
    let (mut agreement, _) = state
        .store
        .get_agreement(&request.agreement_id.0)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("agreement not found"))?;

    agreement.liquid_policy.transport_guard.protocol = request.protocol;
    if request.session_port.is_some() {
        agreement.liquid_policy.transport_guard.session_port = request.session_port;
    }

    let handle = state
        .orchestrator
        .activate_agreement(&agreement, &state.default_interface)
        .await
        .map_err(ApiError::internal)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let response = TransferStartResponse {
        transfer_start: TransferStart {
            transfer_id: transfer_id.clone(),
            agreement_id: agreement.agreement_id.clone(),
            protocol: request.protocol,
            session_port: handle.session_port,
        },
        enforcement_handle: handle,
    };

    state
        .store
        .insert_transfer(&transfer_id, &agreement.agreement_id.0, &request, &response)
        .map_err(ApiError::internal)?;

    Ok(Json(response))
}

async fn transfer_complete(
    State(state): State<ApiState>,
    Path(transfer_id): Path<String>,
) -> ApiResult<Json<TransferCompletion>> {
    let handle = state
        .store
        .get_transfer_handle(&transfer_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("transfer session not found"))?;
    state
        .liquid_agent
        .revoke(&handle)
        .await
        .map_err(ApiError::internal)?;
    state
        .store
        .complete_transfer(&transfer_id)
        .map_err(ApiError::internal)?;

    Ok(Json(TransferCompletion { transfer_id }))
}

async fn create_lineage_job(
    State(state): State<ApiState>,
    Json(request): Json<LineageJobRequest>,
) -> ApiResult<(StatusCode, Json<LineageJobAccepted>)> {
    let requested_profile = RequestedExecutionProfile::from_agreement(&request.agreement);
    state
        .store
        .upsert_agreement(&request.agreement, &requested_profile)
        .map_err(ApiError::internal)?;

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

    tokio::spawn(run_lineage_job(state.clone(), job_id.clone(), request));

    Ok((
        StatusCode::ACCEPTED,
        Json(LineageJobAccepted {
            job_id,
            state: LineageJobState::Pending,
        }),
    ))
}

async fn get_lineage_job(
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

async fn verify_evidence_chain(
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

async fn get_settlement(
    State(state): State<ApiState>,
    Path(agreement_id): Path<String>,
) -> ApiResult<Json<SettlementDecision>> {
    let settlement = state
        .store
        .get_settlement(&agreement_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("agreement not found"))?;
    Ok(Json(settlement))
}

async fn run_lineage_job(state: ApiState, job_id: String, request: LineageJobRequest) {
    if let Err(err) = state
        .store
        .update_job_state(&job_id, LineageJobState::Running)
    {
        tracing::error!(job_id, error = %err, "failed to mark lineage job as running");
        return;
    }

    let iface = request
        .iface
        .clone()
        .unwrap_or_else(|| state.default_interface.clone());

    let job = state
        .orchestrator
        .run_batch_csv_lineage(BatchLineageRequest {
            agreement: request.agreement.clone(),
            iface,
            input_csv: request.input_csv_utf8.clone().into_bytes(),
            manifest: request.manifest.clone(),
            current_price: request.current_price,
            metrics: request.metrics.clone(),
            prior_receipt: request.prior_receipt.clone(),
        })
        .await;

    match job {
        Ok(result) => {
            let enforcement_status =
                match state.liquid_agent.status(&result.enforcement_handle).await {
                    Ok(status) => status,
                    Err(err) => {
                        let _ = state.store.set_job_error(&job_id, &err.to_string());
                        tracing::error!(job_id, error = %err, "failed to fetch enforcement status");
                        return;
                    }
                };

            if let Err(err) = state.liquid_agent.revoke(&result.enforcement_handle).await {
                tracing::warn!(job_id, error = %err, "failed to revoke post-job enforcement");
            }

            let transformed_csv_utf8 = match String::from_utf8(result.transformed_csv.clone()) {
                Ok(csv) => csv,
                Err(err) => {
                    let message = format!("transformed CSV is not valid UTF-8: {err}");
                    let _ = state.store.set_job_error(&job_id, &message);
                    tracing::error!(job_id, error = %message, "failed to persist lineage job");
                    return;
                }
            };

            let record = LineageJobResult {
                agreement_id: request.agreement.agreement_id.0.clone(),
                actual_execution_profile: state
                    .actual_execution_profile(result.price_decision.pricing_mode),
                enforcement_handle: result.enforcement_handle,
                enforcement_status,
                transformed_csv_utf8,
                proof_bundle: result.proof_bundle,
                price_decision: result.price_decision,
                sanction_proposal: result.sanction_proposal,
                settlement_allowed: result.settlement_allowed,
                completed_at: chrono::Utc::now(),
            };

            if let Err(err) =
                state
                    .store
                    .set_job_result(&job_id, &request.agreement.agreement_id.0, &record)
            {
                tracing::error!(job_id, error = %err, "failed to store lineage result");
            }
        }
        Err(err) => {
            if let Err(store_err) = state.store.set_job_error(&job_id, &err.to_string()) {
                tracing::error!(
                    job_id,
                    error = %store_err,
                    original_error = %err,
                    "failed to persist lineage job failure"
                );
            }
        }
    }
}

fn build_proof_engine(proof_backend: ProofBackend) -> AnyhowResult<Arc<dyn ProofEngine>> {
    match proof_backend {
        ProofBackend::DevReceipt => Ok(Arc::new(DevReceiptProofEngine::new())),
        ProofBackend::RiscZero => {
            #[cfg(feature = "risc0")]
            {
                Ok(Arc::new(Risc0ProofEngine::new()))
            }

            #[cfg(not(feature = "risc0"))]
            {
                Err(anyhow!(
                    "proof backend `risc_zero` requires building control-plane-api with the `risc0` feature"
                ))
            }
        }
        ProofBackend::None => Err(anyhow!("proof backend `none` is not valid for Phase 3")),
    }
}

fn build_enclave_manager(
    tee_backend: TeeBackend,
    proof_engine: Arc<dyn ProofEngine>,
    config: &config::ControlPlaneApiConfig,
) -> AnyhowResult<Arc<dyn EnclaveManager>> {
    match tee_backend {
        TeeBackend::NitroDev => Ok(Arc::new(NitroEnclaveManager::new_dev(proof_engine))),
        TeeBackend::NitroLive => {
            let path = config
                .nitro_live_attestation_path
                .as_ref()
                .ok_or_else(|| anyhow!("nitro_live requires `nitro_live_attestation_path`"))?;
            Ok(Arc::new(NitroEnclaveManager::new_live(
                proof_engine,
                load_live_attestation_material(path)?,
            )))
        }
        TeeBackend::None => Err(anyhow!("tee backend `none` is not valid for Phase 3")),
    }
}

fn load_live_attestation_material(path: &str) -> AnyhowResult<NitroLiveAttestationMaterial> {
    #[derive(serde::Deserialize)]
    struct FixtureMeasurements {
        image_hash_hex: String,
        pcrs: std::collections::BTreeMap<u16, String>,
        debug: bool,
    }

    #[derive(serde::Deserialize)]
    struct FixtureMaterial {
        enclave_id: String,
        expected_image_hash_hex: String,
        measurements: FixtureMeasurements,
        raw_attestation_document_utf8: String,
        certificate_chain_pem: Vec<String>,
        timestamp: String,
    }

    let raw = std::fs::read_to_string(path)?;
    let fixture: FixtureMaterial = serde_json::from_str(&raw)?;
    Ok(NitroLiveAttestationMaterial {
        enclave_id: fixture.enclave_id,
        expected_image_hash: lsdc_common::crypto::Sha256Hash::from_hex(
            &fixture.expected_image_hash_hex,
        )
        .map_err(|err| anyhow!(err))?,
        measurements: lsdc_common::crypto::AttestationMeasurements {
            image_hash: lsdc_common::crypto::Sha256Hash::from_hex(
                &fixture.measurements.image_hash_hex,
            )
            .map_err(|err| anyhow!(err))?,
            pcrs: fixture.measurements.pcrs,
            debug: fixture.measurements.debug,
        },
        raw_attestation_document: fixture.raw_attestation_document_utf8.into_bytes(),
        certificate_chain_pem: fixture.certificate_chain_pem,
        timestamp: chrono::DateTime::parse_from_rfc3339(&fixture.timestamp)?
            .with_timezone(&chrono::Utc),
    })
}

type ApiResult<T> = std::result::Result<T, ApiError>;

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(err: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    fn internal(err: impl ToString) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
