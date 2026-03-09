use crate::state::ApiState;
use control_plane::orchestrator::BatchLineageRequest;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use lsdc_ports::DataPlane;
use lsdc_service_types::{LineageJobRequest, LineageJobResult, LineageJobState};

#[derive(Clone)]
pub struct LineageJobRunner {
    state: ApiState,
}

impl LineageJobRunner {
    pub fn new(state: ApiState) -> Self {
        Self { state }
    }

    pub async fn resume_pending_jobs(&self) -> Result<()> {
        for record in self.state.store.list_restartable_jobs()? {
            self.spawn(record.job_id, record.request);
        }
        Ok(())
    }

    pub fn spawn(&self, job_id: String, request: LineageJobRequest) {
        let runner = self.clone();
        tokio::spawn(async move {
            runner.run(job_id, request).await;
        });
    }

    async fn run(self, job_id: String, request: LineageJobRequest) {
        if let Err(err) = self
            .state
            .store
            .update_job_state(&job_id, LineageJobState::Running)
        {
            tracing::error!(job_id, error = %err, "failed to mark lineage job as running");
            return;
        }

        let LineageJobRequest {
            agreement,
            iface,
            input_csv_utf8,
            manifest,
            current_price,
            metrics,
            prior_receipt,
        } = request;

        let iface = iface.unwrap_or_else(|| self.state.default_interface.clone());

        let job = self
            .state
            .orchestrator
            .run_batch_csv_lineage(BatchLineageRequest {
                agreement: agreement.clone(),
                iface,
                input_csv: input_csv_utf8.into_bytes(),
                manifest,
                current_price,
                metrics,
                prior_receipt,
            })
            .await;

        match job {
            Ok(result) => self.persist_success(job_id, agreement, result).await,
            Err(err) => {
                if let Err(store_err) = self.state.store.set_job_error(&job_id, &err.to_string()) {
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

    async fn persist_success(
        &self,
        job_id: String,
        agreement: ContractAgreement,
        result: control_plane::orchestrator::BatchLineageResult,
    ) {
        let handle = result.enforcement_handle;
        let resolved_transport = handle.resolved_transport.clone();
        let enforcement_runtime = handle.runtime.clone();
        let enforcement_status = match self.state.liquid_agent.status(&handle).await {
            Ok(status) => status,
            Err(err) => {
                let _ = self.state.store.set_job_error(&job_id, &err.to_string());
                tracing::error!(job_id, error = %err, "failed to fetch enforcement status");
                return;
            }
        };

        if let Err(err) = self.state.liquid_agent.revoke(&handle).await {
            tracing::warn!(job_id, error = %err, "failed to revoke post-job enforcement");
        }

        let transformed_csv_utf8 = match String::from_utf8(result.transformed_csv.clone()) {
            Ok(csv) => csv,
            Err(err) => {
                let message = format!("transformed CSV is not valid UTF-8: {err}");
                let _ = self.state.store.set_job_error(&job_id, &message);
                tracing::error!(job_id, error = %message, "failed to persist lineage job");
                return;
            }
        };

        let record = LineageJobResult {
            agreement_id: agreement.agreement_id.0.clone(),
            actual_execution_profile: self
                .state
                .actual_execution_profile(result.price_decision.pricing_mode),
            enforcement_handle: handle,
            enforcement_status,
            policy_execution: Some(self.state.policy_execution_for(&agreement)),
            resolved_transport,
            enforcement_runtime,
            transformed_csv_utf8,
            proof_bundle: result.proof_bundle,
            price_decision: result.price_decision,
            sanction_proposal: result.sanction_proposal,
            settlement_allowed: result.settlement_allowed,
            completed_at: chrono::Utc::now(),
        };

        if let Err(err) =
            self.state
                .store
                .set_job_result(&job_id, &agreement.agreement_id.0, &record)
        {
            tracing::error!(job_id, error = %err, "failed to store lineage result");
        }
    }
}
