use crate::state::ApiState;
use control_plane::orchestrator::BatchLineageRequest;
use lsdc_common::crypto::AttestationEvidence;
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

    async fn get_latest_attestation_evidence(
        &self,
        session_id: String,
    ) -> Option<AttestationEvidence> {
        let store = self.state.store.clone();
        let lookup_session_id = session_id.clone();
        match tokio::task::spawn_blocking(move || {
            store.get_latest_attestation_evidence(&lookup_session_id)
        })
        .await
        {
            Ok(Ok(evidence)) => evidence,
            Ok(Err(err)) => {
                tracing::warn!(
                    session_id,
                    error = %err,
                    "failed to load attestation evidence from store"
                );
                None
            }
            Err(err) => {
                tracing::warn!(
                    session_id,
                    error = %err,
                    "attestation evidence lookup task failed"
                );
                None
            }
        }
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
            execution_bindings,
        } = request;

        let iface = iface.unwrap_or_else(|| self.state.default_interface.clone());
        let attestation_evidence = if let Some(bindings) = execution_bindings.as_ref() {
            self.get_latest_attestation_evidence(bindings.session.session_id.to_string())
                .await
        } else {
            None
        };

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
                attestation_evidence,
                execution_bindings: execution_bindings.clone(),
            })
            .await;

        match job {
            Ok(result) => {
                self.persist_success(job_id, agreement, execution_bindings, result)
                    .await
            }
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
        requested_execution_bindings: Option<lsdc_ports::ExecutionBindings>,
        result: control_plane::orchestrator::BatchLineageResult,
    ) {
        let control_plane::orchestrator::BatchLineageResult {
            enforcement_handle: handle,
            execution_bindings: actual_execution_bindings,
            transformed_csv,
            proof_bundle,
            execution_evidence,
            price_decision,
            sanction_proposal,
            settlement_allowed,
        } = result;
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

        let transformed_csv_utf8 = match String::from_utf8(transformed_csv.clone()) {
            Ok(csv) => csv,
            Err(err) => {
                let message = format!("transformed CSV is not valid UTF-8: {err}");
                let _ = self.state.store.set_job_error(&job_id, &message);
                tracing::error!(job_id, error = %message, "failed to persist lineage job");
                return;
            }
        };

        let mut record = LineageJobResult {
            agreement_id: agreement.agreement_id.0.clone(),
            actual_execution_profile: self
                .state
                .actual_execution_profile(price_decision.pricing_mode),
            enforcement_handle: handle,
            enforcement_status,
            policy_execution: Some(self.state.policy_execution_for(&agreement)),
            resolved_transport,
            enforcement_runtime,
            transformed_csv_utf8,
            proof_bundle,
            session_id: actual_execution_bindings
                .as_ref()
                .map(|bindings| bindings.session.session_id.to_string()),
            evidence_root_hash: None,
            transparency_receipt_hash: None,
            price_decision,
            sanction_proposal,
            settlement_allowed,
            completed_at: chrono::Utc::now(),
        };

        let execution_bindings = actual_execution_bindings
            .as_ref()
            .or(requested_execution_bindings.as_ref());

        if let Some(bindings) = execution_bindings {
            let session_id = bindings.session.session_id.to_string();
            self.state
                .store
                .upsert_execution_session(&bindings.session, bindings.challenge.as_ref())
                .ok();
            let attestation_already_persisted = self
                .get_latest_attestation_evidence(session_id.clone())
                .await
                .is_some();
            if !attestation_already_persisted
                && self
                    .state
                    .submit_attestation_evidence(
                        &session_id,
                        &execution_evidence.attestation_evidence,
                    )
                    .is_err()
            {
                tracing::warn!(
                    job_id,
                    "failed to persist attestation evidence for execution session"
                );
            }

            let execution_overlay = match self.state.execution_overlay_for(&agreement) {
                Ok(overlay) => overlay,
                Err(err) => {
                    tracing::error!(job_id, error = %err, "failed to derive execution overlay");
                    return;
                }
            };
            let (dag, transparency_receipt) = match self.state.build_evidence_dag_for_lineage(
                &job_id,
                &agreement,
                &execution_overlay,
                bindings,
                &execution_evidence,
                &record.price_decision,
            ) {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(job_id, error = %err, "failed to build evidence dag");
                    return;
                }
            };
            let transparency_receipt_hash = match transparency_receipt.canonical_hash() {
                Ok(hash) => hash,
                Err(err) => {
                    tracing::error!(job_id, error = %err, "failed to hash transparency receipt");
                    return;
                }
            };
            record.evidence_root_hash = Some(dag.root_hash.clone());
            record.transparency_receipt_hash = Some(transparency_receipt_hash.clone());
            record.proof_bundle.evidence_root_hash = Some(dag.root_hash);
            record.proof_bundle.transparency_receipt_hash = Some(transparency_receipt_hash);
        }

        if let Err(err) =
            self.state
                .store
                .set_job_result(&job_id, &agreement.agreement_id.0, &record)
        {
            tracing::error!(job_id, error = %err, "failed to store lineage result");
        }
    }
}
