use lsdc_common::dsp::{ContractAgreement, TransferRequest};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::RequestedExecutionProfile;
use lsdc_ports::EnforcementHandle;
use lsdc_service_types::{
    LineageJobRecord, LineageJobResult, LineageJobState, SettlementDecision, TransferStartResponse,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct Store {
    connection: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn new(path: &str) -> Result<Self> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
        }

        let connection =
            Connection::open(path).map_err(|err| LsdcError::Database(err.to_string()))?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn upsert_agreement(
        &self,
        agreement: &ContractAgreement,
        requested_profile: &RequestedExecutionProfile,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "INSERT INTO agreements (
                agreement_id,
                agreement_json,
                requested_profile_json,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(agreement_id) DO UPDATE SET
                agreement_json = excluded.agreement_json,
                requested_profile_json = excluded.requested_profile_json,
                updated_at = excluded.updated_at",
                params![
                    agreement.agreement_id.0,
                    to_json(agreement)?,
                    to_json(requested_profile)?,
                    now
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_agreement(
        &self,
        agreement_id: &str,
    ) -> Result<Option<(ContractAgreement, RequestedExecutionProfile)>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT agreement_json, requested_profile_json
                 FROM agreements
                 WHERE agreement_id = ?1",
                params![agreement_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;

        row.map(|(agreement_json, requested_profile_json)| {
            Ok((
                from_json(&agreement_json)?,
                from_json(&requested_profile_json)?,
            ))
        })
        .transpose()
    }

    pub fn insert_transfer(
        &self,
        transfer_id: &str,
        agreement_id: &str,
        request: &TransferRequest,
        response: &TransferStartResponse,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "INSERT INTO transfer_sessions (
                transfer_id,
                agreement_id,
                request_json,
                transfer_start_json,
                enforcement_handle_json,
                state,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)",
                params![
                    transfer_id,
                    agreement_id,
                    to_json(request)?,
                    to_json(&response.transfer_start)?,
                    to_json(&response.enforcement_handle)?,
                    now
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_transfer_handle(&self, transfer_id: &str) -> Result<Option<EnforcementHandle>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT enforcement_handle_json
                 FROM transfer_sessions
                 WHERE transfer_id = ?1",
                params![transfer_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;

        row.map(|json| from_json(&json)).transpose()
    }

    pub fn complete_transfer(&self, transfer_id: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "UPDATE transfer_sessions
             SET state = 'completed', completed_at = ?2
             WHERE transfer_id = ?1",
                params![transfer_id, now],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn insert_job(&self, record: &LineageJobRecord) -> Result<()> {
        self.lock()?
            .execute(
                "INSERT INTO lineage_jobs (
                job_id,
                agreement_id,
                state,
                request_json,
                result_json,
                error_text,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, ?6)",
                params![
                    record.job_id,
                    record.agreement_id,
                    job_state_value(&record.state),
                    to_json(&record.request)?,
                    record.created_at.to_rfc3339(),
                    record.updated_at.to_rfc3339()
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn update_job_state(&self, job_id: &str, state: LineageJobState) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "UPDATE lineage_jobs
             SET state = ?2, updated_at = ?3
             WHERE job_id = ?1",
                params![job_id, job_state_value(&state), now],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn set_job_result(
        &self,
        job_id: &str,
        agreement_id: &str,
        result: &LineageJobResult,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let mut connection = self.lock()?;
        let tx = connection.transaction().map_err(sqlite_error)?;

        tx.execute(
            "UPDATE lineage_jobs
             SET state = 'succeeded',
                 result_json = ?2,
                 error_text = NULL,
                 updated_at = ?3
             WHERE job_id = ?1",
            params![job_id, to_json(result)?, now],
        )
        .map_err(sqlite_error)?;

        tx.execute(
            "INSERT OR REPLACE INTO proof_bundles (job_id, agreement_id, proof_bundle_json, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![job_id, agreement_id, to_json(&result.proof_bundle)?, now],
        )
        .map_err(sqlite_error)?;

        tx.execute(
            "INSERT OR REPLACE INTO price_decisions (job_id, agreement_id, price_decision_json, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![job_id, agreement_id, to_json(&result.price_decision)?, now],
        )
        .map_err(sqlite_error)?;

        tx.execute(
            "INSERT OR REPLACE INTO sanction_proposals (job_id, agreement_id, proposal_json, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                job_id,
                agreement_id,
                option_to_json(&result.sanction_proposal)?,
                now
            ],
        )
        .map_err(sqlite_error)?;

        tx.commit().map_err(sqlite_error)?;
        Ok(())
    }

    pub fn set_job_error(&self, job_id: &str, error: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "UPDATE lineage_jobs
             SET state = 'failed',
                 error_text = ?2,
                 updated_at = ?3
             WHERE job_id = ?1",
                params![job_id, error, now],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_job(&self, job_id: &str) -> Result<Option<LineageJobRecord>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT agreement_id, state, request_json, result_json, error_text, created_at, updated_at
                 FROM lineage_jobs
                 WHERE job_id = ?1",
                params![job_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;

        row.map(
            |(
                agreement_id,
                state,
                request_json,
                result_json,
                error_text,
                created_at,
                updated_at,
            )| {
                Ok(LineageJobRecord {
                    job_id: job_id.to_string(),
                    agreement_id,
                    state: parse_job_state(&state)?,
                    request: from_json(&request_json)?,
                    result: result_json
                        .as_deref()
                        .map(from_json::<LineageJobResult>)
                        .transpose()?,
                    error: error_text,
                    created_at: parse_timestamp(&created_at)?,
                    updated_at: parse_timestamp(&updated_at)?,
                })
            },
        )
        .transpose()
    }

    /// Atomically claims all stale jobs last updated before `cutoff` so each
    /// one is only requeued once across concurrent startup attempts.
    pub fn claim_stale_jobs(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
        claimed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<LineageJobRecord>> {
        let cutoff = cutoff.to_rfc3339();
        let claimed_at_text = claimed_at.to_rfc3339();
        let mut connection = self.lock()?;
        let tx = connection.transaction().map_err(sqlite_error)?;

        let rows = {
            let mut stmt = tx
                .prepare(
                    "SELECT job_id, agreement_id, state, request_json, result_json, \
                     error_text, created_at, updated_at
                     FROM lineage_jobs
                     WHERE state IN ('pending', 'running') AND updated_at < ?1
                     ORDER BY created_at ASC",
                )
                .map_err(sqlite_error)?;

            let rows = stmt
                .query_map(params![&cutoff], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                })
                .map_err(sqlite_error)?;

            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sqlite_error)?
        };

        let mut claimed_jobs = Vec::new();
        for (
            job_id,
            agreement_id,
            _state,
            request_json,
            result_json,
            error_text,
            created_at,
            updated_at,
        ) in rows
        {
            let updated = tx
                .execute(
                    "UPDATE lineage_jobs
                     SET state = 'running', updated_at = ?2
                     WHERE job_id = ?1
                       AND updated_at = ?3
                       AND state IN ('pending', 'running')",
                    params![&job_id, &claimed_at_text, &updated_at],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                continue;
            }

            claimed_jobs.push(LineageJobRecord {
                job_id,
                agreement_id,
                state: LineageJobState::Running,
                request: from_json(&request_json)?,
                result: result_json
                    .as_deref()
                    .map(from_json::<LineageJobResult>)
                    .transpose()?,
                error: error_text,
                created_at: parse_timestamp(&created_at)?,
                updated_at: claimed_at,
            });
        }

        tx.commit().map_err(sqlite_error)?;
        Ok(claimed_jobs)
    }

    pub fn get_settlement(&self, agreement_id: &str) -> Result<Option<SettlementDecision>> {
        if self.get_agreement(agreement_id)?.is_none() {
            return Ok(None);
        }

        let row = self
            .lock()?
            .query_row(
                "SELECT job_id, result_json
                 FROM lineage_jobs
                 WHERE agreement_id = ?1 AND state = 'succeeded'
                 ORDER BY updated_at DESC
                 LIMIT 1",
                params![agreement_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;

        if let Some((job_id, result_json)) = row {
            let result: LineageJobResult = from_json(&result_json)?;
            return Ok(Some(SettlementDecision {
                agreement_id: agreement_id.to_string(),
                latest_job_id: Some(job_id),
                settlement_allowed: result.settlement_allowed,
                actual_execution_profile: Some(result.actual_execution_profile),
                policy_execution: result.policy_execution,
                resolved_transport: result.resolved_transport,
                enforcement_runtime: result.enforcement_runtime,
                price_decision: Some(result.price_decision),
                sanction_proposal: result.sanction_proposal,
                proof_bundle: Some(result.proof_bundle),
            }));
        }

        Ok(Some(SettlementDecision {
            agreement_id: agreement_id.to_string(),
            latest_job_id: None,
            settlement_allowed: false,
            actual_execution_profile: None,
            policy_execution: None,
            resolved_transport: None,
            enforcement_runtime: None,
            price_decision: None,
            sanction_proposal: None,
            proof_bundle: None,
        }))
    }

    fn migrate(&self) -> Result<()> {
        self.lock()?
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS agreements (
                    agreement_id TEXT PRIMARY KEY,
                    agreement_json TEXT NOT NULL,
                    requested_profile_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS transfer_sessions (
                    transfer_id TEXT PRIMARY KEY,
                    agreement_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    transfer_start_json TEXT NOT NULL,
                    enforcement_handle_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS lineage_jobs (
                    job_id TEXT PRIMARY KEY,
                    agreement_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT,
                    error_text TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS proof_bundles (
                    job_id TEXT PRIMARY KEY,
                    agreement_id TEXT NOT NULL,
                    proof_bundle_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS price_decisions (
                    job_id TEXT PRIMARY KEY,
                    agreement_id TEXT NOT NULL,
                    price_decision_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sanction_proposals (
                    job_id TEXT PRIMARY KEY,
                    agreement_id TEXT NOT NULL,
                    proposal_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_lineage_jobs_agreement_id
                ON lineage_jobs (agreement_id, updated_at DESC);

                CREATE INDEX IF NOT EXISTS idx_lineage_jobs_state_updated_created_at
                ON lineage_jobs (state, updated_at, created_at);
                ",
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| LsdcError::Database("sqlite connection mutex poisoned".into()))
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(LsdcError::from)
}

fn option_to_json<T: serde::Serialize>(value: &Option<T>) -> Result<Option<String>> {
    value.as_ref().map(to_json).transpose()
}

fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(LsdcError::from)
}

fn sqlite_error(err: rusqlite::Error) -> LsdcError {
    LsdcError::Database(err.to_string())
}

fn job_state_value(state: &LineageJobState) -> &'static str {
    match state {
        LineageJobState::Pending => "pending",
        LineageJobState::Running => "running",
        LineageJobState::Succeeded => "succeeded",
        LineageJobState::Failed => "failed",
    }
}

fn parse_job_state(value: &str) -> Result<LineageJobState> {
    match value {
        "pending" => Ok(LineageJobState::Pending),
        "running" => Ok(LineageJobState::Running),
        "succeeded" => Ok(LineageJobState::Succeeded),
        "failed" => Ok(LineageJobState::Failed),
        other => Err(LsdcError::Database(format!(
            "unknown lineage job state `{other}`"
        ))),
    }
}

fn parse_timestamp(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .map_err(|err| LsdcError::Database(format!("invalid stored timestamp: {err}")))
}

#[cfg(test)]
mod tests {
    use super::Store;
    use chrono::{Duration, Utc};
    use lsdc_common::dsp::{ContractAgreement, TransportProtocol};
    use lsdc_common::liquid::{
        CsvTransformManifest, LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard,
    };
    use lsdc_common::odrl::ast::PolicyId;
    use lsdc_ports::TrainingMetrics;
    use lsdc_service_types::{LineageJobRecord, LineageJobRequest, LineageJobState};
    use serde_json::json;

    fn sample_lineage_job_request() -> LineageJobRequest {
        let now = Utc::now();
        LineageJobRequest {
            agreement: ContractAgreement {
                agreement_id: PolicyId("agreement-stale".into()),
                asset_id: "asset-csv".into(),
                provider_id: "did:web:provider".into(),
                consumer_id: "did:web:consumer".into(),
                odrl_policy: json!({"permission": [{"action": "read"}]}),
                policy_hash: "policy-hash".into(),
                evidence_requirements: vec![],
                liquid_policy: LiquidPolicyIr {
                    transport_guard: TransportGuard {
                        allow_read: true,
                        allow_transfer: true,
                        packet_cap: None,
                        byte_cap: None,
                        allowed_regions: vec![],
                        valid_until: None,
                        protocol: TransportProtocol::Udp,
                        session_port: Some(31_337),
                    },
                    transform_guard: TransformGuard {
                        allow_anonymize: true,
                        allowed_purposes: vec!["analytics".into()],
                        required_ops: vec![],
                    },
                    runtime_guard: RuntimeGuard {
                        delete_after_seconds: None,
                        evidence_requirements: vec![],
                        approval_required: false,
                    },
                },
            },
            iface: Some("lo".into()),
            input_csv_utf8: "id,value\n1,2\n".into(),
            manifest: CsvTransformManifest {
                dataset_id: "dataset-1".into(),
                purpose: "analytics".into(),
                ops: vec![],
            },
            current_price: 42.0,
            metrics: TrainingMetrics {
                loss_with_dataset: 0.1,
                loss_without_dataset: 0.2,
                accuracy_with_dataset: 0.9,
                accuracy_without_dataset: 0.8,
                model_run_id: "model-1".into(),
                metrics_window_started_at: now,
                metrics_window_ended_at: now,
            },
            prior_receipt: None,
        }
    }

    fn sample_stale_record(
        job_id: &str,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> LineageJobRecord {
        let request = sample_lineage_job_request();
        LineageJobRecord {
            job_id: job_id.into(),
            agreement_id: request.agreement.agreement_id.0.clone(),
            state: LineageJobState::Pending,
            request,
            result: None,
            error: None,
            created_at: updated_at - Duration::minutes(1),
            updated_at,
        }
    }

    #[test]
    fn test_claim_stale_jobs_claims_each_job_once() {
        let store = Store::new(":memory:").unwrap();
        let stale_at = Utc::now() - Duration::minutes(5);
        let cutoff = stale_at + Duration::minutes(1);
        let claimed_at = cutoff + Duration::seconds(1);
        let job_id = "job-stale-1";

        store
            .insert_job(&sample_stale_record(job_id, stale_at))
            .unwrap();

        let claimed = store.claim_stale_jobs(cutoff, claimed_at).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].job_id, job_id);
        assert_eq!(claimed[0].state, LineageJobState::Running);
        assert_eq!(claimed[0].updated_at, claimed_at);

        let claimed_again = store
            .claim_stale_jobs(cutoff, claimed_at + Duration::seconds(1))
            .unwrap();
        assert!(claimed_again.is_empty());

        let persisted = store.get_job(job_id).unwrap().unwrap();
        assert_eq!(persisted.state, LineageJobState::Running);
        assert_eq!(persisted.updated_at, claimed_at);
    }
}
