use lsdc_common::dsp::{ContractAgreement, TransferRequest};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::RequestedExecutionProfile;
use lsdc_common::service::{
    LineageJobRecord, LineageJobResult, LineageJobState, SettlementDecision, TransferStartResponse,
};
use lsdc_common::traits::EnforcementHandle;
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
