use crate::evidence_repo::persist_job_evidence;
use crate::ser::{from_json, parse_timestamp, to_json};
use crate::{sqlite_error, Store};
use lsdc_common::error::{LsdcError, Result};
use lsdc_service_types::{LineageJobRecord, LineageJobResult, LineageJobState};
use rusqlite::{params, OptionalExtension};

impl Store {
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

        persist_job_evidence(&tx, job_id, agreement_id, result, &now)?;

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

    pub fn list_restartable_jobs(&self) -> Result<Vec<LineageJobRecord>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT job_id, agreement_id, state, request_json, result_json, error_text, created_at, updated_at
                 FROM lineage_jobs
                 WHERE state IN ('pending', 'running')
                 ORDER BY created_at ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
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

        let mut records = Vec::new();
        for row in rows {
            let (
                job_id,
                agreement_id,
                state,
                request_json,
                result_json,
                error_text,
                created_at,
                updated_at,
            ) = row.map_err(sqlite_error)?;
            records.push(LineageJobRecord {
                job_id,
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
            });
        }

        Ok(records)
    }
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
