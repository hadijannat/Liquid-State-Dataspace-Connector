use crate::ser::{from_json, to_json};
use crate::{sqlite_error, Store};
use lsdc_common::dsp::TransferRequest;
use lsdc_common::error::Result;
use lsdc_ports::EnforcementHandle;
use lsdc_service_types::TransferStartResponse;
use rusqlite::{params, OptionalExtension};

impl Store {
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
}
