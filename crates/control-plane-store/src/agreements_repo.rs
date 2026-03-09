use crate::ser::{from_json, to_json};
use crate::{sqlite_error, Store};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use lsdc_common::execution::RequestedExecutionProfile;
use rusqlite::{params, OptionalExtension};

impl Store {
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
}
