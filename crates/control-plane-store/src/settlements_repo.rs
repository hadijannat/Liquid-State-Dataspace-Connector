use crate::ser::from_json;
use crate::{sqlite_error, Store};
use lsdc_common::error::Result;
use lsdc_service_types::{LineageJobResult, SettlementDecision};
use rusqlite::{params, OptionalExtension};

impl Store {
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
                session_id: result.session_id,
                evidence_root_hash: result.evidence_root_hash,
                transparency_receipt_hash: result.transparency_receipt_hash,
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
            session_id: None,
            evidence_root_hash: None,
            transparency_receipt_hash: None,
        }))
    }
}
