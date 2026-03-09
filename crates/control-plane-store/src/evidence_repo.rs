use crate::ser::{option_to_json, to_json};
use crate::sqlite_error;
use lsdc_common::error::Result;
use lsdc_service_types::LineageJobResult;
use rusqlite::{params, Transaction};

pub(crate) fn persist_job_evidence(
    tx: &Transaction<'_>,
    job_id: &str,
    agreement_id: &str,
    result: &LineageJobResult,
    now: &str,
) -> Result<()> {
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

    persist_record(
        tx,
        job_id,
        agreement_id,
        "proof_bundle",
        1,
        Some(result.proof_bundle.job_audit_hash.to_hex()),
        &to_json(&result.proof_bundle)?,
        now,
    )?;
    persist_record(
        tx,
        job_id,
        agreement_id,
        "price_decision",
        1,
        Some(result.price_decision.signature_hex.clone()),
        &to_json(&result.price_decision)?,
        now,
    )?;
    persist_record(
        tx,
        job_id,
        agreement_id,
        "sanction_proposal",
        1,
        result.sanction_proposal.as_ref().map(|proposal| proposal.evidence_hash.to_hex()),
        &to_json(&result.sanction_proposal)?,
        now,
    )?;

    Ok(())
}

fn persist_record(
    tx: &Transaction<'_>,
    job_id: &str,
    agreement_id: &str,
    evidence_kind: &str,
    schema_version: i64,
    anchor_hash: Option<String>,
    payload_json: &str,
    now: &str,
) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO evidence_records (
            job_id,
            agreement_id,
            evidence_kind,
            schema_version,
            anchor_hash,
            payload_json,
            created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            job_id,
            agreement_id,
            evidence_kind,
            schema_version,
            anchor_hash,
            payload_json,
            now
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}
