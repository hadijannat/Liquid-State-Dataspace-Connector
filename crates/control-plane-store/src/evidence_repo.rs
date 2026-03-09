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
    let proof_bundle_json = to_json(&result.proof_bundle)?;
    let price_decision_json = to_json(&result.price_decision)?;
    let legacy_sanction_json = option_to_json(&result.sanction_proposal)?;
    let canonical_sanction_json = to_json(&result.sanction_proposal)?;

    tx.execute(
        "INSERT OR REPLACE INTO proof_bundles (job_id, agreement_id, proof_bundle_json, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![job_id, agreement_id, proof_bundle_json, now],
    )
    .map_err(sqlite_error)?;

    tx.execute(
        "INSERT OR REPLACE INTO price_decisions (job_id, agreement_id, price_decision_json, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![job_id, agreement_id, price_decision_json, now],
    )
    .map_err(sqlite_error)?;

    tx.execute(
        "INSERT OR REPLACE INTO sanction_proposals (job_id, agreement_id, proposal_json, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            job_id,
            agreement_id,
            legacy_sanction_json,
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
        &proof_bundle_json,
        now,
    )?;
    persist_record(
        tx,
        job_id,
        agreement_id,
        "price_decision",
        1,
        Some(result.price_decision.signature_hex.clone()),
        &price_decision_json,
        now,
    )?;
    persist_record(
        tx,
        job_id,
        agreement_id,
        "sanction_proposal",
        1,
        result
            .sanction_proposal
            .as_ref()
            .map(|proposal| proposal.evidence_hash.to_hex()),
        &canonical_sanction_json,
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
