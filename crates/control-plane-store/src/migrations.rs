use crate::{sqlite_error, Store};
use lsdc_common::error::Result;

impl Store {
    pub(crate) fn migrate(&self) -> Result<()> {
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

                CREATE TABLE IF NOT EXISTS evidence_records (
                    job_id TEXT NOT NULL,
                    agreement_id TEXT NOT NULL,
                    evidence_kind TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    anchor_hash TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (job_id, evidence_kind)
                );

                CREATE TABLE IF NOT EXISTS agreement_overlays (
                    agreement_id TEXT PRIMARY KEY,
                    overlay_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS execution_sessions (
                    session_id TEXT PRIMARY KEY,
                    agreement_id TEXT NOT NULL,
                    session_json TEXT NOT NULL,
                    challenge_json TEXT,
                    attestation_result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS session_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    challenge_json TEXT NOT NULL,
                    nonce_hash TEXT NOT NULL,
                    resolved_selector_hash TEXT NOT NULL,
                    requester_ephemeral_pubkey_hash TEXT,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    status TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS attestation_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS attestation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence_nodes (
                    job_id TEXT NOT NULL,
                    agreement_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    node_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (job_id, node_id)
                );

                CREATE TABLE IF NOT EXISTS evidence_edges (
                    job_id TEXT NOT NULL,
                    from_node_id TEXT NOT NULL,
                    to_node_id TEXT NOT NULL,
                    dependency_type TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS transparency_receipts (
                    statement_id TEXT PRIMARY KEY,
                    statement_hash TEXT NOT NULL,
                    root_hash TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_lineage_jobs_agreement_id
                ON lineage_jobs (agreement_id, updated_at DESC);
                ",
            )
            .map_err(sqlite_error)?;
        Ok(())
    }
}
