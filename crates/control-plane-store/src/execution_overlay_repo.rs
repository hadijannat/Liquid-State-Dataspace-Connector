use crate::ser::{from_json, to_json};
use crate::{sqlite_error, Store};
use lsdc_common::crypto::AttestationResult;
use lsdc_common::error::Result;
use lsdc_common::execution_overlay::{
    ExecutionSession, ExecutionSessionChallenge, ExecutionStatement, TransparencyReceipt,
};
use lsdc_common::runtime_model::{EvidenceDag, EvidenceEdge, EvidenceNode};
use lsdc_service_types::ExecutionOverlaySummary;
use rusqlite::{params, OptionalExtension};

impl Store {
    pub fn upsert_agreement_overlay(
        &self,
        agreement_id: &str,
        overlay: &ExecutionOverlaySummary,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "INSERT INTO agreement_overlays (
                    agreement_id,
                    overlay_json,
                    created_at,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?3)
                ON CONFLICT(agreement_id) DO UPDATE SET
                    overlay_json = excluded.overlay_json,
                    updated_at = excluded.updated_at",
                params![agreement_id, to_json(overlay)?, now],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_agreement_overlay(
        &self,
        agreement_id: &str,
    ) -> Result<Option<ExecutionOverlaySummary>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT overlay_json
                 FROM agreement_overlays
                 WHERE agreement_id = ?1",
                params![agreement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;

        row.as_deref().map(from_json).transpose()
    }

    pub fn upsert_execution_session(
        &self,
        session: &ExecutionSession,
        challenge: Option<&ExecutionSessionChallenge>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "INSERT INTO execution_sessions (
                    session_id,
                    agreement_id,
                    session_json,
                    challenge_json,
                    attestation_result_json,
                    created_at,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?5)
                ON CONFLICT(session_id) DO UPDATE SET
                    agreement_id = excluded.agreement_id,
                    session_json = excluded.session_json,
                    challenge_json = excluded.challenge_json,
                    updated_at = excluded.updated_at",
                params![
                    session.session_id.to_string(),
                    session.agreement_id,
                    to_json(session)?,
                    challenge.map(to_json).transpose()?,
                    now
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn update_execution_challenge(
        &self,
        session_id: &str,
        session: &ExecutionSession,
        challenge: &ExecutionSessionChallenge,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "UPDATE execution_sessions
                 SET session_json = ?2,
                     challenge_json = ?3,
                     updated_at = ?4
                 WHERE session_id = ?1",
                params![session_id, to_json(session)?, to_json(challenge)?, now],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn save_attestation_result(
        &self,
        session_id: &str,
        session: &ExecutionSession,
        attestation_result: &AttestationResult,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "UPDATE execution_sessions
                 SET session_json = ?2,
                     attestation_result_json = ?3,
                     updated_at = ?4
                 WHERE session_id = ?1",
                params![session_id, to_json(session)?, to_json(attestation_result)?, now],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_execution_session(
        &self,
        session_id: &str,
    ) -> Result<Option<(
        ExecutionSession,
        Option<ExecutionSessionChallenge>,
        Option<AttestationResult>,
    )>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT session_json, challenge_json, attestation_result_json
                 FROM execution_sessions
                 WHERE session_id = ?1",
                params![session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;

        row.map(|(session_json, challenge_json, attestation_result_json)| {
            Ok((
                from_json(&session_json)?,
                challenge_json
                    .as_deref()
                    .map(from_json::<ExecutionSessionChallenge>)
                    .transpose()?,
                attestation_result_json
                    .as_deref()
                    .map(from_json::<AttestationResult>)
                    .transpose()?,
            ))
        })
        .transpose()
    }

    pub fn persist_evidence_dag(
        &self,
        job_id: &str,
        agreement_id: &str,
        dag: &EvidenceDag,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let mut connection = self.lock()?;
        let tx = connection.transaction().map_err(sqlite_error)?;

        tx.execute(
            "DELETE FROM evidence_nodes WHERE job_id = ?1",
            params![job_id],
        )
        .map_err(sqlite_error)?;
        tx.execute(
            "DELETE FROM evidence_edges WHERE job_id = ?1",
            params![job_id],
        )
        .map_err(sqlite_error)?;

        for node in &dag.nodes {
            insert_evidence_node(&tx, job_id, agreement_id, node, &now)?;
        }
        for edge in &dag.edges {
            tx.execute(
                "INSERT INTO evidence_edges (
                    job_id,
                    from_node_id,
                    to_node_id,
                    dependency_type,
                    created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    job_id,
                    edge.from_node_id,
                    edge.to_node_id,
                    serde_json::to_value(edge.dependency_type)
                        .map_err(lsdc_common::error::LsdcError::from)?
                        .as_str()
                        .unwrap_or_default(),
                    now
                ],
            )
            .map_err(sqlite_error)?;
        }

        tx.commit().map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_evidence_dag(&self, job_id: &str) -> Result<Option<EvidenceDag>> {
        let connection = self.lock()?;
        let mut node_statement = connection
            .prepare(
                "SELECT node_id, node_kind, node_hash, status, payload_json
                 FROM evidence_nodes
                 WHERE job_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(sqlite_error)?;
        let node_rows = node_statement
            .query_map(params![job_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(sqlite_error)?;
        let mut nodes = Vec::new();
        for row in node_rows {
            let (node_id, node_kind, node_hash, status, payload_json) = row.map_err(sqlite_error)?;
            nodes.push(EvidenceNode {
                node_id,
                kind: from_json(&format!("\"{}\"", node_kind))?,
                canonical_hash: lsdc_common::crypto::Sha256Hash::from_hex(&node_hash)
                    .map_err(lsdc_common::error::LsdcError::Database)?,
                status: from_json(&format!("\"{}\"", status))?,
                payload_json: serde_json::from_str(&payload_json).map_err(lsdc_common::error::LsdcError::from)?,
            });
        }
        if nodes.is_empty() {
            return Ok(None);
        }

        let mut edge_statement = connection
            .prepare(
                "SELECT from_node_id, to_node_id, dependency_type
                 FROM evidence_edges
                 WHERE job_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(sqlite_error)?;
        let edge_rows = edge_statement
            .query_map(params![job_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sqlite_error)?;
        let mut edges = Vec::new();
        for row in edge_rows {
            let (from_node_id, to_node_id, dependency_type) = row.map_err(sqlite_error)?;
            edges.push(EvidenceEdge {
                from_node_id,
                to_node_id,
                dependency_type: from_json(&format!("\"{}\"", dependency_type))?,
            });
        }

        Ok(Some(EvidenceDag::new(nodes, edges).map_err(lsdc_common::error::LsdcError::from)?))
    }

    pub fn insert_transparency_receipt(
        &self,
        statement: &ExecutionStatement,
        receipt: &TransparencyReceipt,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock()?
            .execute(
                "INSERT INTO transparency_receipts (
                    statement_id,
                    statement_hash,
                    root_hash,
                    receipt_json,
                    created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(statement_id) DO UPDATE SET
                    statement_hash = excluded.statement_hash,
                    root_hash = excluded.root_hash,
                    receipt_json = excluded.receipt_json",
                params![
                    statement.statement_id,
                    statement.subject_hash.to_hex(),
                    receipt.root_hash.to_hex(),
                    to_json(receipt)?,
                    now
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn get_transparency_receipt(
        &self,
        statement_id: &str,
    ) -> Result<Option<TransparencyReceipt>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT receipt_json
                 FROM transparency_receipts
                 WHERE statement_id = ?1",
                params![statement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        row.as_deref().map(from_json).transpose()
    }
}

fn insert_evidence_node(
    tx: &rusqlite::Transaction<'_>,
    job_id: &str,
    agreement_id: &str,
    node: &EvidenceNode,
    now: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO evidence_nodes (
            job_id,
            agreement_id,
            node_id,
            node_kind,
            node_hash,
            status,
            payload_json,
            created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            job_id,
            agreement_id,
            node.node_id,
            serde_json::to_value(node.kind)
                .map_err(lsdc_common::error::LsdcError::from)?
                .as_str()
                .unwrap_or_default(),
            node.canonical_hash.to_hex(),
            serde_json::to_value(node.status)
                .map_err(lsdc_common::error::LsdcError::from)?
                .as_str()
                .unwrap_or_default(),
            serde_json::to_string(&node.payload_json).map_err(lsdc_common::error::LsdcError::from)?,
            now
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}
