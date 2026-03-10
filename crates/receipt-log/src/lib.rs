use chrono::Utc;
use hmac::{Hmac, Mac};
use lsdc_evidence::{canonical_json_bytes, Sha256Hash};
use lsdc_execution_protocol::{ExecutionStatement, TransparencyReceipt};
use lsdc_policy::error::{LsdcError, Result};
use lsdc_ports::TransparencyLog;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct LocalTransparencyLog {
    log_id: Arc<str>,
    secret: Arc<str>,
    state: Arc<Mutex<Vec<(String, Sha256Hash)>>>,
}

impl LocalTransparencyLog {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            log_id: format!("local-log-{}", Uuid::new_v4()).into(),
            secret: secret.into().into(),
            state: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn register(&self, statement: &ExecutionStatement) -> Result<TransparencyReceipt> {
        let statement_hash = statement
            .canonical_hash()
            .map_err(LsdcError::Serialization)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LsdcError::Database("transparency log mutex poisoned".into()))?;
        state.push((statement.statement_id.clone(), statement_hash.clone()));
        let leaf_index = state.len() as u64 - 1;
        let leaves = state
            .iter()
            .map(|(_, hash)| hash.clone())
            .collect::<Vec<_>>();
        let inclusion_path = merkle_inclusion_path(&leaves, leaf_index as usize);
        let root_hash = merkle_root(&leaves);
        let signed_at = Utc::now();
        let unsigned = serde_json::json!({
            "statement_id": statement.statement_id,
            "receipt_profile": lsdc_execution_protocol::LOCAL_TRANSPARENCY_PROFILE,
            "log_id": self.log_id(),
            "statement_hash": statement_hash,
            "leaf_index": leaf_index,
            "tree_size": leaves.len(),
            "root_hash": root_hash,
            "inclusion_path": inclusion_path,
            "consistency_proof": Vec::<Sha256Hash>::new(),
            "signed_at": signed_at,
        });
        let signature_hex = sign(&self.secret, &unsigned)?;

        Ok(TransparencyReceipt {
            statement_id: statement.statement_id.clone(),
            receipt_profile: lsdc_execution_protocol::LOCAL_TRANSPARENCY_PROFILE.into(),
            log_id: self.log_id().to_string(),
            statement_hash,
            leaf_index,
            tree_size: leaves.len() as u64,
            root_hash,
            inclusion_path,
            consistency_proof: Vec::new(),
            signature_hex,
            signed_at,
        })
    }

    pub fn verify_receipt(
        &self,
        statement_hash: &Sha256Hash,
        receipt: &TransparencyReceipt,
    ) -> Result<()> {
        if &receipt.statement_hash != statement_hash {
            return Err(LsdcError::Attestation(
                "transparency receipt statement hash mismatch".into(),
            ));
        }

        let unsigned = serde_json::json!({
            "statement_id": receipt.statement_id,
            "receipt_profile": receipt.receipt_profile,
            "log_id": receipt.log_id,
            "statement_hash": receipt.statement_hash,
            "leaf_index": receipt.leaf_index,
            "tree_size": receipt.tree_size,
            "root_hash": receipt.root_hash,
            "inclusion_path": receipt.inclusion_path,
            "consistency_proof": receipt.consistency_proof,
            "signed_at": receipt.signed_at,
        });
        let expected_signature = sign(&self.secret, &unsigned)?;
        if expected_signature != receipt.signature_hex {
            return Err(LsdcError::Attestation(
                "transparency receipt signature verification failed".into(),
            ));
        }

        let derived_root = merkle_root_from_path(
            statement_hash,
            receipt.leaf_index as usize,
            receipt.tree_size as usize,
            &receipt.inclusion_path,
        );
        if derived_root != receipt.root_hash {
            return Err(LsdcError::Attestation(
                "transparency receipt inclusion path is invalid".into(),
            ));
        }

        Ok(())
    }
}

impl TransparencyLog for LocalTransparencyLog {
    fn register(&self, statement: &ExecutionStatement) -> Result<TransparencyReceipt> {
        LocalTransparencyLog::register(self, statement)
    }

    fn verify_receipt(
        &self,
        statement_hash: &Sha256Hash,
        receipt: &TransparencyReceipt,
    ) -> Result<()> {
        LocalTransparencyLog::verify_receipt(self, statement_hash, receipt)
    }
}

fn sign(secret: &str, value: &impl Serialize) -> Result<String> {
    let payload = canonical_json_bytes(&serde_json::to_value(value).map_err(LsdcError::from)?)
        .map_err(LsdcError::from)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts all key sizes");
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn hash_pair(left: &Sha256Hash, right: &Sha256Hash) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(left.0);
    hasher.update(right.0);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Sha256Hash(bytes)
}

fn merkle_root(leaves: &[Sha256Hash]) -> Sha256Hash {
    if leaves.is_empty() {
        return Sha256Hash::digest_bytes(b"lsdc-empty-log");
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut index = 0;
        while index < level.len() {
            let left = &level[index];
            let right = level.get(index + 1).unwrap_or(left);
            next.push(hash_pair(left, right));
            index += 2;
        }
        level = next;
    }
    level[0].clone()
}

fn merkle_inclusion_path(leaves: &[Sha256Hash], leaf_index: usize) -> Vec<Sha256Hash> {
    if leaves.is_empty() {
        return Vec::new();
    }

    let mut level = leaves.to_vec();
    let mut index = leaf_index;
    let mut path = Vec::new();

    while level.len() > 1 {
        let sibling = if index.is_multiple_of(2) {
            level.get(index + 1).unwrap_or(&level[index]).clone()
        } else {
            level[index - 1].clone()
        };
        path.push(sibling);

        let mut next = Vec::new();
        let mut offset = 0;
        while offset < level.len() {
            let left = &level[offset];
            let right = level.get(offset + 1).unwrap_or(left);
            next.push(hash_pair(left, right));
            offset += 2;
        }
        index /= 2;
        level = next;
    }

    path
}

fn merkle_root_from_path(
    leaf: &Sha256Hash,
    leaf_index: usize,
    tree_size: usize,
    path: &[Sha256Hash],
) -> Sha256Hash {
    if tree_size <= 1 {
        return leaf.clone();
    }

    let mut hash = leaf.clone();
    let mut index = leaf_index;
    for sibling in path {
        hash = if index.is_multiple_of(2) {
            hash_pair(&hash, sibling)
        } else {
            hash_pair(sibling, &hash)
        };
        index /= 2;
    }
    hash
}

pub fn statement_hash(statement: &ExecutionStatement) -> Result<Sha256Hash> {
    statement.canonical_hash().map_err(LsdcError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsdc_execution_protocol::{ExecutionStatementKind, LSDC_EXECUTION_PROTOCOL_VERSION};

    fn sample_statement(id: &str) -> ExecutionStatement {
        ExecutionStatement {
            statement_id: id.into(),
            statement_hash: Sha256Hash::digest_bytes(id.as_bytes()),
            statement_kind: ExecutionStatementKind::SettlementRecorded,
            agreement_id: "agreement-1".into(),
            session_id: None,
            payload_hash: Sha256Hash::digest_bytes(format!("payload:{id}").as_bytes()),
            parent_hashes: Vec::new(),
            producer: "receipt-log-test".into(),
            profile: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
            created_at: Utc::now(),
        }
        .with_computed_hash()
        .expect("statement hash")
    }

    #[test]
    fn test_verify_receipt_handles_multi_leaf_log_and_tampering() {
        let log = LocalTransparencyLog::new("test-transparency-secret");
        let first = sample_statement("statement-1");
        let second = sample_statement("statement-2");
        let third = sample_statement("statement-3");

        let first_receipt = log.register(&first).expect("first receipt");
        let second_receipt = log.register(&second).expect("second receipt");
        let third_receipt = log.register(&third).expect("third receipt");

        assert!(log
            .verify_receipt(&statement_hash(&first).expect("first hash"), &first_receipt)
            .is_ok());
        assert!(log
            .verify_receipt(
                &statement_hash(&second).expect("second hash"),
                &second_receipt
            )
            .is_ok());
        assert!(log
            .verify_receipt(&statement_hash(&third).expect("third hash"), &third_receipt)
            .is_ok());

        let mut tampered_signature = second_receipt.clone();
        tampered_signature.signature_hex = "00".repeat(32);
        assert!(log
            .verify_receipt(
                &statement_hash(&second).expect("second hash"),
                &tampered_signature
            )
            .is_err());

        let mut tampered_path = third_receipt.clone();
        tampered_path.inclusion_path[0] = Sha256Hash::digest_bytes(b"tampered-sibling");
        assert!(log
            .verify_receipt(&statement_hash(&third).expect("third hash"), &tampered_path)
            .is_err());

        assert!(log
            .verify_receipt(
                &Sha256Hash::digest_bytes(b"wrong-statement"),
                &first_receipt
            )
            .is_err());
    }
}
