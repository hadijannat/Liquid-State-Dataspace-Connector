use lsdc_common::crypto::{ProvenanceReceipt, ReceiptKind, Sha256Hash};
use lsdc_common::execution_overlay::ExecutionStatementKind;
use lsdc_common::runtime_model::{DependencyType, EvidenceDag};
pub use lsdc_evidence::{
    ChainVerification, EvidenceEnvelope, PricingEvidenceV1, ReceiptEnvelopeV1, VerifiedClaims,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn verify_receipt_links(chain: &[ReceiptEnvelopeV1]) -> ChainVerification {
    let mut valid = true;
    let mut recursion_used = false;

    for (index, receipt) in chain.iter().enumerate() {
        recursion_used |= receipt.recursion_used;
        if index == 0 {
            if receipt.prior_receipt_hash.is_some() {
                valid = false;
            }
            continue;
        }

        if receipt.prior_receipt_hash.as_ref() != Some(&chain[index - 1].receipt_hash()) {
            valid = false;
        }
    }

    ChainVerification {
        valid,
        checked_receipt_count: chain.len(),
        recursion_used,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptDagVerification {
    pub valid: bool,
    pub checked_receipt_count: usize,
    pub recursion_used: bool,
}

pub fn verify_provenance_receipt_chain(chain: &[ProvenanceReceipt]) -> ReceiptDagVerification {
    let mut valid = true;
    let mut recursion_used = false;

    for (index, receipt) in chain.iter().enumerate() {
        recursion_used |= receipt.prior_receipt_hash.is_some() || receipt.recursion_depth > 0;
        if receipt.receipt_kind != ReceiptKind::Transform {
            valid = false;
            continue;
        }

        if index == 0 {
            if receipt.prior_receipt_hash.is_some()
                || !receipt.parent_receipt_hashes.is_empty()
                || receipt.recursion_depth != 0
            {
                valid = false;
            }
            continue;
        }

        let parent = &chain[index - 1];
        if receipt.prior_receipt_hash.as_ref() != Some(&parent.receipt_hash)
            || receipt.parent_receipt_hashes != vec![parent.receipt_hash.clone()]
            || receipt.recursion_depth != parent.recursion_depth + 1
        {
            valid = false;
        }
    }

    ReceiptDagVerification {
        valid,
        checked_receipt_count: chain.len(),
        recursion_used,
    }
}

pub fn verify_provenance_receipt_dag(
    dag: &EvidenceDag,
) -> Result<ReceiptDagVerification, serde_json::Error> {
    let mut proof_nodes = HashMap::new();
    let mut receipts_by_hash = HashMap::new();
    let mut valid = true;
    let mut recursion_used = false;

    for node in &dag.nodes {
        if node.kind != ExecutionStatementKind::ProofReceiptRegistered {
            continue;
        }

        let receipt: ProvenanceReceipt = serde_json::from_value(node.payload_json.clone())?;
        recursion_used |= receipt.prior_receipt_hash.is_some() || receipt.recursion_depth > 0;
        if node.canonical_hash != receipt.receipt_hash {
            valid = false;
        }
        if proof_nodes
            .insert(node.node_id.clone(), receipt.clone())
            .is_some()
        {
            valid = false;
        }
        if receipts_by_hash
            .insert(receipt.receipt_hash.clone(), receipt)
            .is_some()
        {
            valid = false;
        }
    }

    let proof_edges = dag
        .edges
        .iter()
        .filter(|edge| {
            edge.dependency_type == DependencyType::DerivedFrom
                && proof_nodes.contains_key(&edge.from_node_id)
                && proof_nodes.contains_key(&edge.to_node_id)
        })
        .collect::<Vec<_>>();

    for (node_id, receipt) in &proof_nodes {
        let incoming = proof_edges
            .iter()
            .filter(|edge| edge.to_node_id == *node_id)
            .map(|edge| edge.from_node_id.clone())
            .collect::<Vec<_>>();
        if !validate_receipt_structure(receipt, &receipts_by_hash, Some((&incoming, &proof_nodes)))
        {
            valid = false;
        }
    }

    Ok(ReceiptDagVerification {
        valid,
        checked_receipt_count: proof_nodes.len(),
        recursion_used,
    })
}

fn validate_receipt_structure(
    receipt: &ProvenanceReceipt,
    receipts_by_hash: &HashMap<Sha256Hash, ProvenanceReceipt>,
    dag: Option<(&Vec<String>, &HashMap<String, ProvenanceReceipt>)>,
) -> bool {
    match receipt.receipt_kind {
        ReceiptKind::Transform => validate_transform_receipt(receipt, receipts_by_hash, dag),
        ReceiptKind::Composition => validate_composition_receipt(receipt, receipts_by_hash, dag),
    }
}

fn validate_transform_receipt(
    receipt: &ProvenanceReceipt,
    receipts_by_hash: &HashMap<Sha256Hash, ProvenanceReceipt>,
    dag: Option<(&Vec<String>, &HashMap<String, ProvenanceReceipt>)>,
) -> bool {
    match receipt.prior_receipt_hash.as_ref() {
        Some(prior_hash) => {
            if receipt.parent_receipt_hashes.as_slice() != [prior_hash.clone()] {
                return false;
            }
            let Some(parent) = receipts_by_hash.get(prior_hash) else {
                return false;
            };
            if receipt.recursion_depth != parent.recursion_depth + 1 {
                return false;
            }
            has_exact_dag_parents(receipt, dag)
        }
        None => {
            receipt.parent_receipt_hashes.is_empty()
                && receipt.recursion_depth == 0
                && has_exact_dag_parents(receipt, dag)
        }
    }
}

fn validate_composition_receipt(
    receipt: &ProvenanceReceipt,
    receipts_by_hash: &HashMap<Sha256Hash, ProvenanceReceipt>,
    dag: Option<(&Vec<String>, &HashMap<String, ProvenanceReceipt>)>,
) -> bool {
    if receipt.prior_receipt_hash.is_some() || receipt.parent_receipt_hashes.is_empty() {
        return false;
    }

    let mut parents = Vec::with_capacity(receipt.parent_receipt_hashes.len());
    for hash in &receipt.parent_receipt_hashes {
        let Some(parent) = receipts_by_hash.get(hash) else {
            return false;
        };
        parents.push(parent);
    }

    let expected_depth = parents
        .iter()
        .map(|parent| parent.recursion_depth)
        .max()
        .unwrap_or(0)
        + 1;

    receipt.recursion_depth == expected_depth
        && receipt.input_hash == hash_hex_list(parents.iter().map(|parent| &parent.input_hash))
        && receipt.output_hash == hash_hex_list(parents.iter().map(|parent| &parent.output_hash))
        && receipt.policy_hash == hash_hex_list(parents.iter().map(|parent| &parent.policy_hash))
        && receipt.transform_manifest_hash
            == hash_hex_list(parents.iter().map(|parent| &parent.transform_manifest_hash))
        && has_exact_dag_parents(receipt, dag)
}

fn has_exact_dag_parents(
    receipt: &ProvenanceReceipt,
    dag: Option<(&Vec<String>, &HashMap<String, ProvenanceReceipt>)>,
) -> bool {
    let Some((incoming, nodes)) = dag else {
        return true;
    };
    if incoming.len() != receipt.parent_receipt_hashes.len() {
        return false;
    }

    incoming
        .iter()
        .zip(receipt.parent_receipt_hashes.iter())
        .all(|(parent_node_id, expected_hash)| {
            nodes
                .get(parent_node_id)
                .is_some_and(|parent| parent.receipt_hash == *expected_hash)
        })
}

fn hash_hex_list<'a>(items: impl Iterator<Item = &'a Sha256Hash>) -> Sha256Hash {
    Sha256Hash::digest_bytes(
        &serde_json::to_vec(&items.map(Sha256Hash::to_hex).collect::<Vec<_>>())
            .expect("receipt hash lists should serialize"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lsdc_common::crypto::{ProvenanceReceipt, ReceiptKind, Sha256Hash};
    use lsdc_common::execution::ProofBackend;
    use lsdc_common::execution_overlay::ExecutionStatementKind;
    use lsdc_common::runtime_model::{
        DependencyType, EvidenceDag, EvidenceEdge, EvidenceNode, NodeStatus,
    };

    fn receipt(proof: &[u8], prior_receipt_hash: Option<Sha256Hash>) -> ReceiptEnvelopeV1 {
        ReceiptEnvelopeV1 {
            backend_id: "dev_receipt".into(),
            schema_version: 1,
            policy_hash: Sha256Hash::digest_bytes(b"policy"),
            manifest_hash: Sha256Hash::digest_bytes(b"manifest"),
            input_hash: Sha256Hash::digest_bytes(b"input"),
            output_hash: Sha256Hash::digest_bytes(b"output"),
            prior_receipt_hash,
            recursion_used: false,
            journal: Vec::new(),
            proof: proof.to_vec(),
        }
    }

    #[test]
    fn test_verify_receipt_links_accepts_strictly_linked_chain() {
        let first = receipt(b"receipt-1", None);
        let second = receipt(b"receipt-2", Some(first.receipt_hash()));

        let verification = verify_receipt_links(&[first, second]);

        assert!(verification.valid);
        assert_eq!(verification.checked_receipt_count, 2);
    }

    #[test]
    fn test_verify_receipt_links_rejects_first_receipt_with_prior_hash() {
        let verification = verify_receipt_links(&[receipt(
            b"receipt-1",
            Some(Sha256Hash::digest_bytes(b"unexpected-prior")),
        )]);

        assert!(!verification.valid);
    }

    #[test]
    fn test_verify_receipt_links_rejects_mismatched_prior_hash() {
        let first = receipt(b"receipt-1", None);
        let second = receipt(
            b"receipt-2",
            Some(Sha256Hash::digest_bytes(b"not-the-first-receipt")),
        );

        let verification = verify_receipt_links(&[first, second]);

        assert!(!verification.valid);
    }

    fn provenance_receipt(
        seed: &[u8],
        prior_receipt_hash: Option<Sha256Hash>,
        parent_receipt_hashes: Vec<Sha256Hash>,
        recursion_depth: u32,
        receipt_kind: ReceiptKind,
    ) -> ProvenanceReceipt {
        ProvenanceReceipt {
            agreement_id: "agreement".into(),
            input_hash: Sha256Hash::digest_bytes([seed, b"-input"].concat().as_slice()),
            output_hash: Sha256Hash::digest_bytes([seed, b"-output"].concat().as_slice()),
            policy_hash: Sha256Hash::digest_bytes([seed, b"-policy"].concat().as_slice()),
            transform_manifest_hash: Sha256Hash::digest_bytes(
                [seed, b"-manifest"].concat().as_slice(),
            ),
            prior_receipt_hash,
            agreement_commitment_hash: None,
            session_id: None,
            challenge_nonce_hash: None,
            selector_hash: None,
            attestation_result_hash: None,
            capability_commitment_hash: None,
            transparency_statement_hash: None,
            parent_receipt_hashes,
            recursion_depth,
            receipt_kind,
            receipt_hash: Sha256Hash::digest_bytes([seed, b"-receipt"].concat().as_slice()),
            proof_backend: ProofBackend::RiscZero,
            receipt_format_version: "lsdc.risc0.receipt.v1".into(),
            proof_method_id: "risc0.csv_transform.v1".into(),
            receipt_bytes: seed.to_vec(),
            timestamp: Utc::now(),
        }
    }

    fn composition_receipt(parents: &[&ProvenanceReceipt]) -> ProvenanceReceipt {
        ProvenanceReceipt {
            agreement_id: "agreement".into(),
            input_hash: hash_hex_list(parents.iter().map(|parent| &parent.input_hash)),
            output_hash: hash_hex_list(parents.iter().map(|parent| &parent.output_hash)),
            policy_hash: hash_hex_list(parents.iter().map(|parent| &parent.policy_hash)),
            transform_manifest_hash: hash_hex_list(
                parents.iter().map(|parent| &parent.transform_manifest_hash),
            ),
            prior_receipt_hash: None,
            agreement_commitment_hash: None,
            session_id: None,
            challenge_nonce_hash: None,
            selector_hash: None,
            attestation_result_hash: None,
            capability_commitment_hash: None,
            transparency_statement_hash: None,
            parent_receipt_hashes: parents
                .iter()
                .map(|parent| parent.receipt_hash.clone())
                .collect(),
            recursion_depth: parents
                .iter()
                .map(|parent| parent.recursion_depth)
                .max()
                .unwrap_or(0)
                + 1,
            receipt_kind: ReceiptKind::Composition,
            receipt_hash: Sha256Hash::digest_bytes(b"composition-receipt"),
            proof_backend: ProofBackend::RiscZero,
            receipt_format_version: "lsdc.risc0.receipt.v1".into(),
            proof_method_id: "risc0.receipt_composition.v1".into(),
            receipt_bytes: b"composition".to_vec(),
            timestamp: Utc::now(),
        }
    }

    fn proof_node(node_id: &str, receipt: &ProvenanceReceipt) -> EvidenceNode {
        EvidenceNode {
            node_id: node_id.into(),
            kind: ExecutionStatementKind::ProofReceiptRegistered,
            canonical_hash: receipt.receipt_hash.clone(),
            status: NodeStatus::Verified,
            payload_json: serde_json::to_value(receipt).unwrap(),
        }
    }

    #[test]
    fn test_verify_provenance_receipt_chain_accepts_recursive_transform() {
        let first = provenance_receipt(b"first", None, Vec::new(), 0, ReceiptKind::Transform);
        let second = provenance_receipt(
            b"second",
            Some(first.receipt_hash.clone()),
            vec![first.receipt_hash.clone()],
            1,
            ReceiptKind::Transform,
        );

        let verification = verify_provenance_receipt_chain(&[first, second]);

        assert!(verification.valid);
        assert_eq!(verification.checked_receipt_count, 2);
        assert!(verification.recursion_used);
    }

    #[test]
    fn test_verify_provenance_receipt_chain_rejects_bad_recursion_depth() {
        let first = provenance_receipt(b"first", None, Vec::new(), 0, ReceiptKind::Transform);
        let second = provenance_receipt(
            b"second",
            Some(first.receipt_hash.clone()),
            vec![first.receipt_hash.clone()],
            3,
            ReceiptKind::Transform,
        );

        let verification = verify_provenance_receipt_chain(&[first, second]);

        assert!(!verification.valid);
    }

    #[test]
    fn test_verify_provenance_receipt_dag_accepts_composition_subgraph() {
        let left = provenance_receipt(b"left", None, Vec::new(), 0, ReceiptKind::Transform);
        let right = provenance_receipt(b"right", None, Vec::new(), 0, ReceiptKind::Transform);
        let composed = composition_receipt(&[&left, &right]);
        let dag = EvidenceDag::new(
            vec![
                proof_node("left", &left),
                proof_node("right", &right),
                proof_node("composed", &composed),
            ],
            vec![
                EvidenceEdge {
                    from_node_id: "left".into(),
                    to_node_id: "composed".into(),
                    dependency_type: DependencyType::DerivedFrom,
                },
                EvidenceEdge {
                    from_node_id: "right".into(),
                    to_node_id: "composed".into(),
                    dependency_type: DependencyType::DerivedFrom,
                },
            ],
        )
        .unwrap();

        let verification = verify_provenance_receipt_dag(&dag).unwrap();

        assert!(verification.valid);
        assert_eq!(verification.checked_receipt_count, 3);
        assert!(verification.recursion_used);
    }

    #[test]
    fn test_verify_provenance_receipt_dag_rejects_wrong_edge_direction() {
        let left = provenance_receipt(b"left", None, Vec::new(), 0, ReceiptKind::Transform);
        let right = provenance_receipt(b"right", None, Vec::new(), 0, ReceiptKind::Transform);
        let composed = composition_receipt(&[&left, &right]);
        let dag = EvidenceDag::new(
            vec![
                proof_node("left", &left),
                proof_node("right", &right),
                proof_node("composed", &composed),
            ],
            vec![
                EvidenceEdge {
                    from_node_id: "composed".into(),
                    to_node_id: "left".into(),
                    dependency_type: DependencyType::DerivedFrom,
                },
                EvidenceEdge {
                    from_node_id: "right".into(),
                    to_node_id: "composed".into(),
                    dependency_type: DependencyType::DerivedFrom,
                },
            ],
        )
        .unwrap();

        let verification = verify_provenance_receipt_dag(&dag).unwrap();

        assert!(!verification.valid);
    }

    #[test]
    fn test_verify_provenance_receipt_dag_rejects_missing_parent_node() {
        let left = provenance_receipt(b"left", None, Vec::new(), 0, ReceiptKind::Transform);
        let right = provenance_receipt(b"right", None, Vec::new(), 0, ReceiptKind::Transform);
        let composed = composition_receipt(&[&left, &right]);
        let dag = EvidenceDag::new(
            vec![proof_node("left", &left), proof_node("composed", &composed)],
            vec![EvidenceEdge {
                from_node_id: "left".into(),
                to_node_id: "composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            }],
        )
        .unwrap();

        let verification = verify_provenance_receipt_dag(&dag).unwrap();

        assert!(!verification.valid);
    }

    #[test]
    fn test_verify_provenance_receipt_dag_rejects_duplicate_receipt_nodes() {
        let left = provenance_receipt(b"left", None, Vec::new(), 0, ReceiptKind::Transform);
        let dag = EvidenceDag::new(
            vec![proof_node("left-a", &left), proof_node("left-b", &left)],
            Vec::new(),
        )
        .unwrap();

        let verification = verify_provenance_receipt_dag(&dag).unwrap();

        assert!(!verification.valid);
    }

    #[test]
    fn test_verify_provenance_receipt_dag_rejects_bad_composition_depth() {
        let left = provenance_receipt(b"left", None, Vec::new(), 0, ReceiptKind::Transform);
        let right = provenance_receipt(b"right", None, Vec::new(), 0, ReceiptKind::Transform);
        let mut composed = composition_receipt(&[&left, &right]);
        composed.recursion_depth += 1;
        let dag = EvidenceDag::new(
            vec![
                proof_node("left", &left),
                proof_node("right", &right),
                proof_node("composed", &composed),
            ],
            vec![
                EvidenceEdge {
                    from_node_id: "left".into(),
                    to_node_id: "composed".into(),
                    dependency_type: DependencyType::DerivedFrom,
                },
                EvidenceEdge {
                    from_node_id: "right".into(),
                    to_node_id: "composed".into(),
                    dependency_type: DependencyType::DerivedFrom,
                },
            ],
        )
        .unwrap();

        let verification = verify_provenance_receipt_dag(&dag).unwrap();

        assert!(!verification.valid);
    }
}
