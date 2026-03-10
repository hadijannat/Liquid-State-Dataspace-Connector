#![no_main]

use lsdc_common::crypto::ReceiptKind;
use proof_plane_risc0_model::{ReceiptCompositionProofInput, RecursiveCsvTransformProofJournal};
use risc0_zkvm::guest::env;

mod shared;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: ReceiptCompositionProofInput = env::read();
    assert!(
        !input.child_receipts.is_empty(),
        "cannot compose an empty receipt set"
    );

    let children = input
        .child_receipts
        .iter()
        .map(shared::verify_receipt_witness)
        .collect::<Vec<_>>();

    for child in &children {
        assert_eq!(child.journal.agreement_id, input.context.agreement_id);
        assert_eq!(
            child.journal.agreement_commitment_hash,
            input.context.agreement_commitment_hash
        );
        assert_eq!(child.journal.session_id, input.context.session_id);
        assert_eq!(child.journal.selector_hash, input.context.selector_hash);
        assert_eq!(
            child.journal.capability_commitment_hash,
            input.context.capability_commitment_hash
        );
    }

    let parent_receipt_hashes = children
        .iter()
        .map(|child| child.receipt_hash.clone())
        .collect::<Vec<_>>();
    let recursion_depth = children
        .iter()
        .map(|child| child.journal.recursion_depth)
        .max()
        .unwrap_or(0)
        + 1;

    let journal = RecursiveCsvTransformProofJournal {
        agreement_id: input.context.agreement_id,
        input_hash: shared::hash_hex_list(children.iter().map(|child| &child.journal.input_hash)),
        output_hash: shared::hash_hex_list(children.iter().map(|child| &child.journal.output_hash)),
        policy_hash: shared::hash_hex_list(children.iter().map(|child| &child.journal.policy_hash)),
        transform_manifest_hash: shared::hash_hex_list(
            children.iter().map(|child| &child.journal.transform_manifest_hash),
        ),
        prior_receipt_hash: None,
        agreement_commitment_hash: input.context.agreement_commitment_hash,
        session_id: input.context.session_id,
        challenge_nonce_hash: None,
        selector_hash: input.context.selector_hash,
        attestation_result_hash: None,
        capability_commitment_hash: input.context.capability_commitment_hash,
        transparency_statement_hash: None,
        parent_receipt_hashes,
        recursion_depth,
        receipt_kind: ReceiptKind::Composition,
    };

    env::commit(&journal);
}
