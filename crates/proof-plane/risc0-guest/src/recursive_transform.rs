#![no_main]

use lsdc_common::crypto::{ReceiptKind, Sha256Hash};
use proof_plane_risc0_model::{RecursiveCsvTransformProofInput, RecursiveCsvTransformProofJournal};
use proof_transform_kernel::apply_manifest;
use risc0_zkvm::guest::env;

mod shared;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: RecursiveCsvTransformProofInput = env::read();
    let manifest = input.manifest.clone().into();
    let input_hash = Sha256Hash::digest_bytes(&input.input_csv);
    let output_csv = apply_manifest(&input.input_csv, &manifest)
        .expect("risc0 guest failed to apply CSV transform manifest");
    let transform_manifest_hash = Sha256Hash::digest_bytes(
        &serde_json::to_vec(&manifest).expect("manifest should serialize"),
    );

    let (prior_receipt_hash, parent_receipt_hashes, recursion_depth) =
        match input.prior_receipt.as_ref() {
            Some(witness) => {
                let prior = shared::verify_receipt_witness(witness);
                assert_eq!(prior.journal.agreement_id, input.agreement_id);
                assert_eq!(
                    prior.journal.agreement_commitment_hash,
                    input.agreement_commitment_hash
                );
                assert_eq!(prior.journal.session_id, input.session_id);
                assert_eq!(prior.journal.challenge_nonce_hash, input.challenge_nonce_hash);
                assert_eq!(prior.journal.selector_hash, input.selector_hash);
                assert_eq!(
                    prior.journal.attestation_result_hash,
                    input.attestation_result_hash
                );
                assert_eq!(
                    prior.journal.capability_commitment_hash,
                    input.capability_commitment_hash
                );
                assert_eq!(
                    prior.journal.transparency_statement_hash,
                    input.transparency_statement_hash
                );
                assert_eq!(prior.journal.output_hash, input_hash);

                (
                    Some(prior.receipt_hash.clone()),
                    vec![prior.receipt_hash],
                    prior.journal.recursion_depth + 1,
                )
            }
            None => (None, Vec::new(), 0),
        };

    let journal = RecursiveCsvTransformProofJournal {
        agreement_id: input.agreement_id,
        input_hash,
        output_hash: Sha256Hash::digest_bytes(&output_csv),
        policy_hash: input.policy_hash,
        transform_manifest_hash,
        prior_receipt_hash,
        agreement_commitment_hash: input.agreement_commitment_hash,
        session_id: input.session_id,
        challenge_nonce_hash: input.challenge_nonce_hash,
        selector_hash: input.selector_hash,
        attestation_result_hash: input.attestation_result_hash,
        capability_commitment_hash: input.capability_commitment_hash,
        transparency_statement_hash: input.transparency_statement_hash,
        parent_receipt_hashes,
        recursion_depth,
        receipt_kind: ReceiptKind::Transform,
    };

    env::commit(&journal);
}
