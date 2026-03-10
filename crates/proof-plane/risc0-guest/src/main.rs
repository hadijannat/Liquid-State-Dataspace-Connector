#![no_main]

use lsdc_common::crypto::Sha256Hash;
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::proof::CsvTransformProofJournal;
use proof_plane_risc0_model::RecursiveCsvTransformProofInput;
use proof_transform_kernel::apply_manifest;
use risc0_zkvm::guest::env;

mod shared;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: RecursiveCsvTransformProofInput = env::read();
    let manifest: CsvTransformManifest = input.manifest.clone().into();
    let output_csv = apply_manifest(&input.input_csv, &manifest)
        .expect("risc0 guest failed to apply CSV transform manifest");
    let transform_manifest_hash = Sha256Hash::digest_bytes(
        &serde_json::to_vec(&manifest).expect("manifest should serialize"),
    );
    let (prior_receipt_hash, parent_receipt_hashes, recursion_depth) =
        match input.prior_receipt.as_ref() {
            Some(witness) => {
                let prior = shared::verify_receipt_witness(witness);
                (
                    Some(prior.receipt_hash.clone()),
                    vec![prior.receipt_hash],
                    prior.journal.recursion_depth + 1,
                )
            }
            None => (None, Vec::new(), 0),
        };

    let journal = CsvTransformProofJournal {
        agreement_id: input.agreement_id,
        input_hash: Sha256Hash::digest_bytes(&input.input_csv),
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
        receipt_kind: lsdc_common::crypto::ReceiptKind::Transform,
    };

    env::commit(&journal);
}
