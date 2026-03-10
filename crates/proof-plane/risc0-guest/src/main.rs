#![no_main]

use lsdc_common::crypto::{hash_json, Sha256Hash};
use lsdc_common::proof::{CsvTransformProofInput, CsvTransformProofJournal};
use proof_transform_kernel::apply_manifest;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: CsvTransformProofInput = env::read();
    let output_csv = apply_manifest(&input.input_csv, &input.manifest)
        .expect("risc0 guest failed to apply CSV transform manifest");
    let transform_manifest_hash = Sha256Hash::digest_bytes(
        &serde_json::to_vec(&input.manifest).expect("manifest should serialize"),
    );

    let journal = CsvTransformProofJournal {
        agreement_id: input.agreement_id,
        input_hash: Sha256Hash::digest_bytes(&input.input_csv),
        output_hash: Sha256Hash::digest_bytes(&output_csv),
        policy_hash: hash_json(&input.odrl_policy).expect("policy should hash"),
        transform_manifest_hash,
        agreement_commitment_hash: input.agreement_commitment_hash,
        session_id: input.session_id,
        challenge_nonce_hash: input.challenge_nonce_hash,
        selector_hash: input.selector_hash,
        attestation_result_hash: input.attestation_result_hash,
        capability_commitment_hash: input.capability_commitment_hash,
        transparency_statement_hash: input.transparency_statement_hash,
        parent_receipt_hashes: input.parent_receipt_hashes,
        recursion_depth: input.recursion_depth,
        receipt_kind: input.receipt_kind,
    };

    env::commit(&journal);
}
