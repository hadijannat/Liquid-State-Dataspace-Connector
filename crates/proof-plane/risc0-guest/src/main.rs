#![no_main]

use lsdc_common::crypto::{hash_json, Sha256Hash};
use lsdc_common::proof::{CsvTransformProofInput, CsvTransformProofJournal};
use proof_plane_guest::apply_manifest;
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
        output_csv,
    };

    env::commit(&journal);
}
