use lsdc_common::crypto::Sha256Hash;
use lsdc_common::proof::CsvTransformProofJournal;
use proof_plane_risc0_model::{DecodedWitnessReceipt, ReceiptAssumptionWitness};
use risc0_zkvm::{Receipt, guest::env};

pub fn verify_receipt_witness(witness: &ReceiptAssumptionWitness) -> DecodedWitnessReceipt {
    let receipt: Receipt =
        bincode::deserialize(&witness.receipt_bytes).expect("failed to decode witness receipt");
    env::verify(witness.image_id, receipt.journal.bytes.as_slice())
        .expect("failed to verify witness receipt");

    DecodedWitnessReceipt {
        journal: receipt
            .journal
            .decode()
            .expect("failed to decode witness receipt journal"),
        receipt_hash: Sha256Hash::digest_bytes(&witness.receipt_bytes),
    }
}

pub fn hash_hex_list<'a>(items: impl Iterator<Item = &'a Sha256Hash>) -> Sha256Hash {
    Sha256Hash::digest_bytes(
        &serde_json::to_vec(&items.map(Sha256Hash::to_hex).collect::<Vec<_>>())
            .expect("failed to serialize receipt hash list"),
    )
}
