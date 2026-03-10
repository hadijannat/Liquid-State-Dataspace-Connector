use lsdc_common::crypto::Sha256Hash;
use lsdc_common::proof::CsvTransformProofJournal as LegacyCsvTransformProofJournal;
use proof_plane_risc0_model::{
    DecodedWitnessReceipt, ReceiptAssumptionWitness, RecursiveCsvTransformProofJournal,
    Risc0ReceiptMethod,
};
use risc0_zkvm::{Receipt, guest::env};

pub fn verify_receipt_witness(witness: &ReceiptAssumptionWitness) -> DecodedWitnessReceipt {
    let receipt: Receipt =
        bincode::deserialize(&witness.receipt_bytes).expect("failed to decode witness receipt");

    assert_eq!(receipt.journal.bytes.as_slice(), witness.journal_bytes.as_slice());

    env::verify(witness.image_id, witness.journal_bytes.as_slice())
        .expect("failed to verify witness receipt");

    let journal = match witness.method {
        Risc0ReceiptMethod::LegacyTransform => {
            let journal: LegacyCsvTransformProofJournal = receipt
                .journal
                .decode()
                .expect("failed to decode legacy witness receipt journal");
            RecursiveCsvTransformProofJournal::from(journal)
        }
        Risc0ReceiptMethod::RecursiveTransform | Risc0ReceiptMethod::Composition => receipt
            .journal
            .decode()
            .expect("failed to decode recursive witness receipt journal"),
    };

    let receipt_hash = Sha256Hash::digest_bytes(&witness.receipt_bytes);
    assert_eq!(receipt_hash, witness.receipt_hash);
    assert_eq!(journal.receipt_kind, witness.receipt_kind);
    assert_eq!(journal.recursion_depth, witness.recursion_depth);

    DecodedWitnessReceipt {
        method: witness.method,
        journal,
        receipt_hash,
    }
}

pub fn hash_hex_list<'a>(items: impl Iterator<Item = &'a Sha256Hash>) -> Sha256Hash {
    Sha256Hash::digest_bytes(
        &serde_json::to_vec(&items.map(Sha256Hash::to_hex).collect::<Vec<_>>())
            .expect("failed to serialize receipt hash list"),
    )
}
