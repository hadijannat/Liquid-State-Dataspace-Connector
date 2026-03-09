pub use lsdc_evidence::{
    ChainVerification, EvidenceEnvelope, PricingEvidenceV1, ReceiptEnvelopeV1, VerifiedClaims,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use lsdc_evidence::Sha256Hash;

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
}
