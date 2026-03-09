pub use lsdc_evidence::{
    ChainVerification, EvidenceEnvelope, PricingEvidenceV1, ReceiptEnvelopeV1, VerifiedClaims,
};

pub fn verify_receipt_links(chain: &[ReceiptEnvelopeV1]) -> ChainVerification {
    let mut valid = true;
    let mut recursion_used = false;

    for (index, receipt) in chain.iter().enumerate() {
        recursion_used |= receipt.recursion_used;
        if index > 0 && receipt.prior_receipt_hash.is_none() {
            valid = false;
        }
    }

    ChainVerification {
        valid,
        checked_receipt_count: chain.len(),
        recursion_used,
    }
}
