use crate::crypto::{
    AttestationDocument, PriceDecision, PricingAuditContext, ProofBundle, ProofOfForgetting,
    ProvenanceReceipt, SanctionProposal, Sha256Hash, ShapleyValue,
};
use lsdc_policy::{PricingMode, ProofBackend};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelopeV1 {
    pub backend_id: String,
    pub schema_version: u16,
    pub policy_hash: Sha256Hash,
    pub manifest_hash: Sha256Hash,
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub prior_receipt_hash: Option<Sha256Hash>,
    pub recursion_used: bool,
    pub journal: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedClaims {
    pub agreement_id: String,
    pub policy_hash: Sha256Hash,
    pub manifest_hash: Sha256Hash,
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub prior_receipt_hash: Option<Sha256Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub checked_receipt_count: usize,
    pub recursion_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevDeletionEvidence {
    pub attestation: AttestationDocument,
    pub destruction_timestamp: chrono::DateTime<chrono::Utc>,
    pub data_hash: Sha256Hash,
    pub proof_hash: Sha256Hash,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedTeardownEvidence {
    pub attestation: AttestationDocument,
    pub teardown_timestamp: chrono::DateTime<chrono::Utc>,
    pub data_hash: Sha256Hash,
    pub teardown_hash: Sha256Hash,
    pub attestation_anchor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingEvidenceV1 {
    pub utility_algorithm_id: String,
    pub utility_algorithm_version: String,
    pub decision_policy_id: String,
    pub decision_policy_version: String,
    pub advisory: bool,
    pub evidence_anchor_hash: Sha256Hash,
    pub pricing_mode: PricingMode,
    pub audit_context: PricingAuditContext,
    pub shapley_value: ShapleyValue,
    pub price_decision: PriceDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub receipt: ReceiptEnvelopeV1,
    pub attestation: Option<AttestationDocument>,
    pub deletion_evidence: Option<DevDeletionEvidence>,
    pub pricing: Option<PricingEvidenceV1>,
    pub sanction_proposal: Option<SanctionProposal>,
    pub anchor_hash: Sha256Hash,
}

impl ReceiptEnvelopeV1 {
    pub fn verified_claims(&self, agreement_id: impl Into<String>) -> VerifiedClaims {
        VerifiedClaims {
            agreement_id: agreement_id.into(),
            policy_hash: self.policy_hash.clone(),
            manifest_hash: self.manifest_hash.clone(),
            input_hash: self.input_hash.clone(),
            output_hash: self.output_hash.clone(),
            prior_receipt_hash: self.prior_receipt_hash.clone(),
        }
    }
}

impl From<&ProvenanceReceipt> for ReceiptEnvelopeV1 {
    fn from(receipt: &ProvenanceReceipt) -> Self {
        Self {
            backend_id: proof_backend_id(receipt.proof_backend),
            schema_version: 1,
            policy_hash: receipt.policy_hash.clone(),
            manifest_hash: receipt.transform_manifest_hash.clone(),
            input_hash: receipt.input_hash.clone(),
            output_hash: receipt.output_hash.clone(),
            prior_receipt_hash: receipt.prior_receipt_hash.clone(),
            recursion_used: receipt.prior_receipt_hash.is_some(),
            journal: Vec::new(),
            proof: receipt.receipt_bytes.clone(),
        }
    }
}

impl From<&ProofOfForgetting> for DevDeletionEvidence {
    fn from(value: &ProofOfForgetting) -> Self {
        Self {
            attestation: value.attestation.clone(),
            destruction_timestamp: value.destruction_timestamp,
            data_hash: value.data_hash.clone(),
            proof_hash: value.proof_hash.clone(),
            signature_hex: value.signature_hex.clone(),
        }
    }
}

impl PricingEvidenceV1 {
    pub fn from_price_decision(
        decision: &PriceDecision,
        decision_policy_id: impl Into<String>,
        decision_policy_version: impl Into<String>,
    ) -> Self {
        Self {
            utility_algorithm_id: "pricing_oracle".into(),
            utility_algorithm_version: decision.shapley_value.algorithm_version.clone(),
            decision_policy_id: decision_policy_id.into(),
            decision_policy_version: decision_policy_version.into(),
            advisory: decision.pricing_mode == PricingMode::Advisory,
            evidence_anchor_hash: Sha256Hash::digest_bytes(decision.signature_hex.as_bytes()),
            pricing_mode: decision.pricing_mode,
            audit_context: decision.shapley_value.audit_context.clone(),
            shapley_value: decision.shapley_value.clone(),
            price_decision: decision.clone(),
        }
    }
}

impl EvidenceEnvelope {
    pub fn from_legacy(
        proof_bundle: &ProofBundle,
        price_decision: Option<&PriceDecision>,
        sanction_proposal: Option<&SanctionProposal>,
    ) -> Self {
        let pricing = price_decision.map(|decision| {
            PricingEvidenceV1::from_price_decision(decision, "advisory_pricing_policy", "v1")
        });
        let anchor_source = pricing
            .as_ref()
            .map(|item| item.evidence_anchor_hash.clone())
            .unwrap_or_else(|| proof_bundle.job_audit_hash.clone());

        Self {
            receipt: ReceiptEnvelopeV1::from(&proof_bundle.provenance_receipt),
            attestation: Some(proof_bundle.attestation.clone()),
            deletion_evidence: Some(DevDeletionEvidence::from(&proof_bundle.proof_of_forgetting)),
            pricing,
            sanction_proposal: sanction_proposal.cloned(),
            anchor_hash: anchor_source,
        }
    }
}

fn proof_backend_id(backend: ProofBackend) -> String {
    match backend {
        ProofBackend::None => "none",
        ProofBackend::DevReceipt => "dev_receipt",
        ProofBackend::RiscZero => "risc0",
    }
    .into()
}
