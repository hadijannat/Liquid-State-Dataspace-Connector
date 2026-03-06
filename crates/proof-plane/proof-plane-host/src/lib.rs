use async_trait::async_trait;
use lsdc_common::crypto::{
    hash_json, sign_bytes, verify_signature, ProvenanceReceipt, Sha256Hash,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::liquid::{validate_transform_manifest, CsvTransformManifest};
use lsdc_common::traits::{ProofEngine, ProofExecutionResult};
use proof_plane_guest::apply_manifest;
use serde::{Deserialize, Serialize};

const DEFAULT_PROOF_SECRET: &str = "lsdc-proof-dev-secret";

#[derive(Clone)]
pub struct RiscZeroProofEngine {
    secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProofClaims {
    agreement_id: String,
    input_hash: String,
    output_hash: String,
    policy_hash: String,
    transform_manifest_hash: String,
    prior_receipt_hash: Option<String>,
    recursion_used: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProofEnvelope {
    claims: ProofClaims,
    signature_hex: String,
}

impl Default for RiscZeroProofEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RiscZeroProofEngine {
    pub fn new() -> Self {
        Self {
            secret: std::env::var("LSDC_PROOF_SECRET")
                .unwrap_or_else(|_| DEFAULT_PROOF_SECRET.to_string()),
        }
    }
}

#[async_trait]
impl ProofEngine for RiscZeroProofEngine {
    async fn execute_csv_transform(
        &self,
        agreement: &ContractAgreement,
        input_csv: &[u8],
        manifest: &CsvTransformManifest,
        prior_receipt: Option<&ProvenanceReceipt>,
    ) -> Result<ProofExecutionResult> {
        validate_transform_manifest(&agreement.liquid_policy, manifest)?;

        if let Some(previous) = prior_receipt {
            if !self.verify_receipt(previous).await? {
                return Err(LsdcError::ProofGeneration(
                    "prior provenance receipt failed verification".into(),
                ));
            }
        }

        let output_csv = apply_manifest(input_csv, manifest)?;
        let input_hash = Sha256Hash::digest_bytes(input_csv);
        let output_hash = Sha256Hash::digest_bytes(&output_csv);
        let policy_hash = hash_json(&agreement.odrl_policy)?;
        let transform_manifest_hash =
            Sha256Hash::digest_bytes(&serde_json::to_vec(manifest).map_err(LsdcError::from)?);
        let prior_receipt_hash = prior_receipt.map(|receipt| receipt.receipt_hash.clone());
        let recursion_used = prior_receipt_hash.is_some();

        let claims = ProofClaims {
            agreement_id: agreement.agreement_id.0.clone(),
            input_hash: input_hash.to_hex(),
            output_hash: output_hash.to_hex(),
            policy_hash: policy_hash.to_hex(),
            transform_manifest_hash: transform_manifest_hash.to_hex(),
            prior_receipt_hash: prior_receipt_hash.as_ref().map(Sha256Hash::to_hex),
            recursion_used,
        };

        let claims_bytes = serde_json::to_vec(&claims).map_err(LsdcError::from)?;
        let envelope = ProofEnvelope {
            signature_hex: sign_bytes(&self.secret, &claims_bytes),
            claims,
        };
        let proof_bytes = serde_json::to_vec(&envelope).map_err(LsdcError::from)?;
        let receipt_hash = Sha256Hash::digest_bytes(&proof_bytes);

        Ok(ProofExecutionResult {
            output_csv,
            recursion_used,
            receipt: ProvenanceReceipt {
                agreement_id: agreement.agreement_id.0.clone(),
                input_hash,
                output_hash,
                policy_hash,
                transform_manifest_hash,
                prior_receipt_hash,
                receipt_hash,
                proof_system: if recursion_used {
                    "risc0-dev-recursive".into()
                } else {
                    "risc0-dev-local".into()
                },
                proof_bytes,
                timestamp: chrono::Utc::now(),
            },
        })
    }

    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool> {
        let envelope: ProofEnvelope =
            serde_json::from_slice(&receipt.proof_bytes).map_err(LsdcError::from)?;
        let claims_bytes = serde_json::to_vec(&envelope.claims).map_err(LsdcError::from)?;

        let signature_valid = verify_signature(&self.secret, &claims_bytes, &envelope.signature_hex);
        if !signature_valid {
            return Ok(false);
        }

        Ok(receipt.receipt_hash == Sha256Hash::digest_bytes(&receipt.proof_bytes)
            && envelope.claims.agreement_id == receipt.agreement_id
            && envelope.claims.input_hash == receipt.input_hash.to_hex()
            && envelope.claims.output_hash == receipt.output_hash.to_hex()
            && envelope.claims.policy_hash == receipt.policy_hash.to_hex()
            && envelope.claims.transform_manifest_hash == receipt.transform_manifest_hash.to_hex()
            && envelope.claims.prior_receipt_hash
                == receipt.prior_receipt_hash.as_ref().map(Sha256Hash::to_hex))
    }

    async fn verify_chain(&self, chain: &[ProvenanceReceipt]) -> Result<bool> {
        if chain.is_empty() {
            return Ok(true);
        }

        for (index, receipt) in chain.iter().enumerate() {
            if !self.verify_receipt(receipt).await? {
                return Ok(false);
            }

            if index > 0
                && receipt.prior_receipt_hash.as_ref() != Some(&chain[index - 1].receipt_hash)
            {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
    use lsdc_common::liquid::{
        CsvTransformManifest, CsvTransformOp, CsvTransformOpKind, LiquidPolicyIr, RuntimeGuard,
        TransformGuard, TransportGuard,
    };
    use lsdc_common::odrl::ast::PolicyId;

    fn agreement() -> ContractAgreement {
        ContractAgreement {
            agreement_id: PolicyId("agreement-proof".into()),
            asset_id: "asset-1".into(),
            provider_id: "did:web:provider".into(),
            consumer_id: "did:web:consumer".into(),
            odrl_policy: serde_json::json!({
                "permission": [{
                    "action": ["read", "transfer", "anonymize"],
                    "constraint": [{ "leftOperand": "purpose", "rightOperand": ["analytics"] }],
                    "duty": [{ "action": "anonymize", "constraint": [{ "leftOperand": "transform-required", "rightOperand": "redact_columns" }] }]
                }]
            }),
            policy_hash: "policy-hash".into(),
            evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
            liquid_policy: LiquidPolicyIr {
                transport_guard: TransportGuard {
                    allow_read: true,
                    allow_transfer: true,
                    packet_cap: Some(100),
                    byte_cap: None,
                    allowed_regions: vec!["EU".into()],
                    valid_until: None,
                    protocol: TransportProtocol::Udp,
                    session_port: None,
                },
                transform_guard: TransformGuard {
                    allow_anonymize: true,
                    allowed_purposes: vec!["analytics".into()],
                    required_ops: vec![CsvTransformOpKind::RedactColumns],
                },
                runtime_guard: RuntimeGuard {
                    delete_after_seconds: Some(3600),
                    evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                    approval_required: false,
                },
            },
        }
    }

    fn manifest() -> CsvTransformManifest {
        CsvTransformManifest {
            dataset_id: "dataset-1".into(),
            purpose: "analytics".into(),
            ops: vec![CsvTransformOp::RedactColumns {
                columns: vec!["name".into()],
                replacement: "***".into(),
            }],
        }
    }

    #[tokio::test]
    async fn test_proves_and_verifies_transform() {
        let engine = RiscZeroProofEngine::new();
        let result = engine
            .execute_csv_transform(
                &agreement(),
                b"id,name\n1,Alice\n",
                &manifest(),
                None,
            )
            .await
            .unwrap();

        assert!(String::from_utf8(result.output_csv).unwrap().contains("***"));
        assert!(engine.verify_receipt(&result.receipt).await.unwrap());
    }

    #[tokio::test]
    async fn test_verifies_receipt_chain() {
        let engine = RiscZeroProofEngine::new();
        let agreement = agreement();
        let manifest = manifest();
        let first = engine
            .execute_csv_transform(&agreement, b"id,name\n1,Alice\n", &manifest, None)
            .await
            .unwrap();
        let second = engine
            .execute_csv_transform(
                &agreement,
                first.output_csv.as_slice(),
                &manifest,
                Some(&first.receipt),
            )
            .await
            .unwrap();

        assert!(engine
            .verify_chain(&[first.receipt, second.receipt])
            .await
            .unwrap());
    }
}
