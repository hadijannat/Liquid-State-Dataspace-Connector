use async_trait::async_trait;
use lsdc_common::crypto::{hash_json, sign_bytes, verify_signature, ProvenanceReceipt, Sha256Hash};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::ProofBackend;
use lsdc_common::liquid::{validate_transform_manifest, CsvTransformManifest};
use lsdc_ports::{ProofEngine, ProofExecutionResult};
use proof_transform_kernel::apply_manifest;
use serde::{Deserialize, Serialize};

const DEFAULT_PROOF_SECRET: &str = "lsdc-proof-dev-secret";
const DEV_RECEIPT_FORMAT_VERSION: &str = "lsdc.dev-receipt.v1";
const DEV_RECEIPT_METHOD_ID: &str = "dev-hmac-manifest-v1";
const PROOF_SECRET_ENV: &str = "LSDC_PROOF_SECRET";
const ALLOW_DEV_DEFAULTS_ENV: &str = "LSDC_ALLOW_DEV_DEFAULTS";

#[derive(Clone)]
pub struct DevReceiptProofEngine {
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

impl Default for DevReceiptProofEngine {
    fn default() -> Self {
        Self::new().expect("failed to initialize dev receipt proof engine")
    }
}

impl DevReceiptProofEngine {
    pub fn new() -> Result<Self> {
        Ok(Self {
            secret: resolve_proof_secret(
                std::env::var(PROOF_SECRET_ENV).ok(),
                allow_dev_defaults(),
            )?,
        })
    }
}

fn allow_dev_defaults() -> bool {
    matches!(std::env::var(ALLOW_DEV_DEFAULTS_ENV).as_deref(), Ok("1"))
}

fn resolve_proof_secret(
    explicit_secret: Option<String>,
    allow_dev_defaults: bool,
) -> Result<String> {
    if let Some(secret) = explicit_secret {
        return Ok(secret);
    }

    if allow_dev_defaults {
        return Ok(DEFAULT_PROOF_SECRET.to_string());
    }

    Err(LsdcError::ProofGeneration(format!(
        "{PROOF_SECRET_ENV} must be set unless {ALLOW_DEV_DEFAULTS_ENV}=1"
    )))
}

#[async_trait]
impl ProofEngine for DevReceiptProofEngine {
    fn proof_backend(&self) -> ProofBackend {
        ProofBackend::DevReceipt
    }

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
                proof_backend: ProofBackend::DevReceipt,
                receipt_format_version: DEV_RECEIPT_FORMAT_VERSION.into(),
                proof_method_id: DEV_RECEIPT_METHOD_ID.into(),
                receipt_bytes: proof_bytes,
                timestamp: chrono::Utc::now(),
            },
        })
    }

    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool> {
        let envelope: ProofEnvelope =
            serde_json::from_slice(&receipt.receipt_bytes).map_err(LsdcError::from)?;
        let claims_bytes = serde_json::to_vec(&envelope.claims).map_err(LsdcError::from)?;

        let signature_valid =
            verify_signature(&self.secret, &claims_bytes, &envelope.signature_hex);
        if !signature_valid {
            return Ok(false);
        }

        Ok(
            receipt.receipt_hash == Sha256Hash::digest_bytes(&receipt.receipt_bytes)
                && receipt.proof_backend == ProofBackend::DevReceipt
                && receipt.receipt_format_version == DEV_RECEIPT_FORMAT_VERSION
                && receipt.proof_method_id == DEV_RECEIPT_METHOD_ID
                && envelope.claims.agreement_id == receipt.agreement_id
                && envelope.claims.input_hash == receipt.input_hash.to_hex()
                && envelope.claims.output_hash == receipt.output_hash.to_hex()
                && envelope.claims.policy_hash == receipt.policy_hash.to_hex()
                && envelope.claims.transform_manifest_hash
                    == receipt.transform_manifest_hash.to_hex()
                && envelope.claims.prior_receipt_hash
                    == receipt.prior_receipt_hash.as_ref().map(Sha256Hash::to_hex),
        )
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
    use super::resolve_proof_secret;

    #[test]
    fn test_resolve_proof_secret_rejects_missing_secret_without_dev_defaults() {
        let err = resolve_proof_secret(None, false).unwrap_err();
        assert!(err
            .to_string()
            .contains("LSDC_PROOF_SECRET must be set unless LSDC_ALLOW_DEV_DEFAULTS=1"));
    }

    #[test]
    fn test_resolve_proof_secret_allows_dev_default_when_enabled() {
        let secret = resolve_proof_secret(None, true).unwrap();
        assert_eq!(secret, "lsdc-proof-dev-secret");
    }
}
