use async_trait::async_trait;
use lsdc_common::crypto::{
    hash_json, sign_bytes, verify_signature, ProvenanceReceipt, ReceiptKind, Sha256Hash,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::ProofBackend;
use lsdc_common::execution_overlay::ExecutionStatementKind;
use lsdc_common::liquid::{validate_transform_manifest, CsvTransformManifest};
use lsdc_common::runtime_model::EvidenceDag;
use lsdc_ports::{ProofEngine, ProofExecutionResult};
use proof_transform_kernel::apply_manifest;
use serde::{Deserialize, Serialize};

const DEFAULT_PROOF_SECRET: &str = "lsdc-proof-dev-secret";
const DEV_RECEIPT_FORMAT_VERSION: &str = "lsdc.dev-receipt.v1";
const DEV_RECEIPT_METHOD_ID: &str = "dev-hmac-manifest-v1";
const DEV_COMPOSITION_METHOD_ID: &str = "dev-hmac-composition-v1";
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
    agreement_commitment_hash: Option<String>,
    session_id: Option<String>,
    challenge_nonce_hash: Option<String>,
    selector_hash: Option<String>,
    attestation_result_hash: Option<String>,
    capability_commitment_hash: Option<String>,
    transparency_statement_hash: Option<String>,
    parent_receipt_hashes: Vec<String>,
    recursion_depth: u32,
    receipt_kind: ReceiptKind,
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
    if let Some(secret) = explicit_secret.filter(|secret| !secret.trim().is_empty()) {
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
        execution_bindings: Option<&lsdc_ports::ExecutionBindings>,
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
        let parent_receipt_hashes = prior_receipt_hash.clone().into_iter().collect::<Vec<_>>();
        let agreement_commitment_hash = execution_bindings.map(|bindings| {
            bindings
                .overlay_commitment
                .agreement_commitment_hash
                .clone()
        });
        let session_id = execution_bindings.map(|bindings| bindings.session.session_id.to_string());
        let challenge_nonce_hash = execution_bindings
            .and_then(|bindings| bindings.challenge.as_ref())
            .map(|challenge| challenge.challenge_nonce_hash.clone());
        let selector_hash = execution_bindings
            .and_then(|bindings| bindings.challenge.as_ref())
            .map(|challenge| challenge.resolved_selector_hash.clone());
        let attestation_result_hash =
            execution_bindings.and_then(|bindings| bindings.attestation_result_hash.clone());
        let capability_commitment_hash = execution_bindings.map(|bindings| {
            bindings
                .overlay_commitment
                .capability_descriptor_hash
                .clone()
        });
        let transparency_statement_hash = None;
        let recursion_depth = prior_receipt
            .map(|receipt| receipt.recursion_depth + 1)
            .unwrap_or(0);
        let recursion_used = prior_receipt_hash.is_some();

        let claims = ProofClaims {
            agreement_id: agreement.agreement_id.0.clone(),
            input_hash: input_hash.to_hex(),
            output_hash: output_hash.to_hex(),
            policy_hash: policy_hash.to_hex(),
            transform_manifest_hash: transform_manifest_hash.to_hex(),
            prior_receipt_hash: prior_receipt_hash.as_ref().map(Sha256Hash::to_hex),
            agreement_commitment_hash: agreement_commitment_hash.as_ref().map(Sha256Hash::to_hex),
            session_id: session_id.clone(),
            challenge_nonce_hash: challenge_nonce_hash.as_ref().map(Sha256Hash::to_hex),
            selector_hash: selector_hash.as_ref().map(Sha256Hash::to_hex),
            attestation_result_hash: attestation_result_hash.as_ref().map(Sha256Hash::to_hex),
            capability_commitment_hash: capability_commitment_hash.as_ref().map(Sha256Hash::to_hex),
            transparency_statement_hash: transparency_statement_hash
                .as_ref()
                .map(Sha256Hash::to_hex),
            parent_receipt_hashes: parent_receipt_hashes
                .iter()
                .map(Sha256Hash::to_hex)
                .collect(),
            recursion_depth,
            receipt_kind: ReceiptKind::Transform,
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
                agreement_commitment_hash,
                session_id,
                challenge_nonce_hash,
                selector_hash,
                attestation_result_hash,
                capability_commitment_hash,
                transparency_statement_hash,
                parent_receipt_hashes,
                recursion_depth,
                receipt_kind: ReceiptKind::Transform,
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
                && matches!(
                    receipt.proof_method_id.as_str(),
                    DEV_RECEIPT_METHOD_ID | DEV_COMPOSITION_METHOD_ID
                )
                && envelope.claims.agreement_id == receipt.agreement_id
                && envelope.claims.input_hash == receipt.input_hash.to_hex()
                && envelope.claims.output_hash == receipt.output_hash.to_hex()
                && envelope.claims.policy_hash == receipt.policy_hash.to_hex()
                && envelope.claims.transform_manifest_hash
                    == receipt.transform_manifest_hash.to_hex()
                && envelope.claims.prior_receipt_hash
                    == receipt.prior_receipt_hash.as_ref().map(Sha256Hash::to_hex)
                && envelope.claims.agreement_commitment_hash
                    == receipt
                        .agreement_commitment_hash
                        .as_ref()
                        .map(Sha256Hash::to_hex)
                && envelope.claims.session_id == receipt.session_id
                && envelope.claims.challenge_nonce_hash
                    == receipt
                        .challenge_nonce_hash
                        .as_ref()
                        .map(Sha256Hash::to_hex)
                && envelope.claims.selector_hash
                    == receipt.selector_hash.as_ref().map(Sha256Hash::to_hex)
                && envelope.claims.attestation_result_hash
                    == receipt
                        .attestation_result_hash
                        .as_ref()
                        .map(Sha256Hash::to_hex)
                && envelope.claims.capability_commitment_hash
                    == receipt
                        .capability_commitment_hash
                        .as_ref()
                        .map(Sha256Hash::to_hex)
                && envelope.claims.transparency_statement_hash
                    == receipt
                        .transparency_statement_hash
                        .as_ref()
                        .map(Sha256Hash::to_hex)
                && envelope.claims.parent_receipt_hashes
                    == receipt
                        .parent_receipt_hashes
                        .iter()
                        .map(Sha256Hash::to_hex)
                        .collect::<Vec<_>>()
                && envelope.claims.recursion_depth == receipt.recursion_depth
                && envelope.claims.receipt_kind == receipt.receipt_kind,
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

    async fn compose_receipts(
        &self,
        receipts: &[ProvenanceReceipt],
        ctx: lsdc_ports::CompositionContext,
    ) -> Result<ProvenanceReceipt> {
        if receipts.is_empty() {
            return Err(LsdcError::ProofGeneration(
                "cannot compose an empty receipt set".into(),
            ));
        }

        for receipt in receipts {
            if !self.verify_receipt(receipt).await? {
                return Err(LsdcError::ProofGeneration(
                    "cannot compose invalid child receipts".into(),
                ));
            }
        }

        let parent_receipt_hashes = receipts
            .iter()
            .map(|receipt| receipt.receipt_hash.clone())
            .collect::<Vec<_>>();
        let input_hash = Sha256Hash::digest_bytes(
            &serde_json::to_vec(
                &receipts
                    .iter()
                    .map(|receipt| receipt.input_hash.to_hex())
                    .collect::<Vec<_>>(),
            )
            .map_err(LsdcError::from)?,
        );
        let output_hash = Sha256Hash::digest_bytes(
            &serde_json::to_vec(
                &receipts
                    .iter()
                    .map(|receipt| receipt.output_hash.to_hex())
                    .collect::<Vec<_>>(),
            )
            .map_err(LsdcError::from)?,
        );
        let policy_hash = Sha256Hash::digest_bytes(
            &serde_json::to_vec(
                &receipts
                    .iter()
                    .map(|receipt| receipt.policy_hash.to_hex())
                    .collect::<Vec<_>>(),
            )
            .map_err(LsdcError::from)?,
        );
        let transform_manifest_hash = Sha256Hash::digest_bytes(
            &serde_json::to_vec(
                &receipts
                    .iter()
                    .map(|receipt| receipt.transform_manifest_hash.to_hex())
                    .collect::<Vec<_>>(),
            )
            .map_err(LsdcError::from)?,
        );
        let recursion_depth = receipts
            .iter()
            .map(|receipt| receipt.recursion_depth)
            .max()
            .unwrap_or(0)
            + 1;
        let claims = ProofClaims {
            agreement_id: ctx.agreement_id.clone(),
            input_hash: input_hash.to_hex(),
            output_hash: output_hash.to_hex(),
            policy_hash: policy_hash.to_hex(),
            transform_manifest_hash: transform_manifest_hash.to_hex(),
            prior_receipt_hash: None,
            agreement_commitment_hash: ctx
                .agreement_commitment_hash
                .as_ref()
                .map(Sha256Hash::to_hex),
            session_id: ctx.session_id.clone(),
            challenge_nonce_hash: None,
            selector_hash: ctx.selector_hash.as_ref().map(Sha256Hash::to_hex),
            attestation_result_hash: None,
            capability_commitment_hash: ctx
                .capability_commitment_hash
                .as_ref()
                .map(Sha256Hash::to_hex),
            transparency_statement_hash: None,
            parent_receipt_hashes: parent_receipt_hashes
                .iter()
                .map(Sha256Hash::to_hex)
                .collect(),
            recursion_depth,
            receipt_kind: ReceiptKind::Composition,
            recursion_used: true,
        };
        let claims_bytes = serde_json::to_vec(&claims).map_err(LsdcError::from)?;
        let envelope = ProofEnvelope {
            signature_hex: sign_bytes(&self.secret, &claims_bytes),
            claims,
        };
        let proof_bytes = serde_json::to_vec(&envelope).map_err(LsdcError::from)?;
        let receipt_hash = Sha256Hash::digest_bytes(&proof_bytes);

        Ok(ProvenanceReceipt {
            agreement_id: ctx.agreement_id,
            input_hash,
            output_hash,
            policy_hash,
            transform_manifest_hash,
            prior_receipt_hash: None,
            agreement_commitment_hash: ctx.agreement_commitment_hash,
            session_id: ctx.session_id,
            challenge_nonce_hash: None,
            selector_hash: ctx.selector_hash,
            attestation_result_hash: None,
            capability_commitment_hash: ctx.capability_commitment_hash,
            transparency_statement_hash: None,
            parent_receipt_hashes,
            recursion_depth,
            receipt_kind: ReceiptKind::Composition,
            receipt_hash,
            proof_backend: ProofBackend::DevReceipt,
            receipt_format_version: DEV_RECEIPT_FORMAT_VERSION.into(),
            proof_method_id: DEV_COMPOSITION_METHOD_ID.into(),
            receipt_bytes: proof_bytes,
            timestamp: chrono::Utc::now(),
        })
    }

    async fn verify_receipt_dag(&self, dag: &EvidenceDag) -> Result<bool> {
        for node in &dag.nodes {
            if node.kind != ExecutionStatementKind::ProofReceiptRegistered {
                continue;
            }
            let receipt: ProvenanceReceipt =
                serde_json::from_value(node.payload_json.clone()).map_err(LsdcError::from)?;
            if !self.verify_receipt(&receipt).await? {
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
    fn test_resolve_proof_secret_rejects_blank_secret_without_dev_defaults() {
        let err = resolve_proof_secret(Some("   ".into()), false).unwrap_err();
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
