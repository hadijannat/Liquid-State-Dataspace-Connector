use async_trait::async_trait;
use lsdc_common::crypto::{hash_json, ProvenanceReceipt, ReceiptKind, Sha256Hash};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::ProofBackend;
use lsdc_common::execution_overlay::ExecutionStatementKind;
use lsdc_common::liquid::{validate_transform_manifest, CsvTransformManifest};
use lsdc_common::runtime_model::EvidenceDag;
use lsdc_common::proof::{CsvTransformProofInput, CsvTransformProofJournal};
use lsdc_ports::{CompositionContext, ExecutionBindings, ProofEngine, ProofExecutionResult};
use proof_transform_kernel::apply_manifest;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

const RISC0_RECEIPT_FORMAT_VERSION: &str = "lsdc.risc0.receipt.v1";
const RISC0_PROOF_METHOD_ID: &str = "risc0.csv_transform.v1";
const RISC0_RECURSION_UNSUPPORTED: &str = "recursive proving not implemented for risc0 backend";

#[derive(Clone, Default)]
pub struct Risc0ProofEngine;

impl Risc0ProofEngine {
    pub fn new() -> Self {
        Self
    }

    fn verify_receipt_inner(receipt: &Receipt) -> Result<CsvTransformProofJournal> {
        receipt.verify(methods::CSV_TRANSFORM_ID).map_err(|err| {
            LsdcError::ProofGeneration(format!("risc0 receipt verification failed: {err}"))
        })?;
        receipt.journal.decode().map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to decode risc0 receipt journal: {err}"))
        })
    }
}

#[async_trait]
impl ProofEngine for Risc0ProofEngine {
    fn proof_backend(&self) -> ProofBackend {
        ProofBackend::RiscZero
    }

    async fn execute_csv_transform(
        &self,
        agreement: &ContractAgreement,
        input_csv: &[u8],
        manifest: &CsvTransformManifest,
        prior_receipt: Option<&ProvenanceReceipt>,
        execution_bindings: Option<&ExecutionBindings>,
    ) -> Result<ProofExecutionResult> {
        validate_transform_manifest(&agreement.liquid_policy, manifest)?;

        if prior_receipt.is_some() {
            return Err(LsdcError::Unsupported(RISC0_RECURSION_UNSUPPORTED.into()));
        }

        let output_csv = apply_manifest(input_csv, manifest)?;

        let env = ExecutorEnv::builder()
            .write(&CsvTransformProofInput {
                agreement_id: agreement.agreement_id.0.clone(),
                odrl_policy: agreement.odrl_policy.clone(),
                manifest: manifest.clone(),
                input_csv: input_csv.to_vec(),
                agreement_commitment_hash: execution_bindings
                    .map(|bindings| bindings.overlay_commitment.agreement_commitment_hash.clone()),
                session_id: execution_bindings
                    .map(|bindings| bindings.session.session_id.to_string()),
                challenge_nonce_hash: execution_bindings
                    .and_then(|bindings| bindings.challenge.as_ref())
                    .map(|challenge| challenge.challenge_nonce_hash.clone()),
                selector_hash: execution_bindings
                    .and_then(|bindings| bindings.challenge.as_ref())
                    .map(|challenge| challenge.resolved_selector_hash.clone()),
                attestation_result_hash: execution_bindings
                    .and_then(|bindings| bindings.attestation_result_hash.clone()),
                capability_commitment_hash: execution_bindings
                    .map(|bindings| bindings.overlay_commitment.capability_descriptor_hash.clone()),
                transparency_statement_hash: None,
                parent_receipt_hashes: Vec::new(),
                recursion_depth: 0,
                receipt_kind: ReceiptKind::Transform,
            })
            .map_err(|err| {
                LsdcError::ProofGeneration(format!("failed to encode risc0 proof input: {err}"))
            })?
            .build()
            .map_err(|err| {
                LsdcError::ProofGeneration(format!("failed to build risc0 executor env: {err}"))
            })?;

        let prove_info = default_prover()
            .prove(env, methods::CSV_TRANSFORM_ELF)
            .map_err(|err| LsdcError::ProofGeneration(format!("risc0 proving failed: {err}")))?;
        let receipt = prove_info.receipt;
        let journal = Self::verify_receipt_inner(&receipt)?;
        let receipt_bytes = bincode::serialize(&receipt).map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to serialize risc0 receipt: {err}"))
        })?;
        let receipt_hash = Sha256Hash::digest_bytes(&receipt_bytes);

        Ok(ProofExecutionResult {
            output_csv,
            recursion_used: false,
            receipt: ProvenanceReceipt {
                agreement_id: journal.agreement_id,
                input_hash: journal.input_hash,
                output_hash: journal.output_hash,
                policy_hash: journal.policy_hash,
                transform_manifest_hash: journal.transform_manifest_hash,
                prior_receipt_hash: None,
                agreement_commitment_hash: journal.agreement_commitment_hash,
                session_id: journal.session_id,
                challenge_nonce_hash: journal.challenge_nonce_hash,
                selector_hash: journal.selector_hash,
                attestation_result_hash: journal.attestation_result_hash,
                capability_commitment_hash: journal.capability_commitment_hash,
                transparency_statement_hash: journal.transparency_statement_hash,
                parent_receipt_hashes: journal.parent_receipt_hashes,
                recursion_depth: journal.recursion_depth,
                receipt_kind: journal.receipt_kind,
                receipt_hash,
                proof_backend: ProofBackend::RiscZero,
                receipt_format_version: RISC0_RECEIPT_FORMAT_VERSION.into(),
                proof_method_id: RISC0_PROOF_METHOD_ID.into(),
                receipt_bytes,
                timestamp: chrono::Utc::now(),
            },
        })
    }

    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool> {
        if receipt.proof_backend != ProofBackend::RiscZero
            || receipt.receipt_format_version != RISC0_RECEIPT_FORMAT_VERSION
            || receipt.proof_method_id != RISC0_PROOF_METHOD_ID
            || receipt.prior_receipt_hash.is_some()
        {
            return Ok(false);
        }

        let decoded: Receipt = bincode::deserialize(&receipt.receipt_bytes).map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to deserialize risc0 receipt: {err}"))
        })?;
        let journal = Self::verify_receipt_inner(&decoded)?;

        Ok(
            receipt.receipt_hash == Sha256Hash::digest_bytes(&receipt.receipt_bytes)
                && journal.agreement_id == receipt.agreement_id
                && journal.input_hash == receipt.input_hash
                && journal.output_hash == receipt.output_hash
                && journal.policy_hash == receipt.policy_hash
                && journal.transform_manifest_hash == receipt.transform_manifest_hash
                && journal.agreement_commitment_hash == receipt.agreement_commitment_hash
                && journal.session_id == receipt.session_id
                && journal.challenge_nonce_hash == receipt.challenge_nonce_hash
                && journal.selector_hash == receipt.selector_hash
                && journal.attestation_result_hash == receipt.attestation_result_hash
                && journal.capability_commitment_hash == receipt.capability_commitment_hash
                && journal.transparency_statement_hash == receipt.transparency_statement_hash
                && journal.parent_receipt_hashes == receipt.parent_receipt_hashes
                && journal.recursion_depth == receipt.recursion_depth
                && journal.receipt_kind == receipt.receipt_kind,
        )
    }

    async fn verify_chain(&self, chain: &[ProvenanceReceipt]) -> Result<bool> {
        if chain.len() > 1 {
            return Err(LsdcError::Unsupported(RISC0_RECURSION_UNSUPPORTED.into()));
        }

        if let Some(receipt) = chain.first() {
            self.verify_receipt(receipt).await
        } else {
            Ok(true)
        }
    }

    async fn compose_receipts(
        &self,
        _receipts: &[ProvenanceReceipt],
        _ctx: CompositionContext,
    ) -> Result<ProvenanceReceipt> {
        Err(LsdcError::Unsupported(RISC0_RECURSION_UNSUPPORTED.into()))
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
