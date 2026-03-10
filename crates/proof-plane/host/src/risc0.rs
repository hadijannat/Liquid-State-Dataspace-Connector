use async_trait::async_trait;
use lsdc_common::crypto::{hash_json, ProvenanceReceipt, Sha256Hash};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::ProofBackend;
use lsdc_common::liquid::{validate_transform_manifest, CsvTransformManifest};
use lsdc_common::proof::CsvTransformProofJournal;
use lsdc_common::runtime_model::EvidenceDag;
use lsdc_ports::{CompositionContext, ExecutionBindings, ProofEngine, ProofExecutionResult};
use proof_plane_core::{verify_provenance_receipt_chain, verify_provenance_receipt_dag};
use proof_plane_risc0_model::{
    ReceiptAssumptionWitness, ReceiptCompositionContext, ReceiptCompositionProofInput,
    RecursiveCsvTransformProofInput, Risc0CsvTransformManifest,
};
use proof_transform_kernel::apply_manifest;
use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts, Receipt};
use serde::Serialize;

#[allow(dead_code)]
mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

const RISC0_RECEIPT_FORMAT_VERSION: &str = "lsdc.risc0.receipt.v1";
const RISC0_TRANSFORM_METHOD_ID: &str = "risc0.csv_transform.v1";
const RISC0_COMPOSITION_METHOD_ID: &str = "risc0.receipt_composition.v1";
const RISC0_RECURSION_BACKEND_MISMATCH: &str =
    "risc0 recursive proving only supports prior and child receipts produced by the risc0 backend";
const RISC0_INVALID_RECURSIVE_PARENT: &str =
    "risc0 recursive proving requires valid risc0 parent receipts";

#[derive(Clone, Copy)]
enum Risc0GuestMethod {
    Transform,
    Composition,
}

impl Risc0GuestMethod {
    fn elf(self) -> &'static [u8] {
        match self {
            Self::Transform => methods::CSV_TRANSFORM_ELF,
            Self::Composition => methods::RECEIPT_COMPOSITION_ELF,
        }
    }

    fn image_id(self) -> [u32; 8] {
        match self {
            Self::Transform => methods::CSV_TRANSFORM_ID,
            Self::Composition => methods::RECEIPT_COMPOSITION_ID,
        }
    }

    fn proof_method_id(self) -> &'static str {
        match self {
            Self::Transform => RISC0_TRANSFORM_METHOD_ID,
            Self::Composition => RISC0_COMPOSITION_METHOD_ID,
        }
    }
}

#[derive(Clone, Default)]
pub struct Risc0ProofEngine;

impl Risc0ProofEngine {
    pub fn new() -> Self {
        Self
    }

    fn method_for_proof_method_id(proof_method_id: &str) -> Option<Risc0GuestMethod> {
        match proof_method_id {
            RISC0_TRANSFORM_METHOD_ID => Some(Risc0GuestMethod::Transform),
            RISC0_COMPOSITION_METHOD_ID => Some(Risc0GuestMethod::Composition),
            _ => None,
        }
    }

    fn verify_receipt_inner(
        receipt: &Receipt,
        method: Risc0GuestMethod,
    ) -> Result<CsvTransformProofJournal> {
        receipt.verify(method.image_id()).map_err(|err| {
            LsdcError::ProofGeneration(format!("risc0 receipt verification failed: {err}"))
        })?;
        receipt.journal.decode().map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to decode risc0 receipt journal: {err}"))
        })
    }

    fn decode_receipt_bytes(receipt_bytes: &[u8]) -> Result<Receipt> {
        bincode::deserialize(receipt_bytes).map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to deserialize risc0 receipt: {err}"))
        })
    }

    fn assumption_witness(receipt: &ProvenanceReceipt) -> Result<ReceiptAssumptionWitness> {
        let method = Self::method_for_proof_method_id(&receipt.proof_method_id)
            .ok_or_else(|| LsdcError::ProofGeneration("unsupported risc0 proof method".into()))?;
        Ok(ReceiptAssumptionWitness {
            image_id: method.image_id(),
            receipt_bytes: receipt.receipt_bytes.clone(),
        })
    }

    fn receipt_from_verified_journal(
        receipt: Receipt,
        journal: CsvTransformProofJournal,
        method: Risc0GuestMethod,
    ) -> Result<ProvenanceReceipt> {
        let receipt_bytes = bincode::serialize(&receipt).map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to serialize risc0 receipt: {err}"))
        })?;
        let receipt_hash = Sha256Hash::digest_bytes(&receipt_bytes);

        Ok(ProvenanceReceipt {
            agreement_id: journal.agreement_id,
            input_hash: journal.input_hash,
            output_hash: journal.output_hash,
            policy_hash: journal.policy_hash,
            transform_manifest_hash: journal.transform_manifest_hash,
            prior_receipt_hash: journal.prior_receipt_hash,
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
            proof_method_id: method.proof_method_id().into(),
            receipt_bytes,
            timestamp: chrono::Utc::now(),
        })
    }

    async fn checked_witness(
        &self,
        receipt: &ProvenanceReceipt,
    ) -> Result<ReceiptAssumptionWitness> {
        if receipt.proof_backend != ProofBackend::RiscZero {
            return Err(LsdcError::Unsupported(
                RISC0_RECURSION_BACKEND_MISMATCH.into(),
            ));
        }

        if !self.verify_receipt(receipt).await? {
            return Err(LsdcError::ProofGeneration(
                RISC0_INVALID_RECURSIVE_PARENT.into(),
            ));
        }

        Self::assumption_witness(receipt)
    }

    fn prove_with_assumptions<T: Serialize>(
        method: Risc0GuestMethod,
        input: &T,
        assumptions: &[ReceiptAssumptionWitness],
    ) -> Result<(Receipt, CsvTransformProofJournal)> {
        let mut builder = ExecutorEnv::builder();
        builder.write(input).map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to encode risc0 proof input: {err}"))
        })?;

        for witness in assumptions {
            builder.add_assumption(Self::decode_receipt_bytes(&witness.receipt_bytes)?);
        }

        let env = builder.build().map_err(|err| {
            LsdcError::ProofGeneration(format!("failed to build risc0 executor env: {err}"))
        })?;
        let prove_info = default_prover()
            .prove_with_opts(env, method.elf(), &ProverOpts::succinct())
            .map_err(|err| LsdcError::ProofGeneration(format!("risc0 proving failed: {err}")))?;
        let receipt = prove_info.receipt;
        let journal = Self::verify_receipt_inner(&receipt, method)?;
        Ok((receipt, journal))
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
        let prior_witness = match prior_receipt {
            Some(receipt) => Some(self.checked_witness(receipt).await?),
            None => None,
        };

        let output_csv = apply_manifest(input_csv, manifest)?;
        let proof_input = RecursiveCsvTransformProofInput {
            agreement_id: agreement.agreement_id.0.clone(),
            manifest: Risc0CsvTransformManifest::from(manifest),
            input_csv: input_csv.to_vec(),
            policy_hash: hash_json(&agreement.odrl_policy).map_err(LsdcError::from)?,
            agreement_commitment_hash: execution_bindings.map(|bindings| {
                bindings
                    .overlay_commitment
                    .agreement_commitment_hash
                    .clone()
            }),
            session_id: execution_bindings.map(|bindings| bindings.session.session_id.to_string()),
            challenge_nonce_hash: execution_bindings
                .and_then(|bindings| bindings.challenge.as_ref())
                .map(|challenge| challenge.challenge_nonce_hash.clone()),
            selector_hash: execution_bindings
                .and_then(|bindings| bindings.challenge.as_ref())
                .map(|challenge| challenge.resolved_selector_hash.clone()),
            attestation_result_hash: execution_bindings
                .and_then(|bindings| bindings.attestation_result_hash.clone()),
            capability_commitment_hash: execution_bindings.map(|bindings| {
                bindings
                    .overlay_commitment
                    .capability_descriptor_hash
                    .clone()
            }),
            transparency_statement_hash: None,
            prior_receipt: prior_witness.clone(),
        };
        let assumptions = prior_witness.into_iter().collect::<Vec<_>>();
        let (receipt, journal) =
            Self::prove_with_assumptions(Risc0GuestMethod::Transform, &proof_input, &assumptions)?;
        let receipt =
            Self::receipt_from_verified_journal(receipt, journal, Risc0GuestMethod::Transform)?;

        Ok(ProofExecutionResult {
            output_csv,
            recursion_used: receipt.prior_receipt_hash.is_some(),
            receipt,
        })
    }

    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool> {
        if receipt.proof_backend != ProofBackend::RiscZero
            || receipt.receipt_format_version != RISC0_RECEIPT_FORMAT_VERSION
        {
            return Ok(false);
        }

        let Some(method) = Self::method_for_proof_method_id(&receipt.proof_method_id) else {
            return Ok(false);
        };
        let decoded = Self::decode_receipt_bytes(&receipt.receipt_bytes)?;
        let journal = Self::verify_receipt_inner(&decoded, method)?;

        Ok(
            receipt.receipt_hash == Sha256Hash::digest_bytes(&receipt.receipt_bytes)
                && journal.agreement_id == receipt.agreement_id
                && journal.input_hash == receipt.input_hash
                && journal.output_hash == receipt.output_hash
                && journal.policy_hash == receipt.policy_hash
                && journal.transform_manifest_hash == receipt.transform_manifest_hash
                && journal.prior_receipt_hash == receipt.prior_receipt_hash
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
        let linkage = verify_provenance_receipt_chain(chain);
        if !linkage.valid {
            return Ok(false);
        }

        for receipt in chain {
            if !self.verify_receipt(receipt).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn compose_receipts(
        &self,
        receipts: &[ProvenanceReceipt],
        ctx: CompositionContext,
    ) -> Result<ProvenanceReceipt> {
        if receipts.is_empty() {
            return Err(LsdcError::ProofGeneration(
                "cannot compose an empty receipt set".into(),
            ));
        }

        let mut witnesses = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            witnesses.push(self.checked_witness(receipt).await?);
        }

        let input = ReceiptCompositionProofInput {
            context: ReceiptCompositionContext {
                agreement_id: ctx.agreement_id,
                agreement_commitment_hash: ctx.agreement_commitment_hash,
                session_id: ctx.session_id,
                selector_hash: ctx.selector_hash,
                capability_commitment_hash: ctx.capability_commitment_hash,
            },
            child_receipts: witnesses.clone(),
        };
        let (receipt, journal) =
            Self::prove_with_assumptions(Risc0GuestMethod::Composition, &input, &witnesses)?;

        Self::receipt_from_verified_journal(receipt, journal, Risc0GuestMethod::Composition)
    }

    async fn verify_receipt_dag(&self, dag: &EvidenceDag) -> Result<bool> {
        let verification = verify_provenance_receipt_dag(dag).map_err(LsdcError::from)?;
        if !verification.valid {
            return Ok(false);
        }

        for node in &dag.nodes {
            if node.kind
                != lsdc_common::execution_overlay::ExecutionStatementKind::ProofReceiptRegistered
            {
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
