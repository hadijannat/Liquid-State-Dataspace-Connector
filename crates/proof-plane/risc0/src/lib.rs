#[cfg(feature = "risc0")]
pub use proof_plane_host::Risc0ProofEngine;

#[cfg(not(feature = "risc0"))]
mod stub {
    use async_trait::async_trait;
    use lsdc_common::crypto::ProvenanceReceipt;
    use lsdc_common::dsp::ContractAgreement;
    use lsdc_common::error::{LsdcError, Result};
    use lsdc_common::execution::ProofBackend;
    use lsdc_common::liquid::CsvTransformManifest;
    use lsdc_common::runtime_model::EvidenceDag;
    use lsdc_ports::{CompositionContext, ExecutionBindings, ProofEngine, ProofExecutionResult};

    const RISC0_DISABLED_MESSAGE: &str =
        "risc0 backend requires the `risc0` feature and Risc Zero guest toolchain";

    #[derive(Clone, Default)]
    pub struct Risc0ProofEngine;

    impl Risc0ProofEngine {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl ProofEngine for Risc0ProofEngine {
        fn proof_backend(&self) -> ProofBackend {
            ProofBackend::RiscZero
        }

        async fn execute_csv_transform(
            &self,
            _agreement: &ContractAgreement,
            _input_csv: &[u8],
            _manifest: &CsvTransformManifest,
            _prior_receipt: Option<&ProvenanceReceipt>,
            _execution_bindings: Option<&ExecutionBindings>,
        ) -> Result<ProofExecutionResult> {
            Err(LsdcError::Unsupported(RISC0_DISABLED_MESSAGE.into()))
        }

        async fn verify_receipt(&self, _receipt: &ProvenanceReceipt) -> Result<bool> {
            Err(LsdcError::Unsupported(RISC0_DISABLED_MESSAGE.into()))
        }

        async fn verify_chain(&self, _chain: &[ProvenanceReceipt]) -> Result<bool> {
            Err(LsdcError::Unsupported(RISC0_DISABLED_MESSAGE.into()))
        }

        async fn compose_receipts(
            &self,
            _receipts: &[ProvenanceReceipt],
            _ctx: CompositionContext,
        ) -> Result<ProvenanceReceipt> {
            Err(LsdcError::Unsupported(RISC0_DISABLED_MESSAGE.into()))
        }

        async fn verify_receipt_dag(&self, _dag: &EvidenceDag) -> Result<bool> {
            Err(LsdcError::Unsupported(RISC0_DISABLED_MESSAGE.into()))
        }
    }
}

#[cfg(not(feature = "risc0"))]
pub use stub::Risc0ProofEngine;
