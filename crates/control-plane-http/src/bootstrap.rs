use crate::state::{ApiState, ApiStateInit, BackendSummary};
use anyhow::{anyhow, Result as AnyhowResult};
use control_plane::pricing::GrpcPricingOracle;
use control_plane_store::Store;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use lsdc_config::ControlPlaneApiConfig;
use lsdc_ports::{EnclaveManager, PricingOracle, ProofEngine};
use proof_plane_host::DevReceiptProofEngine;
#[cfg(feature = "risc0")]
use proof_plane_host::Risc0ProofEngine;
use std::sync::Arc;
use tee_orchestrator::enclave::{NitroEnclaveManager, NitroLiveAttestationMaterial};

pub async fn state_from_config(config: &ControlPlaneApiConfig) -> AnyhowResult<ApiState> {
    let liquid_agent = Arc::new(LiquidAgentGrpcClient::new(
        config.liquid_agent_endpoint.clone(),
    ));
    let actual_transport_backend = liquid_agent.transport_backend().await?;
    let configured_backends = BackendSummary {
        transport_backend: config.transport_backend,
        proof_backend: config.proof_backend,
        tee_backend: config.tee_backend,
    };
    validate_backend_intent(
        "transport",
        configured_backends.transport_backend,
        actual_transport_backend,
    )?;

    let proof_engine = build_proof_engine(config.proof_backend)?;
    validate_backend_intent(
        "proof",
        configured_backends.proof_backend,
        proof_engine.proof_backend(),
    )?;
    let enclave_manager = build_enclave_manager(config.tee_backend, proof_engine.clone(), config)?;
    validate_backend_intent(
        "tee",
        configured_backends.tee_backend,
        enclave_manager.tee_backend(),
    )?;
    let pricing_oracle: Arc<dyn PricingOracle> =
        Arc::new(GrpcPricingOracle::new(config.pricing_endpoint.clone()));
    let store = Store::new(&config.database_path)?;

    Ok(ApiState::new(ApiStateInit {
        store,
        node_name: config.node_name.clone(),
        liquid_agent,
        proof_engine,
        enclave_manager,
        pricing_oracle,
        default_interface: config.default_interface.clone(),
        configured_backends,
        actual_transport_backend,
    }))
}

fn build_proof_engine(
    proof_backend: lsdc_common::execution::ProofBackend,
) -> AnyhowResult<Arc<dyn ProofEngine>> {
    match proof_backend {
        lsdc_common::execution::ProofBackend::DevReceipt => {
            Ok(Arc::new(DevReceiptProofEngine::new()))
        }
        lsdc_common::execution::ProofBackend::RiscZero => {
            #[cfg(feature = "risc0")]
            {
                Ok(Arc::new(Risc0ProofEngine::new()))
            }

            #[cfg(not(feature = "risc0"))]
            {
                Err(anyhow!(
                    "proof backend `risc_zero` requires building control-plane-api with the `risc0` feature"
                ))
            }
        }
        lsdc_common::execution::ProofBackend::None => {
            Err(anyhow!("proof backend `none` is not valid for Phase 3"))
        }
    }
}

fn build_enclave_manager(
    tee_backend: lsdc_common::execution::TeeBackend,
    proof_engine: Arc<dyn ProofEngine>,
    config: &ControlPlaneApiConfig,
) -> AnyhowResult<Arc<dyn EnclaveManager>> {
    match tee_backend {
        lsdc_common::execution::TeeBackend::NitroDev => {
            Ok(Arc::new(NitroEnclaveManager::new_dev(proof_engine)))
        }
        lsdc_common::execution::TeeBackend::NitroLive => {
            let path = config
                .nitro_live_attestation_path
                .as_ref()
                .ok_or_else(|| anyhow!("nitro_live requires `nitro_live_attestation_path`"))?;
            Ok(Arc::new(NitroEnclaveManager::new_live(
                proof_engine,
                load_live_attestation_material(path)?,
            )?))
        }
        lsdc_common::execution::TeeBackend::None => {
            Err(anyhow!("tee backend `none` is not valid for Phase 3"))
        }
    }
}

fn validate_backend_intent<T>(label: &str, configured: T, actual: T) -> AnyhowResult<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if configured == actual {
        return Ok(());
    }

    Err(anyhow!(
        "configured {label} backend {configured:?} does not match instantiated backend {actual:?}"
    ))
}

fn load_live_attestation_material(path: &str) -> AnyhowResult<NitroLiveAttestationMaterial> {
    #[derive(serde::Deserialize)]
    struct FixtureMeasurements {
        image_hash_hex: String,
        pcrs: std::collections::BTreeMap<u16, String>,
        debug: bool,
    }

    #[derive(serde::Deserialize)]
    struct FixtureMaterial {
        enclave_id: String,
        expected_image_hash_hex: String,
        measurements: FixtureMeasurements,
        raw_attestation_document_utf8: String,
        certificate_chain_pem: Vec<String>,
        timestamp: String,
    }

    let raw = std::fs::read_to_string(path)?;
    let fixture: FixtureMaterial = serde_json::from_str(&raw)?;
    Ok(NitroLiveAttestationMaterial {
        enclave_id: fixture.enclave_id,
        expected_image_hash: lsdc_common::crypto::Sha256Hash::from_hex(
            &fixture.expected_image_hash_hex,
        )
        .map_err(|err| anyhow!(err))?,
        measurements: lsdc_common::crypto::AttestationMeasurements {
            image_hash: lsdc_common::crypto::Sha256Hash::from_hex(
                &fixture.measurements.image_hash_hex,
            )
            .map_err(|err| anyhow!(err))?,
            pcrs: fixture.measurements.pcrs,
            debug: fixture.measurements.debug,
        },
        raw_attestation_document: fixture.raw_attestation_document_utf8.into_bytes(),
        certificate_chain_pem: fixture.certificate_chain_pem,
        timestamp: chrono::DateTime::parse_from_rfc3339(&fixture.timestamp)?
            .with_timezone(&chrono::Utc),
    })
}
