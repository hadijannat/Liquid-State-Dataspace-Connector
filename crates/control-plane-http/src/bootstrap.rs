use crate::state::{ApiState, ApiStateInit, BackendSummary};
use anyhow::{anyhow, Result as AnyhowResult};
use axum::http::Uri;
use control_plane::pricing::GrpcPricingOracle;
use control_plane_store::Store;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use lsdc_common::execution::ProofBackend;
use lsdc_config::ControlPlaneApiConfig;
use lsdc_ports::{EnclaveManager, PricingOracle, ProofEngine};
use proof_plane_host::DevReceiptProofEngine;
#[cfg(feature = "risc0")]
use proof_plane_host::Risc0ProofEngine;
use std::sync::Arc;
use tee_orchestrator::enclave::{NitroEnclaveManager, NitroLiveAttestationMaterial};

const API_BEARER_TOKEN_ENV: &str = "LSDC_API_BEARER_TOKEN";
const ALLOW_DEV_DEFAULTS_ENV: &str = "LSDC_ALLOW_DEV_DEFAULTS";

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
    let dev_receipt_verifier = build_dev_receipt_verifier(proof_engine.clone())?;
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
    validate_pricing_endpoint(&config.pricing_endpoint)?;
    let pricing_oracle: Arc<dyn PricingOracle> =
        Arc::new(GrpcPricingOracle::new(config.pricing_endpoint.clone()));
    let store = Store::new(&config.database_path)?;
    let api_bearer_token = required_api_bearer_token()?;

    Ok(ApiState::new(ApiStateInit {
        store,
        node_name: config.node_name.clone(),
        liquid_agent,
        proof_engine,
        dev_receipt_verifier,
        enclave_manager,
        pricing_oracle,
        default_interface: config.default_interface.clone(),
        api_bearer_token,
        configured_backends,
        actual_transport_backend,
    }))
}

fn build_proof_engine(
    proof_backend: lsdc_common::execution::ProofBackend,
) -> AnyhowResult<Arc<dyn ProofEngine>> {
    match proof_backend {
        lsdc_common::execution::ProofBackend::DevReceipt => {
            Ok(Arc::new(DevReceiptProofEngine::new()?))
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

fn build_dev_receipt_verifier(
    proof_engine: Arc<dyn ProofEngine>,
) -> AnyhowResult<Arc<dyn ProofEngine>> {
    if proof_engine.proof_backend() == ProofBackend::DevReceipt {
        return Ok(proof_engine);
    }

    Ok(Arc::new(DevReceiptProofEngine::new()?))
}

fn build_enclave_manager(
    tee_backend: lsdc_common::execution::TeeBackend,
    proof_engine: Arc<dyn ProofEngine>,
    config: &ControlPlaneApiConfig,
) -> AnyhowResult<Arc<dyn EnclaveManager>> {
    match tee_backend {
        lsdc_common::execution::TeeBackend::NitroDev => {
            Ok(Arc::new(NitroEnclaveManager::new_dev(proof_engine)?))
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

fn required_api_bearer_token() -> AnyhowResult<String> {
    let token = std::env::var(API_BEARER_TOKEN_ENV)
        .map_err(|_| anyhow!("{API_BEARER_TOKEN_ENV} must be set"))?;
    if token.trim().is_empty() {
        return Err(anyhow!("{API_BEARER_TOKEN_ENV} must not be empty"));
    }
    Ok(token)
}

fn allow_dev_defaults() -> bool {
    matches!(std::env::var(ALLOW_DEV_DEFAULTS_ENV).as_deref(), Ok("1"))
}

fn validate_pricing_endpoint(endpoint: &str) -> AnyhowResult<()> {
    validate_pricing_endpoint_with_policy(endpoint, allow_dev_defaults())
}

fn validate_pricing_endpoint_with_policy(
    endpoint: &str,
    allow_dev_defaults: bool,
) -> AnyhowResult<()> {
    let uri: Uri = endpoint
        .parse()
        .map_err(|err| anyhow!("invalid pricing endpoint `{endpoint}`: {err}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow!("pricing endpoint `{endpoint}` must include a scheme"))?;

    match scheme {
        "https" => Ok(()),
        "http" => {
            let host = uri.host().ok_or_else(|| {
                anyhow!("pricing endpoint `{endpoint}` must include a loopback host")
            })?;
            if !allow_dev_defaults {
                return Err(anyhow!(
                    "insecure pricing endpoint `{endpoint}` requires {ALLOW_DEV_DEFAULTS_ENV}=1"
                ));
            }
            if !is_loopback_host(host) {
                return Err(anyhow!(
                    "insecure pricing endpoint `{endpoint}` must use a loopback host"
                ));
            }
            Ok(())
        }
        other => Err(anyhow!(
            "pricing endpoint `{endpoint}` must use http or https, found `{other}`"
        )),
    }
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
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

#[cfg(test)]
mod tests {
    use super::validate_pricing_endpoint_with_policy;

    #[test]
    fn test_validate_pricing_endpoint_rejects_insecure_non_loopback_host() {
        let err = validate_pricing_endpoint_with_policy("http://0.0.0.0:50051", true).unwrap_err();
        assert!(err.to_string().contains("must use a loopback host"));
    }
}
