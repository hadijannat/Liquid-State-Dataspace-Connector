use crate::state::{ApiState, ApiStateInit, BackendSummary};
use anyhow::{anyhow, Result as AnyhowResult};
use axum::http::Uri;
use base64::Engine;
use control_plane::pricing::GrpcPricingOracle;
use control_plane_store::Store;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use lsdc_common::execution::ProofBackend;
use lsdc_config::{ControlPlaneApiConfig, KeyBrokerBackend};
use lsdc_ports::{AttestationVerifier, EnclaveManager, KeyBroker, PricingOracle, ProofEngine};
use proof_plane_host::DevReceiptProofEngine;
#[cfg(feature = "risc0")]
use proof_plane_host::Risc0ProofEngine;
use std::sync::Arc;
use tee_orchestrator::attestation::{
    build_aws_nitro_attestation_document_from_bundle, AwsNitroAttestationVerifier,
    LocalAttestationVerifier,
};
use tee_orchestrator::enclave::{NitroEnclaveManager, NitroLiveAttestationMaterial};
use tee_orchestrator::key_release::{AwsKmsKeyBroker, AwsSdkKmsDataKeyClient};

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
    let attestation_verifier = build_attestation_verifier(config)?;
    let enclave_manager = build_enclave_manager(
        config.tee_backend,
        proof_engine.clone(),
        attestation_verifier.clone(),
        config,
    )
    .await?;
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
        attestation_verifier,
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

fn build_attestation_verifier(
    config: &ControlPlaneApiConfig,
) -> AnyhowResult<Arc<dyn AttestationVerifier>> {
    match config.tee_backend {
        lsdc_common::execution::TeeBackend::NitroDev => {
            Ok(Arc::new(LocalAttestationVerifier::new()))
        }
        lsdc_common::execution::TeeBackend::NitroLive => {
            Ok(Arc::new(AwsNitroAttestationVerifier::new(
                load_live_attestation_fixture_mode(config)?
                    .as_ref()
                    .map(|fixture| fixture.expected_image_hash_hex.clone()),
                config.nitro_trust_bundle_path.as_deref(),
            )?))
        }
        lsdc_common::execution::TeeBackend::None => {
            Err(anyhow!("tee backend `none` is not valid for Phase 3"))
        }
    }
}

async fn build_enclave_manager(
    tee_backend: lsdc_common::execution::TeeBackend,
    proof_engine: Arc<dyn ProofEngine>,
    attestation_verifier: Arc<dyn AttestationVerifier>,
    config: &ControlPlaneApiConfig,
) -> AnyhowResult<Arc<dyn EnclaveManager>> {
    match tee_backend {
        lsdc_common::execution::TeeBackend::NitroDev => Ok(Arc::new(NitroEnclaveManager::new_dev(
            proof_engine,
            attestation_verifier,
        )?)),
        lsdc_common::execution::TeeBackend::NitroLive => {
            let key_broker = build_key_broker(config).await?;
            Ok(Arc::new(NitroEnclaveManager::new_live(
                proof_engine,
                attestation_verifier,
                load_live_attestation_fixture_mode(config)?
                    .as_ref()
                    .map(|fixture| {
                        load_live_attestation_material(
                            fixture,
                            config.nitro_trust_bundle_path.as_deref(),
                        )
                    })
                    .transpose()?,
                key_broker,
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

#[derive(serde::Deserialize)]
struct NitroLiveAttestationFixture {
    expected_image_hash_hex: String,
    raw_attestation_document_base64: Option<String>,
    raw_attestation_document_utf8: Option<String>,
}

fn load_live_attestation_fixture(path: &str) -> AnyhowResult<NitroLiveAttestationFixture> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn load_live_attestation_fixture_mode(
    config: &ControlPlaneApiConfig,
) -> AnyhowResult<Option<NitroLiveAttestationFixture>> {
    match config.nitro_live_attestation_path.as_deref() {
        Some(_path) if !allow_dev_defaults() => Err(anyhow!(
            "nitro_live_attestation_path is fixture/demo-only and requires {ALLOW_DEV_DEFAULTS_ENV}=1"
        )),
        Some(path) => load_live_attestation_fixture(path).map(Some),
        None => Ok(None),
    }
}

fn load_live_attestation_material(
    fixture: &NitroLiveAttestationFixture,
    trust_bundle_path: Option<&str>,
) -> AnyhowResult<NitroLiveAttestationMaterial> {
    let raw_attestation_document = match (
        fixture.raw_attestation_document_base64.clone(),
        fixture.raw_attestation_document_utf8.clone(),
    ) {
        (Some(base64), _) => base64::engine::general_purpose::STANDARD.decode(base64)?,
        (None, Some(raw_utf8)) => raw_utf8.into_bytes(),
        (None, None) => {
            return Err(anyhow!(
                "nitro live attestation fixture must include raw_attestation_document_base64 or raw_attestation_document_utf8"
            ))
        }
    };
    Ok(NitroLiveAttestationMaterial {
        document: build_aws_nitro_attestation_document_from_bundle(
            Some(&fixture.expected_image_hash_hex),
            &raw_attestation_document,
            trust_bundle_path,
        )?,
    })
}

async fn build_key_broker(config: &ControlPlaneApiConfig) -> AnyhowResult<Arc<dyn KeyBroker>> {
    if config.tee_backend != lsdc_common::execution::TeeBackend::NitroLive {
        return Err(anyhow!(
            "aws kms key broker is only valid when tee_backend = nitro_live"
        ));
    }
    if config.key_broker_backend != KeyBrokerBackend::AwsKms {
        return Err(anyhow!(
            "nitro_live requires `key_broker_backend = aws_kms`"
        ));
    }
    let aws_region = config
        .aws_region
        .as_ref()
        .ok_or_else(|| anyhow!("nitro_live requires `aws_region`"))?;
    let kms_key_id = config
        .kms_key_id
        .as_ref()
        .ok_or_else(|| anyhow!("nitro_live requires `kms_key_id`"))?;
    let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_kms::config::Region::new(aws_region.clone()))
        .load()
        .await;
    let client = aws_sdk_kms::Client::new(&shared_config);

    Ok(Arc::new(AwsKmsKeyBroker::new(
        kms_key_id.clone(),
        Arc::new(AwsSdkKmsDataKeyClient::new(client)),
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        build_attestation_verifier, build_key_broker, validate_pricing_endpoint_with_policy,
    };
    use lsdc_common::execution::{ProofBackend, TeeBackend, TransportBackend};
    use lsdc_config::{ControlPlaneApiConfig, KeyBrokerBackend};

    fn sample_nitro_live_config() -> ControlPlaneApiConfig {
        ControlPlaneApiConfig {
            node_name: "nitro-live-node".into(),
            listen_addr: "127.0.0.1:0".into(),
            database_path: ":memory:".into(),
            liquid_agent_endpoint: "http://127.0.0.1:50051".into(),
            transport_backend: TransportBackend::Simulated,
            proof_backend: ProofBackend::DevReceipt,
            tee_backend: TeeBackend::NitroLive,
            pricing_endpoint: "http://127.0.0.1:50052".into(),
            default_interface: "lo".into(),
            key_broker_backend: KeyBrokerBackend::AwsKms,
            aws_region: Some("eu-central-1".into()),
            kms_key_id: Some("arn:aws:kms:eu-central-1:123:key/test".into()),
            nitro_trust_bundle_path: None,
            nitro_live_attestation_path: None,
        }
    }

    #[test]
    fn test_validate_pricing_endpoint_rejects_insecure_non_loopback_host() {
        let err = validate_pricing_endpoint_with_policy("http://0.0.0.0:50051", true).unwrap_err();
        assert!(err.to_string().contains("must use a loopback host"));
    }

    #[test]
    fn test_build_attestation_verifier_allows_nitro_live_without_fixture_path() {
        let config = sample_nitro_live_config();

        build_attestation_verifier(&config)
            .expect("nitro_live should not require nitro_live_attestation_path at startup");
    }

    #[tokio::test]
    async fn test_build_key_broker_requires_aws_region() {
        let mut config = sample_nitro_live_config();
        config.aws_region = None;

        let err = match build_key_broker(&config).await {
            Ok(_) => panic!("expected missing aws_region to fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("aws_region"));
    }

    #[tokio::test]
    async fn test_build_key_broker_requires_kms_key_id() {
        let mut config = sample_nitro_live_config();
        config.kms_key_id = None;

        let err = match build_key_broker(&config).await {
            Ok(_) => panic!("expected missing kms_key_id to fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("kms_key_id"));
    }
}
