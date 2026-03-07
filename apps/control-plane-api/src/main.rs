use clap::Parser;
use control_plane_api::{serve, state_from_config};
use lsdc_config::{ControlPlaneApiArgs, ControlPlaneApiConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = ControlPlaneApiArgs::parse();
    let config = ControlPlaneApiConfig::from_path(&args.config)?;
    let state = state_from_config(&config).await?;
    let listener = TcpListener::bind(&config.listen_addr).await?;
    let actual = state.actual_backends_summary();
    let configured = state.configured_backends_summary();

    tracing::info!(
        node = %config.node_name,
        listen_addr = %config.listen_addr,
        configured_transport_backend = ?configured.transport_backend,
        configured_proof_backend = ?configured.proof_backend,
        configured_tee_backend = ?configured.tee_backend,
        actual_transport_backend = ?actual.transport_backend,
        actual_proof_backend = ?actual.proof_backend,
        actual_tee_backend = ?actual.tee_backend,
        "starting control-plane-api"
    );

    serve(listener, state).await?;
    Ok(())
}
