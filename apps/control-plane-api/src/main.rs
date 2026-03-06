use clap::Parser;
use control_plane_api::config::ControlPlaneApiArgs;
use control_plane_api::{serve, state_from_config};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = ControlPlaneApiArgs::parse();
    let config = control_plane_api::config::ControlPlaneApiConfig::from_path(&args.config)?;
    let state = state_from_config(&config)?;
    let listener = TcpListener::bind(&config.listen_addr).await?;

    tracing::info!(
        node = %config.node_name,
        listen_addr = %config.listen_addr,
        transport_backend = ?config.transport_backend,
        proof_backend = ?config.proof_backend,
        tee_backend = ?config.tee_backend,
        "starting control-plane-api"
    );

    serve(listener, state).await?;
    Ok(())
}
