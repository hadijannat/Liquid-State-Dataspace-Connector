use clap::Parser;
use liquid_agent::config::LiquidAgentArgs;
use liquid_agent::server::{serve, LiquidAgentService};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = LiquidAgentArgs::parse();
    let config = liquid_agent::config::LiquidAgentConfig::from_path(&args.config)?;
    let listener = TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(
        listen_addr = %config.listen_addr,
        ?config.mode,
        "starting liquid agent"
    );

    serve(listener, LiquidAgentService::from_config(&config)).await?;
    Ok(())
}
