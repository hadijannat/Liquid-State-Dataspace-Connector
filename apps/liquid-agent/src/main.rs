mod config;

use clap::Parser;
use config::{LiquidAgentArgs, LiquidAgentConfig, LiquidAgentMode};
use liquid_agent_grpc::server::{serve, LiquidAgentService};
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_ports::DataPlane;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = LiquidAgentArgs::parse();
    let config = LiquidAgentConfig::from_path(&args.config)?;
    let listener = TcpListener::bind(&config.listen_addr).await?;
    let transport_backend = config.effective_transport_backend();
    tracing::info!(
        listen_addr = %config.listen_addr,
        ?config.mode,
        ?transport_backend,
        "starting liquid agent"
    );

    serve(listener, service_from_config(&config)).await?;
    Ok(())
}

fn service_from_config(config: &LiquidAgentConfig) -> LiquidAgentService {
    let plane: Arc<dyn DataPlane> = match config.mode {
        LiquidAgentMode::Kernel => {
            #[cfg(target_os = "linux")]
            {
                Arc::new(LiquidDataPlane::new())
            }

            #[cfg(not(target_os = "linux"))]
            {
                tracing::warn!(
                    "kernel mode requested on non-Linux host; falling back to simulated enforcement"
                );
                Arc::new(LiquidDataPlane::new_simulated())
            }
        }
        LiquidAgentMode::Simulated => Arc::new(LiquidDataPlane::new_simulated()),
    };

    LiquidAgentService::new(plane, config.effective_transport_backend())
}
