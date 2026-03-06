use clap::Parser;
use lsdc_common::execution::TransportBackend;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct LiquidAgentArgs {
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidAgentConfig {
    pub listen_addr: String,
    pub mode: LiquidAgentMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiquidAgentMode {
    Simulated,
    Kernel,
}

impl LiquidAgentConfig {
    pub fn from_path(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn effective_transport_backend(&self) -> TransportBackend {
        match self.mode {
            LiquidAgentMode::Simulated => TransportBackend::Simulated,
            LiquidAgentMode::Kernel => {
                #[cfg(target_os = "linux")]
                {
                    TransportBackend::AyaXdp
                }

                #[cfg(not(target_os = "linux"))]
                {
                    TransportBackend::Simulated
                }
            }
        }
    }
}
