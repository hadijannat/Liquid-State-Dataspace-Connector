use clap::Parser;
use lsdc_common::execution::{ProofBackend, TeeBackend, TransportBackend};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct ControlPlaneApiArgs {
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneApiConfig {
    pub node_name: String,
    pub listen_addr: String,
    pub database_path: String,
    pub liquid_agent_endpoint: String,
    pub transport_backend: TransportBackend,
    pub proof_backend: ProofBackend,
    pub tee_backend: TeeBackend,
    pub pricing_endpoint: String,
    pub default_interface: String,
    pub nitro_live_attestation_path: Option<String>,
}

impl ControlPlaneApiConfig {
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        read_toml(path)
    }
}

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
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        read_toml(path)
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

fn read_toml<T>(path: &Path) -> Result<T, Box<dyn std::error::Error>>
where
    T: DeserializeOwned,
{
    let raw = fs::read_to_string(path)?;
    Ok(toml::from_str(&raw)?)
}
