use clap::Parser;
use lsdc_common::execution::{ProofBackend, TeeBackend, TransportBackend};
use serde::{Deserialize, Serialize};
use std::fs;
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
    pub fn from_path(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }
}
