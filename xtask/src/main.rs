use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF XDP program
    BuildEbpf {
        /// Build in release mode
        #[clap(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    let ebpf_dir = workspace_root
        .join("crates")
        .join("liquid-data-plane")
        .join("liquid-data-plane-ebpf");

    if !ebpf_dir.exists() {
        bail!("eBPF crate not found at {}", ebpf_dir.display());
    }

    // On non-Linux, we cannot compile to BPF target.
    if cfg!(not(target_os = "linux")) {
        println!("Skipping eBPF build on non-Linux platform.");
        println!("User-space crate will use mock enforcement.");
        return Ok(());
    }

    let target = "bpfel-unknown-none";
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("build")
        .arg("--target")
        .arg(target)
        .arg("-Z")
        .arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to run cargo build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    println!("eBPF program built successfully.");
    Ok(())
}
