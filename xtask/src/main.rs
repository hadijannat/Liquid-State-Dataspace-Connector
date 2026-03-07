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
    /// Verify repo structure, shared contracts, and doc consistency invariants
    VerifyRepo,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::VerifyRepo => verify_repo(),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    let ebpf_dir = workspace_root
        .join("crates")
        .join("liquid-data-plane")
        .join("ebpf");

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

    let status = cmd.status().context("failed to run cargo build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    println!("eBPF program built successfully.");
    Ok(())
}

fn verify_repo() -> Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();

    require_exists(
        &workspace_root.join("proto/pricing/v1/pricing.proto"),
        "shared pricing proto",
    )?;
    require_exists(
        &workspace_root.join("crates/liquid-agent-grpc/proto/liquid_agent.proto"),
        "shared liquid-agent proto",
    )?;
    require_not_exists(
        &workspace_root.join("apps/liquid-agent/proto/liquid_agent.proto"),
        "app-local liquid-agent proto",
    )?;
    require_not_exists(
        &workspace_root.join("python/pricing-oracle/src/proto/pricing.proto"),
        "python-local pricing proto",
    )?;

    let workspace_toml = std::fs::read_to_string(workspace_root.join("Cargo.toml"))?;
    require_contains(&workspace_toml, "crates/lsdc-ports", "workspace membership")?;
    require_contains(
        &workspace_toml,
        "crates/lsdc-service-types",
        "workspace membership",
    )?;
    require_contains(
        &workspace_toml,
        "crates/liquid-agent-grpc",
        "workspace membership",
    )?;

    let control_plane_api_toml =
        std::fs::read_to_string(workspace_root.join("apps/control-plane-api/Cargo.toml"))?;
    require_contains(
        &control_plane_api_toml,
        "liquid-agent-grpc",
        "control-plane-api dependency boundary",
    )?;
    require_not_contains(
        &control_plane_api_toml,
        "../liquid-agent",
        "control-plane-api must not depend on the liquid-agent app package",
    )?;

    let control_plane_toml =
        std::fs::read_to_string(workspace_root.join("crates/control-plane/Cargo.toml"))?;
    let (control_plane_dependencies, control_plane_dev_dependencies) =
        split_dependency_sections(&control_plane_toml);
    require_not_contains(
        control_plane_dependencies,
        "liquid-data-plane",
        "control-plane runtime dependencies",
    )?;
    require_contains(
        control_plane_dev_dependencies,
        "liquid-data-plane",
        "control-plane dev-dependencies",
    )?;

    let host_ci = std::fs::read_to_string(workspace_root.join(".github/workflows/host-ci.yml"))?;
    require_contains(
        &host_ci,
        "cargo fmt --all --check",
        "host CI formatting step",
    )?;
    require_contains(
        &host_ci,
        "cargo clippy --workspace --all-targets --exclude liquid-data-plane-ebpf -- -D warnings",
        "host CI clippy step",
    )?;
    require_contains(
        &host_ci,
        "cargo xtask verify-repo",
        "host CI repo verification step",
    )?;

    let readme = std::fs::read_to_string(workspace_root.join("README.md"))?;
    require_contains(&readme, "crates/liquid-agent-grpc", "README workspace map")?;
    require_contains(&readme, "crates/lsdc-ports", "README workspace map")?;
    require_contains(&readme, "crates/lsdc-service-types", "README workspace map")?;
    require_contains(
        &readme,
        "not a root workspace member",
        "README risc0 guest note",
    )?;

    println!("Repo verification passed.");
    Ok(())
}

fn require_exists(path: &std::path::Path, label: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    bail!("{label} missing at {}", path.display())
}

fn require_not_exists(path: &std::path::Path, label: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    bail!("{label} should not exist at {}", path.display())
}

fn require_contains(haystack: &str, needle: &str, label: &str) -> Result<()> {
    if haystack.contains(needle) {
        return Ok(());
    }

    bail!("{label} missing `{needle}`")
}

fn require_not_contains(haystack: &str, needle: &str, label: &str) -> Result<()> {
    if !haystack.contains(needle) {
        return Ok(());
    }

    bail!("{label} unexpectedly contains `{needle}`")
}

fn split_dependency_sections(cargo_toml: &str) -> (&str, &str) {
    let runtime_start = cargo_toml.find("[dependencies]").unwrap_or(0);
    let dev_start = cargo_toml
        .find("[dev-dependencies]")
        .unwrap_or(cargo_toml.len());

    (
        &cargo_toml[runtime_start..dev_start],
        &cargo_toml[dev_start..cargo_toml.len()],
    )
}
