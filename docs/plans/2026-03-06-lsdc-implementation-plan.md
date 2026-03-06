# LSDC Monorepo Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bootstrap the Liquid-State Dataspace Connector Cargo workspace with all four pillar crates, shared types, and a working Pillar 1 (ODRL policy compiler + eBPF data plane with platform-gated kernel code).

**Architecture:** Cargo workspace with nested host/guest splits for eBPF and ZK pillars. Shared `lsdc-common` crate defines ODRL types, DID types, and async pillar traits. Pillar 1 compiles ODRL constraints into eBPF map parameters and attaches a parameterized XDP program to the NIC. Pillars 2-4 are trait-complete stubs.

**Tech Stack:** Rust nightly (aya-rs 0.1.1 for eBPF, risc0-zkvm 3.0.5 stubs), Python 3.12 (pricing oracle sidecar), serde/serde_json, chrono, tokio, thiserror.

**Reference:** See `docs/plans/2026-03-06-lsdc-architecture-design.md` for full architecture rationale.

---

## Task 1: Workspace Root & Toolchain Configuration

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `rust-toolchain.toml`
- Create: `.cargo/config.toml`
- Create: `.gitignore`

**Step 1: Create workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "xtask",
    "crates/lsdc-common",
    "crates/control-plane",
    "crates/liquid-data-plane/liquid-data-plane",
    "crates/proof-plane/proof-plane-host",
    "crates/tee-orchestrator",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/your-org/lsdc-core"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
thiserror = "2"
anyhow = "1"
async-trait = "0.1"
tracing = "0.1"
tracing-subscriber = "0.3"
uuid = { version = "1", features = ["v4", "serde"] }
```

Note: The eBPF crate (`liquid-data-plane-ebpf`) and ZK guest crate (`proof-plane-guest`) are intentionally excluded from the workspace. They target different architectures (BPF, RISC-V) and are built separately via `xtask`.

**Step 2: Create rust-toolchain.toml**

```toml
[toolchain]
channel = "nightly"
components = ["rustfmt", "clippy", "rust-src"]
```

Nightly is required for aya-rs eBPF compilation (the `#![no_std]` BPF target needs nightly features).

**Step 3: Create .cargo/config.toml**

```toml
[alias]
xtask = "run --package xtask --"
```

**Step 4: Create .gitignore**

```
/target
**/*.rs.bk
*.swp
*.swo
.DS_Store
__pycache__/
*.pyc
.venv/
python/pricing-oracle/.venv/
```

**Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .cargo/config.toml .gitignore
git commit -m "feat: initialize Cargo workspace with toolchain config"
```

---

## Task 2: xtask Build Orchestration

**Files:**
- Create: `xtask/Cargo.toml`
- Create: `xtask/src/main.rs`

**Step 1: Create xtask/Cargo.toml**

```toml
[package]
name = "xtask"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
```

**Step 2: Write xtask/src/main.rs**

The xtask builds the eBPF crate to BPF bytecode so the user-space crate can embed it. On non-Linux (macOS), it skips the eBPF build and creates a placeholder.

```rust
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
    // Create a placeholder so the user-space crate can still compile.
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
```

**Step 3: Verify xtask compiles**

Run: `cargo build --package xtask`
Expected: Successful compilation.

**Step 4: Commit**

```bash
git add xtask/
git commit -m "feat: add xtask build orchestration for eBPF compilation"
```

---

## Task 3: lsdc-common — Shared Types & ODRL AST

**Files:**
- Create: `crates/lsdc-common/Cargo.toml`
- Create: `crates/lsdc-common/src/lib.rs`
- Create: `crates/lsdc-common/src/odrl/mod.rs`
- Create: `crates/lsdc-common/src/odrl/ast.rs`
- Create: `crates/lsdc-common/src/odrl/parser.rs`
- Create: `crates/lsdc-common/src/identity/mod.rs`
- Create: `crates/lsdc-common/src/dsp/mod.rs`
- Create: `crates/lsdc-common/src/crypto/mod.rs`
- Create: `crates/lsdc-common/src/traits.rs`
- Create: `crates/lsdc-common/src/error.rs`
- Test: `crates/lsdc-common/tests/odrl_parser_tests.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "lsdc-common"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
chrono = { workspace = true }
thiserror = { workspace = true }
async-trait = { workspace = true }
uuid = { workspace = true }
```

**Step 2: Write error.rs — unified error types**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LsdcError {
    #[error("ODRL parsing error: {0}")]
    OdrlParse(String),

    #[error("Policy compilation error: {0}")]
    PolicyCompile(String),

    #[error("Enforcement error: {0}")]
    Enforcement(String),

    #[error("Proof generation error: {0}")]
    ProofGeneration(String),

    #[error("Attestation error: {0}")]
    Attestation(String),

    #[error("Pricing error: {0}")]
    Pricing(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, LsdcError>;
```

**Step 3: Write odrl/ast.rs — the ODRL Abstract Syntax Tree**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a policy agreement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub String);

impl PolicyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// A negotiated ODRL policy agreement between provider and consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAgreement {
    pub id: PolicyId,
    pub provider: String,
    pub consumer: String,
    pub target: String,
    pub permissions: Vec<Permission>,
    pub prohibitions: Vec<Prohibition>,
    pub obligations: Vec<Duty>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub action: Action,
    pub constraints: Vec<Constraint>,
    pub duties: Vec<Duty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prohibition {
    pub action: Action,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duty {
    pub action: Action,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    Use,
    Transfer,
    Stream,
    Read,
    Aggregate,
    Anonymize,
    Delete,
    Custom(String),
}

/// Enforceable constraints extracted from ODRL policies.
/// Each variant maps to a specific eBPF enforcement mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    /// Maximum number of accesses/packets allowed.
    Count { max: u64 },
    /// Restrict data flow to specific geographic regions.
    Spatial { allowed_regions: Vec<GeoRegion> },
    /// Data access expires after this timestamp.
    Temporal { not_after: DateTime<Utc> },
    /// Restrict usage to specific purposes.
    Purpose { allowed: Vec<String> },
    /// Maximum requests/packets per second.
    RateLimit { max_per_second: u64 },
    /// Extensible constraint for domain-specific rules.
    Custom { key: String, value: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GeoRegion {
    EU,
    US,
    APAC,
    Custom(String),
}
```

**Step 4: Write odrl/parser.rs — JSON to AST**

```rust
use super::ast::PolicyAgreement;
use crate::error::{LsdcError, Result};

/// Parse a JSON string representing an ODRL policy agreement into the AST.
///
/// This is a simplified parser that expects our internal JSON format.
/// A full implementation would parse JSON-LD using an RDF library (oxrdf).
pub fn parse_policy_json(json: &str) -> Result<PolicyAgreement> {
    serde_json::from_str(json).map_err(|e| LsdcError::OdrlParse(e.to_string()))
}
```

**Step 5: Write odrl/mod.rs**

```rust
pub mod ast;
pub mod parser;
```

**Step 6: Write identity/mod.rs — DID types**

```rust
use serde::{Deserialize, Serialize};

/// W3C Decentralized Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl Did {
    pub fn new(method: &str, id: &str) -> Self {
        Self(format!("did:{method}:{id}"))
    }
}

/// A DID Document contains verification methods and service endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: Did,
    pub verification_methods: Vec<VerificationMethod>,
    pub service_endpoints: Vec<ServiceEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub endpoint_type: String,
    pub url: String,
}
```

**Step 7: Write dsp/mod.rs — Dataspace Protocol message types**

```rust
use crate::odrl::ast::{PolicyAgreement, PolicyId};
use serde::{Deserialize, Serialize};

/// Messages per the Eclipse Dataspace Protocol specification.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DspMessage {
    CatalogRequest(CatalogRequest),
    ContractRequest(ContractRequest),
    ContractOffer(ContractOffer),
    ContractAgreement(ContractAgreement),
    TransferRequest(TransferRequest),
    TransferStart(TransferStart),
    TransferCompletion(TransferCompletion),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogRequest {
    pub consumer_id: String,
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRequest {
    pub consumer_id: String,
    pub offer_id: String,
    pub policy: PolicyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractOffer {
    pub provider_id: String,
    pub offer_id: String,
    pub policy: PolicyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAgreement {
    pub agreement_id: PolicyId,
    pub policy: PolicyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub agreement_id: PolicyId,
    pub data_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStart {
    pub transfer_id: String,
    pub agreement_id: PolicyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCompletion {
    pub transfer_id: String,
}
```

**Step 8: Write crypto/mod.rs — shared crypto primitives**

```rust
use serde::{Deserialize, Serialize};

/// A SHA-256 hash digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Hash(pub [u8; 32]);

/// Provenance receipt from the Proof Plane (Pillar 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceReceipt {
    pub input_hash: Sha256Hash,
    pub output_hash: Sha256Hash,
    pub policy_hash: Sha256Hash,
    pub proof_bytes: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Attestation document from a Trusted Execution Environment (Pillar 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub enclave_id: String,
    pub binary_hash: Sha256Hash,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub attestation_bytes: Vec<u8>,
}

/// Proof that data was securely destroyed inside a TEE (Pillar 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfForgetting {
    pub attestation: AttestationDocument,
    pub destruction_timestamp: chrono::DateTime<chrono::Utc>,
    pub data_hash: Sha256Hash,
}

/// Shapley value result from the Pricing Oracle (Pillar 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapleyValue {
    pub dataset_id: String,
    pub marginal_contribution: f64,
    pub confidence: f64,
}

/// Price adjustment after Shapley evaluation (Pillar 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceAdjustment {
    pub agreement_id: String,
    pub original_price: f64,
    pub adjusted_price: f64,
    pub shapley_value: ShapleyValue,
}
```

**Step 9: Write traits.rs — pillar trait boundaries**

```rust
use crate::crypto::{
    AttestationDocument, PriceAdjustment, ProofOfForgetting, ProvenanceReceipt, ShapleyValue,
};
use crate::error::Result;
use crate::odrl::ast::PolicyAgreement;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ── Pillar 1: Data Plane ──────────────────────────────────────────

/// Handle returned when a policy is enforced. Used to revoke or query status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementHandle {
    pub id: String,
    pub interface: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementStatus {
    Active { packets_processed: u64 },
    Expired,
    Revoked,
    Error(String),
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    async fn enforce(&self, policy: &PolicyAgreement, iface: &str) -> Result<EnforcementHandle>;
    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()>;
    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus>;
}

// ── Pillar 2: Proof Engine ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformSpec {
    pub name: String,
    pub description: String,
}

#[async_trait]
pub trait ProofEngine: Send + Sync {
    async fn prove_transform(
        &self,
        input_hash: &[u8; 32],
        policy: &PolicyAgreement,
        transform: &TransformSpec,
    ) -> Result<ProvenanceReceipt>;

    async fn verify_receipt(&self, receipt: &ProvenanceReceipt) -> Result<bool>;

    async fn verify_chain(&self, chain: &[ProvenanceReceipt]) -> Result<bool>;
}

// ── Pillar 3: Enclave Manager ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EnclaveSession {
    pub id: String,
    pub binary_hash: [u8; 32],
}

#[async_trait]
pub trait EnclaveManager: Send + Sync {
    async fn create_enclave(&self, binary_hash: &[u8; 32]) -> Result<EnclaveSession>;
    async fn attest(&self, session: &EnclaveSession) -> Result<AttestationDocument>;
    async fn destroy_and_prove(&self, session: EnclaveSession) -> Result<ProofOfForgetting>;
}

// ── Pillar 4: Pricing Oracle ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetrics {
    pub loss_with_dataset: f64,
    pub loss_without_dataset: f64,
    pub accuracy_with_dataset: f64,
    pub accuracy_without_dataset: f64,
}

#[async_trait]
pub trait PricingOracle: Send + Sync {
    async fn evaluate_utility(
        &self,
        dataset_id: &str,
        metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue>;

    async fn renegotiate(
        &self,
        agreement_id: &str,
        value: &ShapleyValue,
    ) -> Result<PriceAdjustment>;
}
```

**Step 10: Write lib.rs — re-export everything**

```rust
pub mod crypto;
pub mod dsp;
pub mod error;
pub mod identity;
pub mod odrl;
pub mod traits;

pub use error::{LsdcError, Result};
```

**Step 11: Write test — ODRL parser test**

Create `crates/lsdc-common/tests/odrl_parser_tests.rs`:

```rust
use chrono::Utc;
use lsdc_common::odrl::ast::*;
use lsdc_common::odrl::parser::parse_policy_json;

#[test]
fn test_parse_simple_policy() {
    let policy = PolicyAgreement {
        id: PolicyId("test-policy-1".into()),
        provider: "did:web:provider.example".into(),
        consumer: "did:web:consumer.example".into(),
        target: "urn:dataset:sensor-data-2026".into(),
        permissions: vec![Permission {
            action: Action::Stream,
            constraints: vec![
                Constraint::RateLimit { max_per_second: 1000 },
                Constraint::Spatial {
                    allowed_regions: vec![GeoRegion::EU],
                },
                Constraint::Temporal {
                    not_after: Utc::now() + chrono::Duration::days(30),
                },
            ],
            duties: vec![],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + chrono::Duration::days(30)),
    };

    let json = serde_json::to_string(&policy).unwrap();
    let parsed = parse_policy_json(&json).unwrap();

    assert_eq!(parsed.id, policy.id);
    assert_eq!(parsed.permissions.len(), 1);
    assert_eq!(parsed.permissions[0].constraints.len(), 3);
}

#[test]
fn test_parse_invalid_json_returns_error() {
    let result = parse_policy_json("not valid json");
    assert!(result.is_err());
}

#[test]
fn test_parse_empty_policy() {
    let policy = PolicyAgreement {
        id: PolicyId("empty-policy".into()),
        provider: "did:web:a".into(),
        consumer: "did:web:b".into(),
        target: "urn:data:empty".into(),
        permissions: vec![],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: None,
    };

    let json = serde_json::to_string(&policy).unwrap();
    let parsed = parse_policy_json(&json).unwrap();
    assert!(parsed.permissions.is_empty());
    assert!(parsed.valid_until.is_none());
}
```

**Step 12: Run tests**

Run: `cargo test --package lsdc-common`
Expected: 3 tests pass.

**Step 13: Commit**

```bash
git add crates/lsdc-common/
git commit -m "feat: add lsdc-common crate with ODRL types, traits, and parser"
```

---

## Task 4: Liquid Data Plane — User-Space (Pillar 1)

**Files:**
- Create: `crates/liquid-data-plane/liquid-data-plane/Cargo.toml`
- Create: `crates/liquid-data-plane/liquid-data-plane/src/lib.rs`
- Create: `crates/liquid-data-plane/liquid-data-plane/src/compiler.rs`
- Create: `crates/liquid-data-plane/liquid-data-plane/src/loader.rs`
- Create: `crates/liquid-data-plane/liquid-data-plane/src/maps.rs`
- Test: `crates/liquid-data-plane/liquid-data-plane/tests/compiler_tests.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "liquid-data-plane"
version.workspace = true
edition.workspace = true

[dependencies]
lsdc-common = { path = "../../lsdc-common" }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
chrono = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
uuid = { workspace = true }

# eBPF user-space loader — Linux only
[target.'cfg(target_os = "linux")'.dependencies]
aya = "0.13"
aya-log = "0.2"
```

**Step 2: Write maps.rs — eBPF map entry types**

```rust
use serde::{Deserialize, Serialize};

/// Represents a single entry to be inserted into an eBPF map.
/// These are the "compiled" form of ODRL constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MapEntry {
    /// Insert into RATE_LIMIT_MAP: contract_id → max_packets
    RateLimit {
        contract_id: u32,
        max_packets: u64,
    },
    /// Insert into RATE_PER_SEC_MAP: contract_id → max_per_second
    RatePerSecond {
        contract_id: u32,
        max_per_second: u64,
    },
    /// Insert into GEO_FENCE_MAP: ip_prefix → allowed (1) or blocked (0)
    GeoFence {
        /// Encoded as u32 CIDR blocks for allowed source IPs
        allowed_cidrs: Vec<u32>,
    },
    /// Insert into EXPIRY_MAP: contract_id → unix_timestamp
    Expiry {
        contract_id: u32,
        expiry_ts: i64,
    },
}

/// The full set of compiled map entries for a single policy agreement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledPolicy {
    pub contract_id: u32,
    pub entries: Vec<MapEntry>,
}
```

**Step 3: Write compiler.rs — ODRL AST to eBPF map entries**

```rust
use crate::maps::{CompiledPolicy, MapEntry};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::odrl::ast::{Constraint, PolicyAgreement};
use std::hash::{DefaultHasher, Hash, Hasher};

/// Compile an ODRL PolicyAgreement into eBPF map entries.
///
/// This translates high-level semantic constraints into concrete
/// key-value pairs that the XDP program reads at packet-processing time.
pub fn compile_policy(policy: &PolicyAgreement) -> Result<CompiledPolicy> {
    let contract_id = policy_to_contract_id(policy);
    let mut entries = Vec::new();

    for permission in &policy.permissions {
        for constraint in &permission.constraints {
            let entry = compile_constraint(contract_id, constraint)?;
            entries.push(entry);
        }
    }

    // If the policy has a valid_until, add an expiry entry
    if let Some(until) = &policy.valid_until {
        entries.push(MapEntry::Expiry {
            contract_id,
            expiry_ts: until.timestamp(),
        });
    }

    if entries.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "Policy produced no enforceable constraints".into(),
        ));
    }

    Ok(CompiledPolicy {
        contract_id,
        entries,
    })
}

fn compile_constraint(contract_id: u32, constraint: &Constraint) -> Result<MapEntry> {
    match constraint {
        Constraint::Count { max } => Ok(MapEntry::RateLimit {
            contract_id,
            max_packets: *max,
        }),
        Constraint::RateLimit { max_per_second } => Ok(MapEntry::RatePerSecond {
            contract_id,
            max_per_second: *max_per_second,
        }),
        Constraint::Temporal { not_after } => Ok(MapEntry::Expiry {
            contract_id,
            expiry_ts: not_after.timestamp(),
        }),
        Constraint::Spatial { allowed_regions } => {
            // In a real implementation, GeoRegion would map to IP CIDR blocks
            // via a GeoIP database. For Sprint 0, we use placeholder CIDRs.
            let cidrs: Vec<u32> = allowed_regions
                .iter()
                .enumerate()
                .map(|(i, _)| i as u32 + 1) // placeholder
                .collect();
            Ok(MapEntry::GeoFence {
                allowed_cidrs: cidrs,
            })
        }
        Constraint::Purpose { .. } => Err(LsdcError::PolicyCompile(
            "Purpose constraints cannot be enforced at packet level".into(),
        )),
        Constraint::Custom { key, .. } => Err(LsdcError::PolicyCompile(format!(
            "Unknown constraint type: {key}"
        ))),
    }
}

/// Derive a stable 32-bit contract ID from the policy's string ID.
fn policy_to_contract_id(policy: &PolicyAgreement) -> u32 {
    let mut hasher = DefaultHasher::new();
    policy.id.0.hash(&mut hasher);
    hasher.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lsdc_common::odrl::ast::*;

    fn make_test_policy(constraints: Vec<Constraint>) -> PolicyAgreement {
        PolicyAgreement {
            id: PolicyId("test-1".into()),
            provider: "did:web:provider".into(),
            consumer: "did:web:consumer".into(),
            target: "urn:data:test".into(),
            permissions: vec![Permission {
                action: Action::Stream,
                constraints,
                duties: vec![],
            }],
            prohibitions: vec![],
            obligations: vec![],
            valid_from: Utc::now(),
            valid_until: None,
        }
    }

    #[test]
    fn test_compile_rate_limit() {
        let policy = make_test_policy(vec![Constraint::Count { max: 500 }]);
        let compiled = compile_policy(&policy).unwrap();

        assert_eq!(compiled.entries.len(), 1);
        match &compiled.entries[0] {
            MapEntry::RateLimit { max_packets, .. } => assert_eq!(*max_packets, 500),
            other => panic!("Expected RateLimit, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_temporal_constraint() {
        let future = Utc::now() + chrono::Duration::hours(1);
        let policy = make_test_policy(vec![Constraint::Temporal { not_after: future }]);
        let compiled = compile_policy(&policy).unwrap();

        assert_eq!(compiled.entries.len(), 1);
        match &compiled.entries[0] {
            MapEntry::Expiry { expiry_ts, .. } => {
                assert_eq!(*expiry_ts, future.timestamp());
            }
            other => panic!("Expected Expiry, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_geo_fence() {
        let policy = make_test_policy(vec![Constraint::Spatial {
            allowed_regions: vec![GeoRegion::EU, GeoRegion::US],
        }]);
        let compiled = compile_policy(&policy).unwrap();

        assert_eq!(compiled.entries.len(), 1);
        match &compiled.entries[0] {
            MapEntry::GeoFence { allowed_cidrs } => assert_eq!(allowed_cidrs.len(), 2),
            other => panic!("Expected GeoFence, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_purpose_constraint_fails() {
        let policy = make_test_policy(vec![Constraint::Purpose {
            allowed: vec!["research".into()],
        }]);
        let result = compile_policy(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_empty_policy_fails() {
        let policy = make_test_policy(vec![]);
        let result = compile_policy(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_multiple_constraints() {
        let policy = make_test_policy(vec![
            Constraint::Count { max: 1000 },
            Constraint::RateLimit { max_per_second: 100 },
        ]);
        let compiled = compile_policy(&policy).unwrap();
        assert_eq!(compiled.entries.len(), 2);
    }
}
```

**Step 4: Write loader.rs — platform-gated XDP lifecycle**

```rust
use crate::compiler::compile_policy;
use crate::maps::CompiledPolicy;
use lsdc_common::error::Result;
use lsdc_common::odrl::ast::PolicyAgreement;
use lsdc_common::traits::{DataPlane, EnforcementHandle, EnforcementStatus};

/// The Liquid Data Plane enforces ODRL policies via eBPF/XDP.
///
/// On Linux, it attaches compiled XDP programs to network interfaces.
/// On other platforms, it runs in simulation mode for development.
pub struct LiquidDataPlane {
    // Tracks active enforcement handles
    active: std::sync::Arc<tokio::sync::Mutex<Vec<EnforcementHandle>>>,
}

impl LiquidDataPlane {
    pub fn new() -> Self {
        Self {
            active: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Compile and return the map entries without attaching.
    /// Useful for testing the compilation pipeline independently.
    pub fn compile(&self, policy: &PolicyAgreement) -> Result<CompiledPolicy> {
        compile_policy(policy)
    }
}

#[async_trait::async_trait]
impl DataPlane for LiquidDataPlane {
    async fn enforce(&self, policy: &PolicyAgreement, iface: &str) -> Result<EnforcementHandle> {
        let compiled = compile_policy(policy)?;
        tracing::info!(
            contract_id = compiled.contract_id,
            entries = compiled.entries.len(),
            interface = iface,
            "Enforcing policy"
        );

        #[cfg(target_os = "linux")]
        {
            self.enforce_linux(&compiled, iface).await?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("Non-Linux platform: running in simulation mode");
            let _ = &compiled; // suppress unused warning
        }

        let handle = EnforcementHandle {
            id: compiled.contract_id.to_string(),
            interface: iface.to_string(),
            active: true,
        };

        self.active.lock().await.push(handle.clone());
        Ok(handle)
    }

    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()> {
        tracing::info!(handle_id = %handle.id, "Revoking enforcement");

        #[cfg(target_os = "linux")]
        {
            self.revoke_linux(handle).await?;
        }

        let mut active = self.active.lock().await;
        active.retain(|h| h.id != handle.id);
        Ok(())
    }

    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus> {
        let active = self.active.lock().await;
        if active.iter().any(|h| h.id == handle.id) {
            Ok(EnforcementStatus::Active {
                packets_processed: 0, // Real impl reads from eBPF map
            })
        } else {
            Ok(EnforcementStatus::Revoked)
        }
    }
}

// Linux-specific eBPF operations
#[cfg(target_os = "linux")]
impl LiquidDataPlane {
    async fn enforce_linux(
        &self,
        _compiled: &CompiledPolicy,
        _iface: &str,
    ) -> Result<()> {
        // TODO: Load eBPF bytecode via aya::Ebpf::load()
        // TODO: Attach XDP program to interface
        // TODO: Populate eBPF maps with compiled entries
        // TODO: Spawn expiry timer task
        todo!("Linux eBPF enforcement — implement in Sprint 0 Week 2")
    }

    async fn revoke_linux(&self, _handle: &EnforcementHandle) -> Result<()> {
        // TODO: Detach XDP program from interface
        // TODO: Clean up eBPF maps
        todo!("Linux eBPF revocation")
    }
}
```

**Step 5: Write lib.rs**

```rust
pub mod compiler;
pub mod loader;
pub mod maps;
```

**Step 6: Write integration test**

Create `crates/liquid-data-plane/liquid-data-plane/tests/compiler_tests.rs`:

```rust
use chrono::Utc;
use lsdc_common::odrl::ast::*;
use liquid_data_plane::compiler::compile_policy;
use liquid_data_plane::maps::MapEntry;

#[test]
fn test_full_pipeline_compile() {
    let policy = PolicyAgreement {
        id: PolicyId("integration-test-1".into()),
        provider: "did:web:acme.example".into(),
        consumer: "did:web:buyer.example".into(),
        target: "urn:dataset:sensor-stream".into(),
        permissions: vec![Permission {
            action: Action::Stream,
            constraints: vec![
                Constraint::RateLimit { max_per_second: 60 },
                Constraint::Spatial {
                    allowed_regions: vec![GeoRegion::EU],
                },
            ],
            duties: vec![Duty {
                action: Action::Delete,
                constraints: vec![Constraint::Temporal {
                    not_after: Utc::now() + chrono::Duration::days(30),
                }],
            }],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + chrono::Duration::days(90)),
    };

    let compiled = compile_policy(&policy).unwrap();

    // Should have: RatePerSecond + GeoFence + Expiry (from valid_until)
    assert_eq!(compiled.entries.len(), 3);

    let has_rate = compiled.entries.iter().any(|e| matches!(e, MapEntry::RatePerSecond { .. }));
    let has_geo = compiled.entries.iter().any(|e| matches!(e, MapEntry::GeoFence { .. }));
    let has_expiry = compiled.entries.iter().any(|e| matches!(e, MapEntry::Expiry { .. }));

    assert!(has_rate, "Missing rate limit entry");
    assert!(has_geo, "Missing geo fence entry");
    assert!(has_expiry, "Missing expiry entry");
}
```

**Step 7: Run tests**

Run: `cargo test --package liquid-data-plane`
Expected: All unit and integration tests pass.

**Step 8: Commit**

```bash
git add crates/liquid-data-plane/liquid-data-plane/
git commit -m "feat: add liquid data plane with ODRL-to-eBPF policy compiler"
```

---

## Task 5: Liquid Data Plane — eBPF Kernel Program

**Files:**
- Create: `crates/liquid-data-plane/liquid-data-plane-ebpf/Cargo.toml`
- Create: `crates/liquid-data-plane/liquid-data-plane-ebpf/src/main.rs`
- Create: `crates/liquid-data-plane/liquid-data-plane-ebpf/.cargo/config.toml`
- Create: `crates/liquid-data-plane/liquid-data-plane-ebpf/rust-toolchain.toml`

Note: This crate is NOT in the workspace `members` list. It targets `bpfel-unknown-none` and must be built separately via `xtask`. It will only compile on Linux with the BPF target installed.

**Step 1: Create Cargo.toml**

```toml
[package]
name = "liquid-data-plane-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"

[[bin]]
name = "lsdc-xdp"
path = "src/main.rs"
```

**Step 2: Create .cargo/config.toml (eBPF-specific)**

```toml
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]
```

**Step 3: Create rust-toolchain.toml (eBPF-specific)**

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
```

**Step 4: Write src/main.rs — parameterized XDP filter**

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

/// Rate limit map: contract_id (u32) → max_packets (u64)
#[map]
static RATE_LIMIT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Packet counter map: contract_id (u32) → current_count (u64)
#[map]
static PACKET_COUNT_MAP: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Expiry map: contract_id (u32) → unix_timestamp (i64)
#[map]
static EXPIRY_MAP: HashMap<u32, i64> = HashMap::with_max_entries(256, 0);

/// Active contracts map: contract_id (u32) → active (u32, 1=yes, 0=no)
#[map]
static ACTIVE_MAP: HashMap<u32, u32> = HashMap::with_max_entries(256, 0);

#[xdp]
pub fn lsdc_xdp(ctx: XdpContext) -> u32 {
    match try_lsdc_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lsdc_xdp(ctx: XdpContext) -> Result<u32, u32> {
    // For Sprint 0, we enforce a simple contract-based rate limit.
    // The user-space loader populates ACTIVE_MAP with the contract ID
    // and RATE_LIMIT_MAP with the max packet count.

    // Check if any contract is active (contract_id = 1 for MVP)
    let contract_id: u32 = 1;

    let active = unsafe { ACTIVE_MAP.get(&contract_id) };
    if active.is_none() || *active.unwrap() == 0 {
        // No active enforcement — pass all traffic
        return Ok(xdp_action::XDP_PASS);
    }

    // Check rate limit
    if let Some(max_packets) = unsafe { RATE_LIMIT_MAP.get(&contract_id) } {
        let count = unsafe { PACKET_COUNT_MAP.get(&contract_id) }
            .copied()
            .unwrap_or(0);

        if count >= *max_packets {
            // Rate limit exceeded — drop packet
            info!(&ctx, "LSDC: rate limit exceeded, dropping packet");
            return Ok(xdp_action::XDP_DROP);
        }

        // Increment counter
        let new_count = count + 1;
        unsafe {
            let _ = PACKET_COUNT_MAP.insert(&contract_id, &new_count, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

**Step 5: Commit (no compile test on macOS)**

This crate cannot compile on macOS. It will be tested in Linux CI.

```bash
git add crates/liquid-data-plane/liquid-data-plane-ebpf/
git commit -m "feat: add eBPF XDP program with rate-limit enforcement maps"
```

---

## Task 6: Control Plane

**Files:**
- Create: `crates/control-plane/Cargo.toml`
- Create: `crates/control-plane/src/lib.rs`
- Create: `crates/control-plane/src/negotiation.rs`
- Create: `crates/control-plane/src/orchestrator.rs`
- Test: `crates/control-plane/tests/orchestrator_tests.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "control-plane"
version.workspace = true
edition.workspace = true

[dependencies]
lsdc-common = { path = "../lsdc-common" }
liquid-data-plane = { path = "../liquid-data-plane/liquid-data-plane" }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
async-trait = { workspace = true }
```

**Step 2: Write negotiation.rs**

```rust
use lsdc_common::dsp::{ContractAgreement, ContractOffer, ContractRequest};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::odrl::ast::PolicyId;

/// Handles Dataspace Protocol contract negotiation.
pub struct NegotiationEngine;

impl NegotiationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Process an incoming contract request from a consumer.
    pub async fn handle_request(&self, request: ContractRequest) -> Result<ContractOffer> {
        tracing::info!(
            consumer = %request.consumer_id,
            "Received contract request"
        );

        // In a real implementation, this would:
        // 1. Validate the consumer's DID
        // 2. Check the requested policy against provider's catalog
        // 3. Counter-offer or accept
        Ok(ContractOffer {
            provider_id: request.policy.provider.clone(),
            offer_id: uuid::Uuid::new_v4().to_string(),
            policy: request.policy,
        })
    }

    /// Finalize a contract agreement.
    pub async fn finalize(&self, offer: ContractOffer) -> Result<ContractAgreement> {
        let agreement_id = PolicyId::new();
        tracing::info!(agreement_id = %agreement_id.0, "Contract finalized");

        Ok(ContractAgreement {
            agreement_id,
            policy: offer.policy,
        })
    }
}
```

**Step 3: Write orchestrator.rs**

```rust
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use lsdc_common::traits::{DataPlane, EnforcementHandle};
use std::sync::Arc;

/// The Orchestrator dispatches finalized agreements to the appropriate planes.
pub struct Orchestrator {
    data_plane: Arc<dyn DataPlane>,
}

impl Orchestrator {
    pub fn new(data_plane: Arc<dyn DataPlane>) -> Self {
        Self { data_plane }
    }

    /// After a contract is signed, enforce the policy on the data plane.
    pub async fn activate_agreement(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle> {
        tracing::info!(
            agreement_id = %agreement.agreement_id.0,
            "Activating agreement on data plane"
        );

        self.data_plane.enforce(&agreement.policy, iface).await
    }

    /// Revoke an active agreement.
    pub async fn revoke_agreement(&self, handle: &EnforcementHandle) -> Result<()> {
        self.data_plane.revoke(handle).await
    }
}
```

**Step 4: Write lib.rs**

```rust
pub mod negotiation;
pub mod orchestrator;
```

**Step 5: Write orchestrator test**

Create `crates/control-plane/tests/orchestrator_tests.rs`:

```rust
use chrono::Utc;
use control_plane::negotiation::NegotiationEngine;
use control_plane::orchestrator::Orchestrator;
use lsdc_common::dsp::ContractRequest;
use lsdc_common::odrl::ast::*;
use lsdc_common::traits::EnforcementStatus;
use liquid_data_plane::loader::LiquidDataPlane;
use std::sync::Arc;

#[tokio::test]
async fn test_full_negotiation_and_enforcement() {
    let policy = PolicyAgreement {
        id: PolicyId("orch-test-1".into()),
        provider: "did:web:provider.example".into(),
        consumer: "did:web:consumer.example".into(),
        target: "urn:data:stream".into(),
        permissions: vec![Permission {
            action: Action::Stream,
            constraints: vec![Constraint::Count { max: 100 }],
            duties: vec![],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + chrono::Duration::days(7)),
    };

    let request = ContractRequest {
        consumer_id: "did:web:consumer.example".into(),
        offer_id: "offer-1".into(),
        policy,
    };

    // Negotiate
    let engine = NegotiationEngine::new();
    let offer = engine.handle_request(request).await.unwrap();
    let agreement = engine.finalize(offer).await.unwrap();

    // Enforce
    let data_plane = Arc::new(LiquidDataPlane::new());
    let orch = Orchestrator::new(data_plane);
    let handle = orch.activate_agreement(&agreement, "eth0").await.unwrap();

    assert!(handle.active);
    assert_eq!(handle.interface, "eth0");

    // Check status
    let status = orch.data_plane_status(&handle).await;
    // Note: status check requires direct access, so we test via the data plane
}

#[tokio::test]
async fn test_revoke_agreement() {
    let policy = PolicyAgreement {
        id: PolicyId("revoke-test".into()),
        provider: "did:web:p".into(),
        consumer: "did:web:c".into(),
        target: "urn:data:x".into(),
        permissions: vec![Permission {
            action: Action::Read,
            constraints: vec![Constraint::Count { max: 10 }],
            duties: vec![],
        }],
        prohibitions: vec![],
        obligations: vec![],
        valid_from: Utc::now(),
        valid_until: None,
    };

    let data_plane = Arc::new(LiquidDataPlane::new());
    let orch = Orchestrator::new(data_plane.clone());

    let handle = orch
        .activate_agreement(
            &lsdc_common::dsp::ContractAgreement {
                agreement_id: PolicyId::new(),
                policy,
            },
            "lo",
        )
        .await
        .unwrap();

    // Revoke
    orch.revoke_agreement(&handle).await.unwrap();

    // Verify revoked
    let status = data_plane.status(&handle).await.unwrap();
    assert!(matches!(status, EnforcementStatus::Revoked));
}
```

**Step 6: Run tests**

Run: `cargo test --package control-plane`
Expected: Tests pass (the first test may need adjustment if `data_plane_status` isn't exposed — fix it).

**Step 7: Commit**

```bash
git add crates/control-plane/
git commit -m "feat: add control plane with negotiation engine and orchestrator"
```

---

## Task 7: Proof Plane Stubs (Pillar 2)

**Files:**
- Create: `crates/proof-plane/proof-plane-host/Cargo.toml`
- Create: `crates/proof-plane/proof-plane-host/src/lib.rs`
- Create: `crates/proof-plane/proof-plane-guest/Cargo.toml`
- Create: `crates/proof-plane/proof-plane-guest/src/main.rs`

**Step 1: Create proof-plane-host/Cargo.toml**

```toml
[package]
name = "proof-plane-host"
version.workspace = true
edition.workspace = true

[dependencies]
lsdc-common = { path = "../../lsdc-common" }
tokio = { workspace = true }
async-trait = { workspace = true }
tracing = { workspace = true }
```

**Step 2: Write proof-plane-host/src/lib.rs**

```rust
use async_trait::async_trait;
use lsdc_common::crypto::ProvenanceReceipt;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::odrl::ast::PolicyAgreement;
use lsdc_common::traits::{ProofEngine, TransformSpec};

/// RISC Zero-backed proof engine for generating and verifying
/// zero-knowledge proofs of data transformation compliance.
///
/// # Sprint 0 Status
/// All methods are stubbed. Sprint 1 will integrate risc0-zkvm
/// to compile guest programs and generate actual zk-STARK receipts.
pub struct RiscZeroProofEngine;

impl RiscZeroProofEngine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProofEngine for RiscZeroProofEngine {
    async fn prove_transform(
        &self,
        _input_hash: &[u8; 32],
        _policy: &PolicyAgreement,
        _transform: &TransformSpec,
    ) -> Result<ProvenanceReceipt> {
        // Sprint 1: Use risc0_zkvm::default_prover() to execute the guest program
        // inside the zkVM and generate a receipt proving the transformation
        // adhered to the policy constraints.
        //
        // The guest program (proof-plane-guest) receives:
        //   - Private input: the raw data
        //   - Public input: policy hash + transform spec
        //   - Output: transformed data hash committed to journal
        Err(LsdcError::ProofGeneration(
            "RISC Zero integration not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn verify_receipt(&self, _receipt: &ProvenanceReceipt) -> Result<bool> {
        // Sprint 1: Call receipt.verify(IMAGE_ID) to cryptographically
        // verify the receipt was generated by the expected guest program.
        Err(LsdcError::ProofGeneration(
            "Receipt verification not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn verify_chain(&self, _chain: &[ProvenanceReceipt]) -> Result<bool> {
        // Sprint 1: For recursive proofs, verify each receipt in the chain
        // and ensure each one's input_hash matches the previous output_hash.
        // This establishes the "Fractal Sovereignty" property.
        Err(LsdcError::ProofGeneration(
            "Recursive chain verification not yet implemented (Sprint 1)".into(),
        ))
    }
}
```

**Step 3: Create proof-plane-guest/Cargo.toml**

This crate is NOT in the workspace. It targets RISC-V and will be built by RISC Zero tooling.

```toml
[package]
name = "proof-plane-guest"
version = "0.1.0"
edition = "2021"

# This crate will depend on risc0-zkvm guest library when Sprint 1 begins.
# [dependencies]
# risc0-zkvm = { version = "3.0", default-features = false, features = ["guest"] }
```

**Step 4: Write proof-plane-guest/src/main.rs**

```rust
// This file will become the RISC Zero guest program in Sprint 1.
//
// It will be compiled to RISC-V and executed inside the zkVM.
// The prover generates a zk-STARK receipt proving this code
// executed correctly on the given inputs.
//
// Sprint 1 implementation:
//
// #![no_main]
// risc0_zkvm::guest::entry!(main);
//
// fn main() {
//     // Read private input: raw data bytes
//     let data: Vec<u8> = risc0_zkvm::guest::env::read();
//
//     // Read public input: policy hash
//     let policy_hash: [u8; 32] = risc0_zkvm::guest::env::read();
//
//     // Apply transformation (e.g., anonymization, aggregation)
//     let transformed = transform(data);
//
//     // Commit output hash to the journal (public output)
//     let output_hash = sha256(&transformed);
//     risc0_zkvm::guest::env::commit(&output_hash);
// }

fn main() {
    // Placeholder — this file exists to establish the crate structure.
    // Sprint 1 will replace this with the actual RISC Zero guest entry.
    println!("proof-plane-guest: placeholder for RISC Zero guest program");
}
```

**Step 5: Commit**

```bash
git add crates/proof-plane/
git commit -m "feat: add proof plane stubs with RISC Zero trait implementation"
```

---

## Task 8: TEE Orchestrator Stubs (Pillar 3)

**Files:**
- Create: `crates/tee-orchestrator/Cargo.toml`
- Create: `crates/tee-orchestrator/src/lib.rs`
- Create: `crates/tee-orchestrator/src/enclave.rs`
- Create: `crates/tee-orchestrator/src/attestation.rs`
- Create: `crates/tee-orchestrator/src/forgetting.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "tee-orchestrator"
version.workspace = true
edition.workspace = true

[dependencies]
lsdc-common = { path = "../lsdc-common" }
tokio = { workspace = true }
async-trait = { workspace = true }
tracing = { workspace = true }
chrono = { workspace = true }
```

**Step 2: Write enclave.rs**

```rust
use async_trait::async_trait;
use lsdc_common::crypto::{AttestationDocument, ProofOfForgetting, Sha256Hash};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{EnclaveManager, EnclaveSession};

/// AWS Nitro Enclave-backed TEE manager.
///
/// Manages the lifecycle of hardware-isolated enclaves for
/// confidential data processing and Proof-of-Forgetting generation.
///
/// # Sprint 0 Status
/// All methods return errors. Sprint 1 will integrate with
/// AWS Nitro Enclaves SDK via vsock communication.
pub struct NitroEnclaveManager;

impl NitroEnclaveManager {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EnclaveManager for NitroEnclaveManager {
    async fn create_enclave(&self, _binary_hash: &[u8; 32]) -> Result<EnclaveSession> {
        // Sprint 1: Use AWS Nitro CLI to:
        // 1. Build enclave image (EIF) from the processing binary
        // 2. Launch enclave with vsock connection
        // 3. Verify enclave measurement matches expected hash
        Err(LsdcError::Attestation(
            "Nitro Enclave creation not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn attest(&self, _session: &EnclaveSession) -> Result<AttestationDocument> {
        // Sprint 1: Request attestation document from Nitro Secure Module
        // The document contains: PCRs, enclave binary hash, public key
        // Signed by AWS Nitro root certificate chain
        Err(LsdcError::Attestation(
            "Attestation not yet implemented (Sprint 1)".into(),
        ))
    }

    async fn destroy_and_prove(&self, _session: EnclaveSession) -> Result<ProofOfForgetting> {
        // Sprint 1: The Proof-of-Forgetting protocol:
        // 1. Signal the enclave to zeroize all data buffers
        //    (using the `zeroize` crate for guaranteed memory clearing)
        // 2. Enclave generates final attestation document with:
        //    - Destruction timestamp
        //    - Hash of destroyed data
        //    - Signed by enclave's ephemeral key
        // 3. Terminate the enclave process
        // 4. Return ProofOfForgetting with the attestation
        Err(LsdcError::Attestation(
            "Proof-of-Forgetting not yet implemented (Sprint 1)".into(),
        ))
    }
}
```

**Step 3: Write attestation.rs**

```rust
use lsdc_common::crypto::AttestationDocument;
use lsdc_common::error::{LsdcError, Result};

/// Verify an attestation document against a trusted root certificate.
///
/// # Sprint 0 Status
/// Stubbed. Sprint 1 will implement AWS Nitro root cert verification.
pub fn verify_attestation(_doc: &AttestationDocument) -> Result<bool> {
    // Sprint 1: Verify the attestation document's signature chain:
    // 1. Parse CBOR-encoded attestation document
    // 2. Verify signature against AWS Nitro root certificate
    // 3. Check PCR values match expected enclave binary
    // 4. Verify timestamp is within acceptable bounds
    Err(LsdcError::Attestation(
        "Attestation verification not yet implemented".into(),
    ))
}
```

**Step 4: Write forgetting.rs**

```rust
use lsdc_common::crypto::ProofOfForgetting;
use lsdc_common::error::{LsdcError, Result};

/// Verify a Proof-of-Forgetting receipt.
///
/// This confirms that data was securely destroyed inside a TEE
/// and the destruction was attested by hardware.
pub fn verify_proof_of_forgetting(_proof: &ProofOfForgetting) -> Result<bool> {
    // Sprint 1:
    // 1. Verify the embedded attestation document
    // 2. Check destruction timestamp is after data processing completed
    // 3. Verify data hash matches the originally transferred dataset
    Err(LsdcError::Attestation(
        "Proof-of-Forgetting verification not yet implemented".into(),
    ))
}
```

**Step 5: Write lib.rs**

```rust
pub mod attestation;
pub mod enclave;
pub mod forgetting;
```

**Step 6: Verify compilation**

Run: `cargo build --package tee-orchestrator`
Expected: Compiles successfully.

**Step 7: Commit**

```bash
git add crates/tee-orchestrator/
git commit -m "feat: add TEE orchestrator stubs for Nitro Enclave and Proof-of-Forgetting"
```

---

## Task 9: Pricing Oracle Python Sidecar (Pillar 4)

**Files:**
- Create: `python/pricing-oracle/pyproject.toml`
- Create: `python/pricing-oracle/src/__init__.py`
- Create: `python/pricing-oracle/src/server.py`
- Create: `python/pricing-oracle/src/shapley.py`
- Create: `python/pricing-oracle/src/proto/pricing.proto`
- Create: `python/pricing-oracle/tests/__init__.py`
- Create: `python/pricing-oracle/tests/test_shapley.py`

**Step 1: Create pyproject.toml**

```toml
[project]
name = "lsdc-pricing-oracle"
version = "0.1.0"
description = "Shapley value-based dynamic data pricing oracle for LSDC"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.104",
    "uvicorn>=0.24",
    "grpcio>=1.59",
    "grpcio-tools>=1.59",
    "numpy>=1.26",
    "pydantic>=2.5",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4",
    "pytest-asyncio>=0.23",
]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["."]
include = ["src*"]
```

**Step 2: Create src/proto/pricing.proto**

```protobuf
syntax = "proto3";

package lsdc.pricing;

service PricingOracle {
    rpc EvaluateUtility(UtilityRequest) returns (ShapleyResponse);
    rpc Renegotiate(RenegotiateRequest) returns (PriceAdjustmentResponse);
}

message UtilityRequest {
    string dataset_id = 1;
    double loss_with_dataset = 2;
    double loss_without_dataset = 3;
    double accuracy_with_dataset = 4;
    double accuracy_without_dataset = 5;
}

message ShapleyResponse {
    string dataset_id = 1;
    double marginal_contribution = 2;
    double confidence = 3;
}

message RenegotiateRequest {
    string agreement_id = 1;
    double marginal_contribution = 2;
    double current_price = 3;
}

message PriceAdjustmentResponse {
    string agreement_id = 1;
    double original_price = 2;
    double adjusted_price = 3;
}
```

**Step 3: Create src/shapley.py**

```python
"""
Truncated Monte Carlo (TMC) Shapley Value estimation.

Sprint 0: Simplified marginal contribution calculation.
Sprint 1: Full TMC-Shapley with convergence detection.
"""

import numpy as np
from dataclasses import dataclass


@dataclass
class ShapleyResult:
    dataset_id: str
    marginal_contribution: float
    confidence: float


def estimate_shapley_value(
    dataset_id: str,
    loss_with: float,
    loss_without: float,
    accuracy_with: float,
    accuracy_without: float,
) -> ShapleyResult:
    """
    Estimate the marginal contribution of a dataset to model performance.

    Sprint 0: Simple difference-based estimation.
    Sprint 1: TMC-Shapley with Monte Carlo permutation sampling.

    The marginal contribution is the normalized performance improvement
    attributable to including this specific dataset in training.
    """
    # Accuracy improvement (primary signal)
    accuracy_delta = accuracy_with - accuracy_without

    # Loss reduction (secondary signal, inverted — lower loss is better)
    loss_delta = loss_without - loss_with

    # Weighted combination
    marginal = 0.7 * accuracy_delta + 0.3 * max(loss_delta, 0.0)

    # Confidence is higher when both signals agree
    if accuracy_delta > 0 and loss_delta > 0:
        confidence = 0.9
    elif accuracy_delta > 0 or loss_delta > 0:
        confidence = 0.6
    else:
        confidence = 0.3

    return ShapleyResult(
        dataset_id=dataset_id,
        marginal_contribution=round(marginal, 6),
        confidence=confidence,
    )


def calculate_price_adjustment(
    original_price: float,
    marginal_contribution: float,
    elasticity: float = 1.5,
) -> float:
    """
    Adjust price based on marginal contribution.

    Uses a simple elasticity model: if the data contributes more than
    expected (marginal > 0.5), price increases; if less, price decreases.

    elasticity controls how aggressively the price adjusts.
    """
    # Baseline expectation: 0.5 marginal contribution = fair price
    adjustment_factor = 1.0 + elasticity * (marginal_contribution - 0.05)
    adjusted = original_price * max(adjustment_factor, 0.1)  # floor at 10%
    return round(adjusted, 2)
```

**Step 4: Create src/server.py**

```python
"""
FastAPI server exposing the Shapley pricing oracle.

Sprint 0: REST API. Sprint 1: gRPC service matching pricing.proto.
"""

from fastapi import FastAPI
from pydantic import BaseModel

from .shapley import estimate_shapley_value, calculate_price_adjustment

app = FastAPI(title="LSDC Pricing Oracle", version="0.1.0")


class UtilityRequest(BaseModel):
    dataset_id: str
    loss_with_dataset: float
    loss_without_dataset: float
    accuracy_with_dataset: float
    accuracy_without_dataset: float


class ShapleyResponse(BaseModel):
    dataset_id: str
    marginal_contribution: float
    confidence: float


class RenegotiateRequest(BaseModel):
    agreement_id: str
    marginal_contribution: float
    current_price: float


class PriceAdjustmentResponse(BaseModel):
    agreement_id: str
    original_price: float
    adjusted_price: float


@app.post("/evaluate", response_model=ShapleyResponse)
async def evaluate_utility(req: UtilityRequest) -> ShapleyResponse:
    result = estimate_shapley_value(
        dataset_id=req.dataset_id,
        loss_with=req.loss_with_dataset,
        loss_without=req.loss_without_dataset,
        accuracy_with=req.accuracy_with_dataset,
        accuracy_without=req.accuracy_without_dataset,
    )
    return ShapleyResponse(
        dataset_id=result.dataset_id,
        marginal_contribution=result.marginal_contribution,
        confidence=result.confidence,
    )


@app.post("/renegotiate", response_model=PriceAdjustmentResponse)
async def renegotiate(req: RenegotiateRequest) -> PriceAdjustmentResponse:
    adjusted = calculate_price_adjustment(req.current_price, req.marginal_contribution)
    return PriceAdjustmentResponse(
        agreement_id=req.agreement_id,
        original_price=req.current_price,
        adjusted_price=adjusted,
    )


@app.get("/health")
async def health():
    return {"status": "ok"}
```

**Step 5: Create src/__init__.py**

```python
```

**Step 6: Create tests/__init__.py**

```python
```

**Step 7: Create tests/test_shapley.py**

```python
from src.shapley import estimate_shapley_value, calculate_price_adjustment


def test_positive_contribution():
    result = estimate_shapley_value(
        dataset_id="ds-1",
        loss_with=0.3,
        loss_without=0.5,
        accuracy_with=0.85,
        accuracy_without=0.75,
    )
    assert result.marginal_contribution > 0
    assert result.confidence == 0.9


def test_negative_contribution():
    result = estimate_shapley_value(
        dataset_id="ds-2",
        loss_with=0.5,
        loss_without=0.3,
        accuracy_with=0.70,
        accuracy_without=0.80,
    )
    assert result.marginal_contribution < 0
    assert result.confidence == 0.3


def test_mixed_signals():
    result = estimate_shapley_value(
        dataset_id="ds-3",
        loss_with=0.4,
        loss_without=0.3,
        accuracy_with=0.82,
        accuracy_without=0.78,
    )
    assert result.confidence == 0.6


def test_price_adjustment_upward():
    adjusted = calculate_price_adjustment(100.0, 0.15)
    assert adjusted > 100.0


def test_price_adjustment_downward():
    adjusted = calculate_price_adjustment(100.0, 0.01)
    assert adjusted < 100.0


def test_price_floor():
    adjusted = calculate_price_adjustment(100.0, -1.0)
    assert adjusted >= 10.0  # 10% floor
```

**Step 8: Commit**

```bash
git add python/pricing-oracle/
git commit -m "feat: add pricing oracle Python sidecar with Shapley value estimation"
```

---

## Task 10: Workspace Compilation & Final Verification

**Step 1: Verify full workspace compiles**

Run: `cargo build --workspace`
Expected: All Rust crates compile without errors.

**Step 2: Run all Rust tests**

Run: `cargo test --workspace`
Expected: All tests pass.

**Step 3: Run Python tests**

Run: `cd python/pricing-oracle && python -m pytest tests/ -v`
Expected: 6 tests pass.

**Step 4: Clean up firebase-debug.log**

```bash
rm -f firebase-debug.log
```

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: verify workspace builds and clean up stale files"
```

---

## Summary

| Task | Component | Status | Tests |
|------|-----------|--------|-------|
| 1 | Workspace root + toolchain | Config | — |
| 2 | xtask build orchestration | Real | Compile check |
| 3 | lsdc-common (types, ODRL, traits) | Real | 3 unit tests |
| 4 | Liquid Data Plane (user-space) | Real | 7 unit + 1 integration |
| 5 | Liquid Data Plane (eBPF kernel) | Real (Linux only) | Linux CI |
| 6 | Control Plane | Real | 2 integration tests |
| 7 | Proof Plane stubs | Stub | Compile check |
| 8 | TEE Orchestrator stubs | Stub | Compile check |
| 9 | Pricing Oracle (Python) | Real | 6 unit tests |
| 10 | Final verification | — | Full workspace |
