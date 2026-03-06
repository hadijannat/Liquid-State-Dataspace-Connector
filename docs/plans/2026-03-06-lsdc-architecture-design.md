# Liquid-State Dataspace Connector (LSDC) — Architecture Design

**Date:** 2026-03-06
**Status:** Approved
**Scope:** Full monorepo scaffold + Pillar 1 (Liquid Data Plane) live implementation

## Overview

The LSDC replaces the traditional heavyweight Data Plane proxy with four pillars:

1. **Liquid Data Plane** — Compiles ODRL policies into eBPF map parameters, enforced at NIC line rate
2. **Proof Plane** — Recursive zk-SNARKs for multi-hop data provenance
3. **TEE Orchestrator** — Hardware-anchored Proof-of-Forgetting via Trusted Execution Environments
4. **Pricing Oracle** — Shapley value-based dynamic data pricing

Sprint 0 builds all four pillar crates with real trait boundaries, but only Pillar 1 has runtime logic.

## Repository Structure

```
lsdc-core/
├── Cargo.toml                          # Workspace root
├── rust-toolchain.toml                 # Nightly + bpfel target
├── .cargo/config.toml                  # Cross-compile settings
├── xtask/src/main.rs                   # Build orchestration (eBPF compile)
├── crates/
│   ├── lsdc-common/src/                # Shared types & crypto primitives
│   │   ├── lib.rs
│   │   ├── odrl/                       # ODRL AST, policy types, parser
│   │   ├── identity/                   # W3C DID types
│   │   ├── dsp/                        # Dataspace Protocol messages
│   │   └── crypto/                     # Shared hashing, key types
│   ├── control-plane/src/              # DSP negotiation, orchestration
│   ├── liquid-data-plane/
│   │   ├── liquid-data-plane/src/      # User-space: compiler, loader, maps
│   │   └── liquid-data-plane-ebpf/src/ # Kernel-space: #![no_std] XDP
│   ├── proof-plane/
│   │   ├── proof-plane-host/src/       # zkVM host: prove & verify
│   │   └── proof-plane-guest/src/      # zkVM guest: runs inside RISC Zero
│   └── tee-orchestrator/src/           # Enclave lifecycle, attestation
├── python/pricing-oracle/              # Shapley value gRPC sidecar
└── docs/plans/                         # Design documents
```

## Decisions

### Approach B: Nested Workspace with Host/Guest Splits

aya-rs requires a `#![no_std]` eBPF crate separate from user-space. RISC Zero requires a host/guest split. These are non-negotiable toolchain constraints. Each pillar that needs a split gets nested sub-crates within the workspace.

### Cross-Compile + Test Stubs for macOS

eBPF requires Linux kernel >= 5.15. On macOS, kernel-dependent code is gated behind `#[cfg(target_os = "linux")]`. User-space logic (ODRL parsing, policy compilation) compiles and tests everywhere. Real XDP attachment tests run in Linux CI.

### RISC Zero as zkVM

More mature Rust ecosystem, well-documented dev-mode for fast testing. Concrete `RiscZeroProofEngine` implements the `ProofEngine` trait.

## Core Type System

### ODRL Policy Types

```rust
pub struct PolicyAgreement {
    pub id: PolicyId,
    pub provider: Did,
    pub consumer: Did,
    pub permissions: Vec<Permission>,
    pub prohibitions: Vec<Prohibition>,
    pub obligations: Vec<Duty>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

pub enum Constraint {
    Count { max: u64 },
    Spatial { allowed_regions: Vec<GeoRegion> },
    Temporal { not_after: DateTime<Utc> },
    Purpose { allowed: Vec<String> },
    RateLimit { max_per_second: u64 },
    Custom { key: String, value: serde_json::Value },
}
```

### Pillar Trait Boundaries

Each pillar exposes an async trait in `lsdc-common`:

- `DataPlane` — enforce/revoke/status
- `ProofEngine` — prove_transform/verify_receipt/verify_chain
- `EnclaveManager` — create_enclave/attest/destroy_and_prove
- `PricingOracle` — evaluate_utility/renegotiate

## Pillar 1: Liquid Data Plane (Live in Sprint 0)

### Compilation Pipeline

```
JSON-LD ODRL → (oxrdf) → PolicyAgreement AST → (compiler.rs) → Vec<MapEntry>
                                                                     │
                                                          eBPF maps populated
                                                                     │
                                                          XDP attached to NIC
```

The XDP program is parameterized, not JIT-compiled. It reads enforcement rules from eBPF hash maps at runtime. The "compilation" step translates ODRL constraints into map key-value entries.

### XDP Program Behavior

1. Read source IP from packet header
2. Check GEO_FENCE_MAP — drop if outside allowed regions
3. Increment PACKET_COUNT_MAP — drop if over rate limit
4. Check EXPIRY_MAP — signal user-space if contract expired

### Lifecycle

- On contract signature: attach XDP, populate maps
- On contract expiry: async timer calls `xdp::detach()`
- On revocation: immediate detach + map cleanup

## Pillars 2-4: Stubbed in Sprint 0

Each pillar has:
- Concrete struct implementing the trait
- Method bodies containing `todo!()` with descriptive messages
- Correct type signatures matching the trait boundary
- Enough structure that Sprint 1 teams can implement without refactoring interfaces

### Pillar 2: Proof Plane

- `RiscZeroProofEngine` struct with stub methods
- `proof-plane-guest` skeleton with RISC Zero entry macro
- Recursive proof verification chain typed but not implemented

### Pillar 3: TEE Orchestrator

- `NitroEnclaveManager` struct targeting AWS Nitro Enclaves
- Attestation document types defined
- `ProofOfForgetting` type with timestamp and attestation fields

### Pillar 4: Pricing Oracle

- Python gRPC service skeleton with `pricing.proto`
- Rust `GrpcPricingOracle` client stub in control-plane
- TMC-Shapley algorithm placeholder in Python

## Testing Strategy

| Layer | Platform | Method |
|-------|----------|--------|
| ODRL parser | All | Unit tests with sample JSON-LD |
| Policy compiler | All | Unit + property tests (proptest) |
| XDP attachment | Linux CI | Integration tests with raw sockets |
| ZK proofs | All (dev-mode) | RISC Zero dev-mode bypasses crypto |
| TEE attestation | AWS only | Requires enclave-enabled EC2 |
