# Liquid-State Dataspace Connector

The Liquid-State Dataspace Connector (LSDC) is a Rust-first dataspace prototype that keeps `DSP + ODRL` on the external boundary and reinterprets the connector as a control, proof, TEE, and pricing platform instead of a persistent middleware proxy.

This repository is intentionally split across three documentation layers:

- Vision: [docs/vision.md](/Users/aeroshariati/Liquid-State-Dataspace-Connector/docs/vision.md)
- Current state: [docs/current-state.md](/Users/aeroshariati/Liquid-State-Dataspace-Connector/docs/current-state.md)
- Next milestone: [docs/next-milestone.md](/Users/aeroshariati/Liquid-State-Dataspace-Connector/docs/next-milestone.md)

## Implemented Today

- DSP contract request and agreement flow with stable raw-ODRL policy hashing.
- Lowering of the executable ODRL subset into `LiquidPolicyIr`.
- Multi-agreement Aya/XDP enforcement for packet and byte caps on Linux, with simulation mode elsewhere.
- Batch CSV transform lineage with the default `DevReceiptProofEngine`.
- Feature-gated single-hop `RISC Zero` proof backend in `proof-plane-host`.
- Nitro-oriented attestation and proof-of-forgetting flows for `nitro-dev` plus pinned-measurement validation for `nitro-live`.
- Advisory-only pricing over gRPC with truthful heuristic algorithm metadata.

## Experimental vs Future

- Experimental:
  - `RISC Zero` proving is feature-gated and off by default.
  - `nitro-live` validates pinned measurements and raw attestation shape, but local CI does not launch real enclaves.
- Future:
  - recursive proof rollups
  - live enclave lifecycle orchestration on Nitro-capable runners
  - non-advisory pricing and contract/billing mutation
  - richer ODRL enforcement beyond the currently executable subset

## Workspace

- `crates/lsdc-common`: shared DSP types, requested execution profile, liquid policy IR, crypto/evidence models, fixtures loader
- `crates/control-plane`: negotiation, orchestration, gRPC pricing client, smoke example
- `crates/liquid-data-plane/host`: userspace loader and agreement lifecycle management
- `crates/liquid-data-plane/ebpf`: XDP program and eBPF maps
- `crates/proof-plane/guest`: shared batch CSV transform kernel
- `crates/proof-plane/host`: dev receipt engine and feature-gated `RISC Zero` host backend
- `crates/proof-plane/risc0-guest`: embedded guest package used only by the `RISC Zero` feature build
- `crates/tee-orchestrator`: protected job execution and forgetting-proof verification
- `python/pricing-oracle`: gRPC pricing sidecar and FastAPI health endpoint
- `fixtures/`: shared ODRL, manifest, CSV, proof, and Nitro attestation samples

## Getting Started

Ubuntu or Debian bootstrap:

```bash
./scripts/bootstrap-ubuntu.sh
```

Rust and Python verification:

```bash
cargo test --workspace
.venv/bin/python -m pytest python/pricing-oracle/tests
```

Linux XDP integration:

```bash
cargo xtask build-ebpf
sudo cargo test -p liquid-data-plane --test linux_xdp_tests -- --ignored
```

Feature-gated `RISC Zero` backend:

```bash
cargo test -p proof-plane-host --features risc0
```

The `RISC Zero` feature requires the external `cargo risczero` toolchain to be installed on the machine that runs it.
