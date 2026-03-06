# Liquid-State Dataspace Connector

The Liquid-State Dataspace Connector (LSDC) is a Rust-first dataspace prototype that keeps `DSP + ODRL` on the external boundary and reinterprets the connector as a control, proof, TEE, and pricing platform instead of a persistent middleware proxy.

This repository is intentionally split across three documentation layers:

- Vision: [docs/vision.md](docs/vision.md)
- Current state: [docs/current-state.md](docs/current-state.md)
- Next milestone: [docs/next-milestone.md](docs/next-milestone.md)
- Phase 3 reference stack: [docs/phase3-reference-stack.md](docs/phase3-reference-stack.md)

## Implemented Today

- DSP contract request and agreement flow with stable raw-ODRL policy hashing.
- Lowering of the executable ODRL subset into `LiquidPolicyIr` and `RequestedExecutionProfile`.
- `apps/control-plane-api`: an `axum` + SQLite service that exposes DSP-style contract and transfer endpoints plus LSDC lineage, evidence, and settlement endpoints.
- `apps/liquid-agent`: a loopback gRPC daemon that runs real Aya/XDP enforcement on Linux and simulated enforcement elsewhere.
- Batch CSV transform lineage with the default `DevReceiptProofEngine`, proof-of-forgetting, and advisory pricing behind the HTTP service surface.
- Feature-gated single-hop `RISC Zero` proof backend in `proof-plane-host`.
- Nitro-oriented attestation and proof-of-forgetting flows for `nitro-dev` plus pinned-measurement validation for `nitro-live`.
- Advisory-only pricing over gRPC with truthful heuristic algorithm metadata.

## Experimental vs Future

- Experimental:
  - `RISC Zero` proving is feature-gated and off by default.
  - `nitro-live` validates pinned measurements and raw attestation shape, but the local reference stack does not launch real enclaves.
- Future:
  - recursive proof rollups
  - live enclave lifecycle orchestration on Nitro-capable runners
  - non-advisory pricing and contract/billing mutation
  - richer ODRL enforcement beyond the currently executable subset

## Workspace

- `apps/control-plane-api`: DSP-style HTTP API, SQLite persistence, async lineage jobs, settlement view
- `apps/liquid-agent`: privileged or simulated transport daemon with loopback gRPC API
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

Run the local Phase 3 reference stack:

```bash
./scripts/run-phase3-demo.sh
```

Linux XDP integration:

```bash
cargo xtask build-ebpf
sudo cargo test -p liquid-agent --test linux_agent_tests -- --ignored
```

Feature-gated `RISC Zero` control-plane path:

```bash
cargo test -p control-plane-api --features risc0 --test risc0_http_tests
```

The `RISC Zero` feature requires the external `cargo risczero` toolchain to be installed on the machine that runs it.
