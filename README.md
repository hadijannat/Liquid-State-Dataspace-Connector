# Liquid-State Dataspace Connector

This repository is the Phase 1 rebaseline of the Liquid-State Dataspace Connector. It keeps `DSP + ODRL` at the public boundary, uses batch CSV lineage as the executable proving ground, and evolves the system as a Rust-first control, proof, TEE, and pricing platform.

## What is implemented

- Raw ODRL JSON negotiation with stable `policy_hash` generation.
- Reduced executable ODRL lowering into `LiquidPolicyIr` for `read`, `transfer`, `anonymize`, `count`, `purpose`, `validUntil`, `transform-required`, and `delete-after`.
- Internal `ExecutionProfile` derivation after agreement finalization.
- Multi-agreement Aya/XDP enforcement keyed by agreement id and session port.
- Batch CSV transforms for `drop_columns`, `redact_columns`, `hash_columns`, and `row_filter`.
- Development proof receipts with explicit backend metadata and prior-receipt chaining.
- Nitro-oriented attestation and proof-of-forgetting evidence for `nitro-dev` and pinned-measurement `nitro-live` validation.
- gRPC pricing oracle with signed, advisory-only `PriceDecision` responses plus audit context.
- End-to-end orchestration for negotiate -> arm XDP -> run protected CSV job -> verify forgetting proof -> request advisory price decision -> emit sanctions when forgetting verification fails.

## Important limits

- The default proof backend is still the development receipt engine. Real `RISC Zero` proving is the next proof milestone, not the default path today.
- `spatial` is negotiated metadata only. It is not enforced as geofencing in XDP in this phase.
- `nitro-live` currently validates pinned measurements and rejects debug-style PCRs, but this repo is not launching real enclaves in local host CI.
- Linux is the only real XDP enforcement target. macOS uses simulation mode.
- Pricing is advisory only and does not mutate contracts or billing automatically.

## Workspace layout

- `crates/lsdc-common`: public DSP types, liquid policy IR, shared crypto/evidence helpers
- `crates/control-plane`: negotiation, orchestration, gRPC pricing client, smoke example
- `crates/liquid-data-plane/host`: userspace loader and agreement lifecycle management
- `crates/liquid-data-plane/ebpf`: XDP program and eBPF maps
- `crates/proof-plane/host`: proof-engine implementations and receipt verification
- `crates/proof-plane/guest`: CSV transform kernel
- `crates/tee-orchestrator`: protected job execution and forgetting-proof verification
- `python/pricing-oracle`: gRPC pricing sidecar and health endpoint
- `scripts/`: bootstrap and smoke scripts

## Architecture and roadmap

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)

## Getting started

On Ubuntu or Debian:

```bash
./scripts/bootstrap-ubuntu.sh
```

Manual Python setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e 'python/pricing-oracle[dev]'
```

## Verification

Rust workspace:

```bash
cargo test --workspace
```

Python oracle:

```bash
.venv/bin/python -m pytest python/pricing-oracle/tests
```

Smoke the Python gRPC server with the Rust client:

```bash
./scripts/smoke-pricing-oracle.sh
```

Linux XDP integration on a privileged Linux runner:

```bash
cargo xtask build-ebpf
sudo cargo test -p liquid-data-plane --test linux_xdp_tests -- --ignored
```
