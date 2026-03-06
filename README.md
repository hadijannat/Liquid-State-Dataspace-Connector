# Liquid-State Dataspace Connector

This repository is a Rust-first LSDC prototype for batch CSV lineage. It keeps DSP/ODRL at the public boundary, lowers policies into an internal `LiquidPolicyIr`, enforces transfer guards in an Aya/XDP data plane, produces chained provenance receipts for CSV transforms, emits prototype Nitro-style attestation and proof-of-forgetting evidence, and prices completed jobs over gRPC from a Python sidecar.

## What is implemented

- Raw ODRL JSON-LD request and agreement payloads with stable `policy_hash` generation.
- A reduced, explicit ODRL subset lowered into `LiquidPolicyIr`:
  - actions: `read`, `transfer`, `anonymize`
  - constraints: `count`, `spatial`, `purpose`, `validUntil`
  - duties: `delete-after`, `transform-required`
- Multi-agreement liquid data plane state keyed by DSP `agreement_id` and per-session port.
- Batch CSV transform kernel for `drop_columns`, `redact_columns`, `hash_columns`, and `row_filter`.
- Prototype proof receipts with prior-receipt chaining and host-side verification.
- Prototype Nitro-style proof bundles containing provenance, attestation, proof-of-forgetting, and an audit hash.
- gRPC pricing oracle with signed `PriceDecision` responses and a FastAPI `/health` endpoint.
- An orchestration path for negotiate -> arm XDP -> run protected CSV job -> verify forgetting proof -> request price decision -> emit amendment/sanction proposals.

## What is still prototype-only

- The proof plane uses a local proof envelope and receipt chain, not real RISC Zero cryptography yet.
- The TEE layer produces deterministic Nitro-style attestation receipts locally; it is not connected to live Nitro hardware.
- The XDP transport guard is real on Linux, but the ignored loopback integration test still requires a privileged Linux runner and a built eBPF object.

## Workspace layout

- `crates/lsdc-common`: public DSP types, liquid policy IR, shared crypto/evidence helpers
- `crates/control-plane`: negotiation, orchestration, gRPC pricing client, smoke example
- `crates/liquid-data-plane`: userspace loader and XDP eBPF program
- `crates/proof-plane`: CSV transform kernel and receipt chain implementation
- `crates/tee-orchestrator`: protected job execution and forgetting-proof verification
- `python/pricing-oracle`: gRPC pricing sidecar and health endpoint
- `scripts/`: bootstrap and smoke scripts

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
