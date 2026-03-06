# LSDC Delivery Roadmap

## Current Phase

Phase 1 establishes a truthful baseline:

- DSP/ODRL negotiation with reduced executable lowering
- agreement-aware Aya/XDP enforcement
- batch CSV transform lineage with chained development receipts
- Nitro-oriented attestation and proof-of-forgetting evidence
- signed, advisory gRPC pricing decisions with audit context

## Next Engineering Milestones

1. Add a feature-gated real `RISC Zero` single-hop proving backend alongside the current dev receipt engine.
2. Harden `nitro-live` from pinned-measurement validation into real attestation parsing and enclave launch on Nitro-capable runners.
3. Promote richer policy semantics into executable enforcement only when they have truthful runtime implementations.
4. Keep pricing advisory until billing mutation, contract amendment approval, and audit retention are specified end-to-end.

## CI Topology

- `host-ci`: standard Rust and Python tests
- `linux-xdp`: self-hosted Linux runner for ignored XDP integration tests
- `zk-nightly`: proof-plane runner for heavier proving work
- `nitro-integration`: Nitro-capable self-hosted runner for enclave and attestation flows

## Verification Commands

Rust workspace:

```bash
cargo test --workspace
```

Python pricing oracle:

```bash
.venv/bin/python -m pytest python/pricing-oracle/tests
```

Pricing smoke path:

```bash
./scripts/smoke-pricing-oracle.sh
```

Linux-only XDP integration:

```bash
cargo xtask build-ebpf
sudo cargo test -p liquid-data-plane --test linux_xdp_tests -- --ignored
```
