# Liquid-State Dataspace Connector (LSDC) — Sprint 0 Architecture Rebaseline

**Date:** 2026-03-06  
**Status:** Implemented and verified for the Sprint 0 MVP surface

## Summary

This repository now describes a truthful Sprint 0 MVP instead of the full four-pillar LSDC vision.

Implemented now:

1. **Reduced policy DSL** in Rust, parsed as the serde representation of `PolicyAgreement`
2. **Agreement-aware Liquid Data Plane** keyed by DSP `agreement_id`
3. **Real Linux XDP attachment path** for packet-cap enforcement, with simulation mode on non-Linux hosts
4. **REST-based pricing oracle boundary** with a concrete Rust client and advisory renegotiation flow

Deferred:

1. JSON-LD / RDF / ODRL translation
2. Multi-agreement packet classification on a single interface
3. gRPC pricing transport
4. Recursive proofs, zk receipts, and proof chaining
5. Hardware attestation and Proof-of-Forgetting execution

## Implemented MVP Surface

### Policy Model

Sprint 0 uses a reduced internal policy DSL:

- `Constraint::Count { max }` is the only packet-level constraint enforced in XDP
- `valid_until` is honored by a user-space expiry timer
- `Spatial`, `RateLimit`, `Purpose`, `Temporal`, `Custom`, prohibitions, duties, and obligations are rejected with explicit errors

The parser in [`crates/lsdc-common/src/odrl/parser.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/lsdc-common/src/odrl/parser.rs) parses the internal JSON shape directly. It is not a JSON-LD parser.

### Enforcement Identity

The canonical runtime identity is the DSP `agreement_id`, not `policy.id`.

- Public handle id: agreement id string
- Kernel map key: stable 32-bit hash derived from agreement id
- Supported topology: one active agreement per interface in Sprint 0

### Liquid Data Plane

The data plane in [`crates/liquid-data-plane/liquid-data-plane/src/loader.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/liquid-data-plane/liquid-data-plane/src/loader.rs) now tracks lifecycle state across:

- `Active`
- `Expired`
- `Revoked`
- `Error`

Linux behavior:

- Load the eBPF object built by `cargo xtask build-ebpf`
- Attach `lsdc_xdp` to the interface in `SKB_MODE`
- Populate three maps:
  - `ACTIVE_AGREEMENT_MAP`
  - `RATE_LIMIT_MAP`
  - `PACKET_COUNT_MAP`
- Read live packet counters from the kernel map in `status()`
- Detach and clear active configuration on revoke or expiry

Non-Linux behavior:

- Preserve the same lifecycle and agreement-aware API in simulation mode
- Skip XDP attach while keeping tests executable on macOS

### Pricing Boundary

Sprint 0 makes REST the canonical pricing transport.

- Python service: [`python/pricing-oracle/src/server.py`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/python/pricing-oracle/src/server.py)
- Rust client: [`crates/control-plane/src/pricing.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/control-plane/src/pricing.rs)
- Orchestrator advisory entrypoint: [`crates/control-plane/src/orchestrator.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/control-plane/src/orchestrator.rs)

The canonical payload now includes:

- full `ShapleyValue`
- `algorithm_version = "heuristic_v0"`
- advisory `PriceAdjustment` responses that do not mutate DSP contracts automatically

The proto file remains as a forward-looking schema reference and mirrors the REST contract shape.

## Deferred Work

### Proof Plane

[`crates/proof-plane/proof-plane-host/src/lib.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/proof-plane/proof-plane-host/src/lib.rs) remains a trait-complete stub. No zk proof generation or recursive verification is implemented in Sprint 0.

### TEE Orchestrator

[`crates/tee-orchestrator/src/enclave.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/tee-orchestrator/src/enclave.rs) remains a trait-complete stub. No live enclave provisioning or attestation verification is implemented in Sprint 0.

### Beyond Sprint 0

Future milestones should build in this order:

1. Real JSON-LD / ODRL subset translation into the reduced enforcement DSL
2. Multi-agreement classification and richer XDP policy maps
3. Pricing transport hardening and optional gRPC migration
4. Proof-plane implementation
5. TEE orchestration and proof-of-forgetting flow

## Verification

Verified in this repo today:

- `cargo test`
- `python3 -m pytest python/pricing-oracle/tests`

Included but not executed in this environment:

- Linux-only ignored integration test for loopback XDP attach and revoke: [`crates/liquid-data-plane/liquid-data-plane/tests/linux_xdp_tests.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/liquid-data-plane/liquid-data-plane/tests/linux_xdp_tests.rs)
