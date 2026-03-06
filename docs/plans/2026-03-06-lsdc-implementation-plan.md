# LSDC Sprint 0 MVP Implementation Plan

**Status:** Implemented for the current repository state  
**Goal:** Provide a truthful, test-backed Sprint 0 baseline for agreement-aware packet-cap enforcement and advisory pricing

## What Sprint 0 Includes

### 1. Reduced Policy DSL

- Internal JSON parsing for `PolicyAgreement`
- Agreement activation rejects unsupported constructs explicitly
- Effective packet cap is the strictest `Count` constraint across permissions
- Agreement expiry is driven by `valid_until` in user space

### 2. Agreement-Aware Liquid Data Plane

- `DataPlane::enforce` now accepts a full `ContractAgreement`
- `agreement_id` is the public enforcement identity
- one active agreement per interface
- Linux loader attaches an XDP program and populates runtime maps
- `status()` reads live packet counters on Linux and lifecycle state everywhere

### 3. Advisory Pricing Integration

- REST is the only implemented pricing transport
- Rust client implements `PricingOracle`
- Orchestrator exposes a separate advisory pricing method
- `ShapleyValue` now carries `algorithm_version`
- `PriceAdjustment` embeds the full `ShapleyValue`

### 4. Truthful Stubs

- proof-plane remains a stub with stable trait boundaries
- tee-orchestrator remains a stub with stable trait boundaries
- the proto mirrors the REST wire shape but is not the active transport

## Key Files

- [`crates/lsdc-common/src/traits.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/lsdc-common/src/traits.rs)
- [`crates/liquid-data-plane/liquid-data-plane/src/compiler.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/liquid-data-plane/liquid-data-plane/src/compiler.rs)
- [`crates/liquid-data-plane/liquid-data-plane/src/loader.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/liquid-data-plane/liquid-data-plane/src/loader.rs)
- [`crates/control-plane/src/pricing.rs`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/crates/control-plane/src/pricing.rs)
- [`python/pricing-oracle/src/server.py`](/Users/aeroshariati/Liquid-State-Dataspace-Connector/python/pricing-oracle/src/server.py)

## Acceptance Criteria

Implemented and verified:

- parser/compiler tests cover accepted and rejected policy shapes
- orchestrator tests cover agreement activation and revoke
- pricing client tests verify the REST wire contract used by Rust
- Python endpoint tests verify the JSON schema served by FastAPI
- `cargo test` passes on the current host
- `python3 -m pytest python/pricing-oracle/tests` passes on the current host

Implemented but environment-dependent:

- Linux XDP attach/revoke integration test exists and is intentionally ignored by default because it requires:
  - Linux
  - privileges to attach XDP
  - a built eBPF object via `cargo xtask build-ebpf`

## Explicit Non-Goals for Sprint 0

- JSON-LD / RDF parsing
- full ODRL semantics
- geofencing or rate-per-second enforcement
- multiple active agreements per interface
- automatic DSP contract mutation from pricing outputs
- recursive proof generation
- live enclave orchestration

## Next Milestones

1. Run and harden the Linux XDP test on a real Linux runner
2. Decide the next reduced-policy feature to promote into the executable map/XDP contract
3. Add stronger pricing audit context before any billing automation
4. Implement proof-plane and TEE milestones only after the MVP surface is stable
