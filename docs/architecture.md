# LSDC Phase 1 Architecture

This repository is the Phase 1 rebaseline of the Liquid-State Dataspace Connector. It keeps `DSP + ODRL` at the public boundary, uses batch CSV as the executable proving ground, and evolves the connector as a Rust-first control, proof, and TEE platform instead of a Java middleware stack.

## Boundary Model

- `ContractRequest`, `ContractOffer`, and `ContractAgreement` remain the external DSP contract surface.
- Raw ODRL JSON stays on the wire and is lowered into an internal `LiquidPolicyIr`.
- `ExecutionProfile` is derived after negotiation and captures the intended runtime shape:
  - `transport_backend`
  - `proof_backend`
  - `tee_backend`
  - `pricing_mode`

## Supported ODRL Subset

Phase 1 intentionally supports only the executable subset already represented in the code:

- actions: `read`, `transfer`, `anonymize`
- constraints: `count`, `purpose`, `validUntil`
- duties: `transform-required`, `delete-after`
- negotiated metadata only: `spatial`

`spatial` is preserved in the lowered policy as negotiated metadata. It is not enforced in XDP as geofencing until topology-aware enforcement exists.

## Workspace Layout

- `crates/lsdc-common`: shared DSP types, liquid policy IR, execution profile, evidence models
- `crates/control-plane`: negotiation, orchestration, gRPC pricing client, smoke example
- `crates/liquid-data-plane/host`: Aya userspace loader and agreement lifecycle management
- `crates/liquid-data-plane/ebpf`: XDP program and eBPF maps
- `crates/proof-plane/host`: proof-engine implementations and receipt verification
- `crates/proof-plane/guest`: CSV transform kernel shared by proof backends
- `crates/tee-orchestrator`: dev and live Nitro-oriented attestation / forgetting flows
- `python/pricing-oracle`: gRPC pricing service plus FastAPI health endpoint

## Proof Plane

- The default host-CI proof engine is `DevReceiptProofEngine`.
- It produces signed development receipts with explicit metadata:
  - `proof_backend`
  - `receipt_format_version`
  - `proof_method_id`
  - `prior_receipt_hash`
  - opaque `receipt_bytes`
- Proof bundles carry the receipt metadata again so downstream orchestration can reason about the proof backend without reparsing the receipt.
- Receipt chaining is single-hop hash binding today. Full recursive proving is deferred.

## TEE Plane

- `nitro-dev` is the default deterministic attestation path for local tests.
- `nitro-live` is represented as a pinned-measurement verification mode:
  - it validates a raw attestation blob is present
  - it rejects zero-PCR debug measurements
  - it rejects image hashes that do not match the pinned EIF measurement
- Proof-of-forgetting remains attested zeroization plus enclave teardown evidence. It is not a claim that no external copy ever existed.

## Pricing Plane

- gRPC is the canonical pricing transport.
- FastAPI is only the health/admin surface.
- Pricing decisions are advisory-only and signed.
- Pricing requests include audit context:
  - dataset id
  - transformed asset hash
  - proof receipt hash
  - model run id
  - metrics window

## Enforcement Model

- Linux is the only real XDP enforcement target.
- macOS and other non-Linux hosts run in simulation mode.
- One XDP attachment is maintained per interface and agreements are managed through maps keyed by agreement identity and session port.
- Multi-agreement behavior is supported and revoke/expiry only removes the targeted agreement state.
