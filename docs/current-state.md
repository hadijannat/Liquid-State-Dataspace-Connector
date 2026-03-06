# Current State

## Truthful Runtime Model

Negotiation now derives a `RequestedExecutionProfile`, which describes requested capability intent only:

- transport intent: guarded transfer
- proof intent: provenance receipt required
- TEE intent: attested execution required
- pricing mode: advisory

Actual runtime backends are chosen by the instantiated components and the evidence they emit at execution time. The repo no longer treats negotiation as proof that `RISC Zero` or `nitro-live` are being used.

## Implemented Behavior

- ODRL subset:
  - actions: `read`, `transfer`, `anonymize`
  - constraints: `count`, `purpose`, `validUntil`
  - duties: `transform-required`, `delete-after`
  - negotiated metadata only: `spatial`
- Liquid data plane:
  - parameterized Aya/XDP enforcement for packet and byte caps
  - multi-agreement lifecycle keyed by agreement identity and session port
  - Linux enforcement plus simulation mode on non-Linux hosts
- Proof plane:
  - default `DevReceiptProofEngine`
  - shared CSV transform kernel
  - feature-gated single-hop `RISC Zero` backend
  - recursive proving explicitly unsupported for the `RISC Zero` backend in this phase
- TEE plane:
  - deterministic `nitro-dev`
  - pinned-measurement `nitro-live` validation with shared fixture coverage
  - proof-of-forgetting is attested zeroization plus teardown evidence
- Pricing plane:
  - gRPC transport
  - signed, advisory-only decisions
  - truthful algorithm label: `heuristic_marginal_v0`

## Shared Fixtures

The repo now keeps reusable workload artifacts in `fixtures/`:

- `fixtures/odrl/`: supported policy samples
- `fixtures/liquid/`: transform manifests
- `fixtures/csv/`: canonical batch inputs
- `fixtures/proof/`: expected proof workload outputs
- `fixtures/nitro/`: live attestation samples

## Verification

- Default workspace: `cargo test --workspace`
- Python oracle: `.venv/bin/python -m pytest python/pricing-oracle/tests`
- Linux XDP: `cargo xtask build-ebpf` and ignored integration tests on a privileged Linux runner
- `RISC Zero`: `cargo test -p proof-plane-host --features risc0`

For the bounded delivery target, use [next-milestone.md](/Users/aeroshariati/Liquid-State-Dataspace-Connector/docs/next-milestone.md).
