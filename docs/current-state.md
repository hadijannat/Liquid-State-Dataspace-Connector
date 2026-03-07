# Current State

## Truthful Runtime Model

Negotiation now derives a `RequestedExecutionProfile`, which describes requested capability intent only:

- transport intent: guarded transfer
- proof intent: provenance receipt required
- TEE intent: attested execution required
- pricing mode: advisory

Actual runtime backends are chosen by the instantiated components and the evidence they emit at execution time. The repo no longer treats negotiation as proof that `RISC Zero` or `nitro-live` are being used, and `control-plane-api` now validates configured transport/proof/TEE intent against instantiated runtime components before startup succeeds.

## Implemented Behavior

- Reference stack:
  - `apps/control-plane-api` exposes DSP-style contract and transfer endpoints plus `lsdc` lineage, evidence, and settlement endpoints
  - `apps/control-plane-api` reports configured versus resolved actual backends from `/health`
  - `apps/control-plane-api` persists agreements, transfer sessions, lineage jobs, proof bundles, pricing decisions, and sanction proposals in SQLite
  - `apps/liquid-agent` is a binary composition root over the shared `liquid-agent-grpc` contract crate
  - the pricing oracle and the Rust gRPC client both compile from `proto/pricing/v1/pricing.proto`
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
- Cross-node validation:
  - HTTP integration tests cover request/finalize, transfer start/complete, async lineage jobs, evidence verification, and settlement responses
  - the default demo path is a three-party A -> B -> C CSV flow backed by simulated liquid agents, `nitro-dev`, and `DevReceiptProofEngine`

## Shared Fixtures

The repo now keeps reusable workload artifacts in `fixtures/`:

- `fixtures/odrl/`: supported policy samples
- `fixtures/liquid/`: transform manifests
- `fixtures/csv/`: canonical batch inputs
- `fixtures/proof/`: expected proof workload outputs
- `fixtures/nitro/`: live attestation samples

## Verification

- Repo hygiene: `cargo xtask verify-repo`
- Default workspace: `cargo test --workspace`
- Python oracle: `.venv/bin/python -m pytest python/pricing-oracle/tests`
- Local reference stack: `./scripts/run-phase3-demo.sh`
- Linux XDP: `cargo xtask build-ebpf` and `cargo test -p liquid-agent --test linux_agent_tests -- --ignored` on a privileged Linux runner
- `RISC Zero`: `cargo test -p control-plane-api --features risc0 --test risc0_http_tests`

For the next bounded delivery target, use [next-milestone.md](next-milestone.md).
