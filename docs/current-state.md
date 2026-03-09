# Current State

## Truthful Runtime Model

Negotiation now derives a `RequestedExecutionProfile`, which describes requested capability intent only:

- transport intent: guarded transfer
- proof intent: provenance receipt required
- TEE intent: attested execution required
- pricing mode: advisory

Actual runtime backends are chosen by the instantiated components and the evidence they emit at execution time. The repo no longer treats negotiation as proof that `RISC Zero` or `nitro-live` are being used, and `control-plane-api` now validates configured transport/proof/TEE intent against instantiated runtime components before startup succeeds.

The API now also exposes `PolicyExecutionClassification`, which labels negotiated clauses as:

- `executable`: backed by a real enforcement or evidence path
- `metadata_only`: negotiated and surfaced, but not technically enforced in this phase
- `rejected`: incompatible with the instantiated runtime stack

Internally, the repo now keeps four layers separate:

- policy lowering: ODRL parsing, normalization, lowering, requested-profile derivation, and clause classification
- execution planning: backend-neutral transport plans and execution-pipeline inputs
- backend realization: XDP/simulated transport enforcement, dev/live TEE adapters, and proof backend adapters
- evidence generation: receipts, deletion evidence, pricing evidence, and settlement inputs

That layering is implemented without changing the public HTTP routes, gRPC proto, or current config schema.

## Internal Architecture

- Canonical domain crates:
  - `crates/lsdc-policy`: ODRL AST/parser, lowering, `LiquidPolicyIr`, `RequestedExecutionProfile`, `PolicyExecutionClassification`
  - `crates/lsdc-contracts`: DSP-facing agreement, transfer, lineage-job, and settlement DTOs
  - `crates/lsdc-evidence`: receipt envelopes, attestation DTOs, deletion evidence, pricing evidence, and evidence hashing
- Compatibility facades:
  - `crates/lsdc-common` now re-exports the policy/contracts/evidence domains for one release while keeping `fixtures` and `identity`
  - `crates/proof-plane/host` remains the compatibility host crate while `proof-plane-core`, `proof-plane-dev`, and `proof-plane-risc0` expose clearer proof-plane surfaces
- Control plane split:
  - `crates/control-plane` now routes work through `agreement_service`, `lineage_job_service`, `execution_pipeline`, `pricing_service`, and `breach_service`
  - `Orchestrator` remains as a thin compatibility facade over those services
- HTTP and store split:
  - `crates/control-plane-http` is now separated into bootstrap, router, state, error, and aggregate handlers
  - detached lineage execution is owned by `LineageJobRunner`, which is reused for both startup reconciliation and newly created jobs
  - `crates/control-plane-store` is split by aggregate and now dual-writes canonical evidence into `evidence_records` while preserving legacy settlement reads
- Liquid data plane split:
  - `crates/liquid-data-plane/agent-core` now separates `planner`, `projection`, `runtime`, `backend/linux_xdp`, `backend/simulated`, and `service`
  - the static XDP program and map-driven parameterization remain in place; policy lowering does not know XDP map layout

## Implemented Behavior

- Reference stack:
- `apps/control-plane-api` exposes DSP-style contract and transfer endpoints plus `lsdc` lineage, evidence, and settlement endpoints
- `apps/control-plane-api` requires `Authorization: Bearer <LSDC_API_BEARER_TOKEN>` on every non-health route
- `apps/control-plane-api` reports configured versus resolved actual backends from `/health`
- `apps/control-plane-api` exposes policy-truthfulness details on finalize, transfer, lineage, settlement, and health responses
- `apps/control-plane-api` verifies evidence chains by checking canonical receipt linkage first, then verifying each receipt against the backend declared inside the receipt
- `apps/control-plane-api` persists agreements, transfer sessions, lineage jobs, proof bundles, pricing decisions, sanction proposals, and canonical evidence records in SQLite
  - `apps/liquid-agent` is a binary composition root over the shared `liquid-agent-grpc` contract crate
  - the pricing oracle and the Rust gRPC client both compile from `proto/pricing/v1/pricing.proto`
- ODRL subset:
  - actions: `read`, `transfer`, `anonymize`
  - constraints: `count`, `purpose`, `validUntil`
  - duties: `transform-required`, `delete-after`
  - negotiated metadata only: `spatial`
- Liquid data plane:
  - parameterized Aya/XDP enforcement for packet and byte caps
  - multi-agreement lifecycle keyed by agreement identity and protocol-aware transport selector
  - collision-aware dynamic session-port allocation that keeps the hash-derived port as the preferred choice and probes within `20_000..60_000` before failing
  - explicit resolved transport guards surfaced through enforcement handles and API responses
  - Linux enforcement plus simulation mode on non-Linux hosts
- Proof plane:
  - default `DevReceiptProofEngine`
  - shared CSV transform kernel
  - `proof-plane-core` defines canonical receipt and chain-verification types
  - `proof-plane-dev` re-exports the dev receipt engine
  - `proof-plane-risc0` is present in the workspace but the real backend is enabled only with the `risc0` feature and the external guest toolchain
  - recursive proving explicitly unsupported for the `RISC Zero` backend in this phase
- TEE plane:
  - deterministic `nitro-dev`
  - pinned-measurement `nitro-live` validation with shared fixture coverage
  - current forgetting evidence is development evidence, not hardware-rooted deletion proof
  - `DevDeletionEvidence` is the truthful canonical label for the current secret-signed teardown path
  - current settlement gating verifies that dev deletion evidence and its embedded dev attestation are both internally consistent
  - future attested teardown evidence is modeled separately and not implemented
- Pricing plane:
  - gRPC transport
  - signed, advisory-only decisions
  - truthful algorithm label: `heuristic_marginal_v0`
  - canonical `PricingEvidenceV1` records algorithm id/version, decision policy id/version, advisory status, and evidence anchor hash
  - insecure loopback-only gRPC is supported only in explicit development mode with `LSDC_ALLOW_DEV_DEFAULTS=1`
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
- Python oracle: `python -m pytest python/pricing-oracle/tests`
- Local reference stack: `./scripts/run-phase3-demo.sh`
- Linux XDP: `cargo xtask build-ebpf` and `cargo test -p liquid-agent --test linux_agent_tests -- --ignored` on a privileged Linux runner
- `RISC Zero`: `cargo test -p proof-plane-risc0 --features risc0` or `cargo test -p control-plane-api --features risc0 --test risc0_http_tests`

For the current delivery sequence, use [roadmap.md](roadmap.md).

## Runtime Secrets And Dev Mode

- `LSDC_API_BEARER_TOKEN` is required at startup for the control-plane API.
- `LSDC_PROOF_SECRET`, `LSDC_FORGETTING_SECRET`, and `LSDC_PRICING_SECRET` are required unless `LSDC_ALLOW_DEV_DEFAULTS=1`.
- The reference demo exports explicit development values for those variables instead of relying on silent fallbacks.
