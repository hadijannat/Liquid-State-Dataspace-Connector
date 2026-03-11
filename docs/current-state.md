# Current State

## Truthful Runtime Model

Negotiation still derives a `RequestedExecutionProfile`, which describes requested capability intent only:

- transport intent: guarded transfer
- proof intent: provenance receipt required
- TEE intent: attested execution required
- pricing mode: advisory

Actual runtime backends are chosen by the instantiated components and the evidence they emit at execution time. The repo does not treat negotiation as proof that `RISC Zero` or `nitro-live` are being used, and `control-plane-api` validates configured transport, proof, and TEE intent against instantiated runtime components before startup succeeds.

The current branch adds an **LSDC execution overlay** on top of DSP:

- DSP remains the contract and transfer protocol surface.
- LSDC adds execution capability advertisement, session binding, verifier-produced attestation results, proof receipt binding, and transparency receipts.
- Legacy routes continue to work, but the runtime now treats them as compatibility paths over the same execution-session and evidence graph model.

The API now also exposes `PolicyExecutionClassification`, which labels negotiated clauses as:

- `executable`: backed by a real enforcement or evidence path
- `metadata_only`: negotiated and surfaced, but not technically enforced in this phase
- `rejected`: incompatible with the instantiated runtime stack

Internally, the repo now keeps five layers separate:

- policy lowering: ODRL parsing, normalization, lowering, requested-profile derivation, and clause classification
- execution overlay: capability descriptors, overlay commitments, execution sessions, challenges, and truthfulness mode
- execution planning: backend-neutral transport plans and execution-pipeline inputs
- backend realization: XDP/simulated transport enforcement, dev/live TEE adapters, and proof backend adapters
- evidence generation: attestation evidence, verifier-produced attestation results, receipt DAG nodes, teardown evidence, transparency receipts, pricing evidence, and settlement inputs

That layering is implemented as an additive change: the new `/lsdc/v1/*` overlay routes exist alongside the previous HTTP surface, and older job and settlement responses remain available as compatibility views.

## Internal Architecture

- Canonical domain crates:
  - `crates/lsdc-policy`: ODRL AST/parser, lowering, `LiquidPolicyIr`, `RequestedExecutionProfile`, `PolicyExecutionClassification`
  - `crates/lsdc-contracts`: DSP-facing agreement, transfer, lineage-job, and settlement DTOs
  - `crates/lsdc-evidence`: receipt envelopes, attestation DTOs, deletion evidence, pricing evidence, and evidence hashing
  - `crates/lsdc-execution-protocol`: execution capability descriptors, overlay commitments, sessions, challenges, statements, and transparency receipts
  - `crates/lsdc-runtime-model`: `ExecutionSessionAggregate`, `CapabilityResolution`, `EvidenceDag`, and legacy projection builders
  - `crates/receipt-log`: local append-only transparency log and inclusion receipts
- Compatibility facades:
  - `crates/lsdc-common` now re-exports the policy/contracts/evidence domains for one release while keeping `fixtures` and `identity`
  - `crates/proof-plane/host` remains the compatibility host crate while `proof-plane-core`, `proof-plane-dev`, and `proof-plane-risc0` expose clearer proof-plane surfaces
- Control plane split:
  - `crates/control-plane` now routes work through `agreement_service`, `lineage_job_service`, `execution_pipeline`, `pricing_service`, and `breach_service`
  - `Orchestrator` remains as a thin compatibility facade over those services
- HTTP and store split:
  - `crates/control-plane-http` is now separated into bootstrap, router, state, error, and aggregate handlers
  - detached lineage execution is owned by `LineageJobRunner`, which is reused for both startup reconciliation and newly created jobs
  - `crates/control-plane-store` is split by aggregate and now persists execution sessions, evidence graph nodes and edges, transparency receipts, and compatibility records for older settlement reads
- Liquid data plane split:
  - `crates/liquid-data-plane/agent-core` now separates `planner`, `projection`, `runtime`, `backend/linux_xdp`, `backend/simulated`, and `service`
  - the static XDP program and map-driven parameterization remain in place; policy lowering does not know XDP map layout

## Implemented Behavior

- Reference stack:
  - `apps/control-plane-api` exposes DSP-style contract and transfer endpoints plus additive LSDC execution-overlay routes under `/lsdc/v1/*`
  - `apps/control-plane-api` requires `Authorization: Bearer <LSDC_API_BEARER_TOKEN>` on every non-health route
  - `apps/control-plane-api` reports configured versus resolved actual backends from `/health`
  - `apps/control-plane-api` exposes policy-truthfulness details and execution capability advertisement on finalize, transfer, lineage, settlement, health, and `/lsdc/v1/capabilities`
  - `apps/control-plane-api` can verify both the legacy linear receipt chain and the newer evidence-DAG plus transparency-receipt path
  - `apps/control-plane-api` persists agreements, execution sessions, lineage jobs, evidence graph records, transparency receipts, pricing decisions, sanction proposals, and compatibility evidence records in SQLite
  - `apps/liquid-agent` is a binary composition root over the shared `liquid-agent-grpc` contract crate
  - the pricing oracle and the Rust gRPC client both compile from `proto/pricing/v1/pricing.proto`
- ODRL subset:
  - actions: `read`, `transfer`, `anonymize`
  - constraints: `count`, `purpose`, `validUntil`
  - duties: `transform-required`, `delete-after`
  - overlay operands: `teeImageSha384`, `attestationFreshnessSeconds`, `proofKind`, `keyReleaseProfile`, `maxEgressBytes`, `deletionMode`
  - session-binding and transparency-registration requirements live in the execution overlay, not the ODRL profile
  - negotiated metadata only or strict-rejected depending on truthfulness mode: unsupported overlay clauses and `spatial`
- Liquid data plane:
  - parameterized Aya/XDP enforcement for packet and byte caps
  - multi-agreement lifecycle keyed by agreement identity and protocol-aware transport selector
  - collision-aware dynamic session-port allocation that keeps the hash-derived port as the preferred choice and probes within `20_000..60_000` before failing
  - explicit resolved transport guards surfaced through enforcement handles and API responses
  - Linux enforcement plus simulation mode on non-Linux hosts
- Proof plane:
  - default `DevReceiptProofEngine`
  - shared CSV transform kernel
  - `proof-plane-core` defines canonical receipt plus chain- and DAG-verification helpers
  - `proof-plane-dev` re-exports the dev receipt engine
  - `proof-plane-risc0` is present in the workspace but the real backend is enabled only with the `risc0` feature and the external guest toolchain
  - session-bound receipts now carry agreement and challenge commitments
  - the default local stack still uses the dev receipt backend, but the `risc0` feature now enables versioned recursive transform chaining and receipt-composition proofs for the `RISC Zero` backend while preserving verification of legacy `risc0.csv_transform.v1` receipts
  - recursive verification is DAG-native on `/lsdc/v1/evidence/verify` while the legacy chain endpoint remains a strictly linear compatibility path
- TEE plane:
  - deterministic `nitro-dev`
  - pinned-measurement `nitro-live` validation with shared fixture coverage
  - submitted `AttestationEvidence` is appraised server-side into `AttestationResult`
  - verifier-produced `AttestationResult` is the canonical execution appraisal object
  - challenge nonce and resolved transport guard bindings are part of the execution-session model
  - optional attested-recipient-key pinning is stored as a challenge-bound SHA-256 hash rather than as replicated raw key material
  - the live Nitro path now wires an AWS-backed attestation verifier plus AWS KMS key broker when `tee_backend = nitro_live`
  - `TeardownEvidence` still defaults to `DevDeletionEvidence` outside the live Nitro path, but the live KMS-attested execution flow can emit `KeyErasureEvidence`
  - the current live path is still not a complete end-to-end confidential dataflow because plaintext transform inputs remain in the runtime path
- Transparency plane:
  - a local append-only Merkle log registers execution statement hashes and returns inclusion receipts
  - settlement and verification can anchor to the resulting transparency receipts
  - this is not presented as an external SCITT deployment or internet-facing transparency service
- Pricing plane:
  - gRPC transport
  - signed, advisory-only decisions
  - truthful algorithm label: `heuristic_marginal_v0`
  - canonical `PricingEvidenceV1` records algorithm id/version, decision policy id/version, advisory status, and evidence anchor hash
  - pricing remains anchored into the evidence DAG without claiming autonomous contract mutation
  - insecure loopback-only gRPC is supported only in explicit development mode with `LSDC_ALLOW_DEV_DEFAULTS=1`
- Cross-node validation:
  - HTTP integration tests cover request/finalize, transfer start/complete, async lineage jobs, legacy chain verification, execution-overlay endpoints, and settlement responses
  - the default demo path is a three-party A -> B -> C CSV flow backed by simulated liquid agents, `nitro-dev`, local transparency receipts, and the dev receipt backend

## Production Boundaries

The branch still does **not** claim:

- hardware-rooted deletion proof
- autonomous pricing or ledger mutation

The branch also does not claim that those feature-gated implementations are active in the default local workspace. Recursive `RISC Zero` proving still requires the `risc0` feature plus the external guest toolchain, and the live Nitro AWS verifier/KMS path still requires explicit production configuration.

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
- `RISC Zero`: install the guest toolchain first with `rzup install rust`, then run `cargo test -p proof-plane-host --features risc0` or `cargo test -p control-plane-api --features risc0 --test risc0_http_tests`

For the current delivery sequence, use [roadmap.md](roadmap.md).

## Runtime Secrets And Dev Mode

- `LSDC_API_BEARER_TOKEN` is required at startup for the control-plane API.
- `LSDC_PROOF_SECRET`, `LSDC_FORGETTING_SECRET`, and `LSDC_PRICING_SECRET` are required unless `LSDC_ALLOW_DEV_DEFAULTS=1`.
- The reference demo exports explicit development values for those variables into the stack processes it launches instead of relying on silent fallbacks, and it prints the bearer token for any separate shell that needs to call the protected HTTP routes.
