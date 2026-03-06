# Next Milestone

## Phase 2 MVP

The current milestone is a truthful MVP, not a full realization of the Liquid-State vision.

Acceptance criteria:

- default workspace stays green with the dev receipt engine and `nitro-dev`
- the repo clearly separates implemented, experimental, and future claims
- the `RISC Zero` backend exists as a feature-gated single-hop proving path
- recursive proving remains explicitly unsupported for that backend
- pricing remains advisory-only

## Boundaries

- Keep the current parameterized Aya/XDP design.
- Do not expand the ODRL subset until new semantics have a real runtime path.
- Keep Nitro as the only live TEE target in scope.
- Keep recursive proofs, live enclave launch orchestration, and billing mutation out of this phase.

## CI Expectations

- `host-ci`: default Rust and Python suites
- `linux-xdp`: privileged Linux runner for ignored XDP tests
- `zk-nightly`: install the external `cargo risczero` toolchain and run the feature-gated proof backend
- `nitro-integration`: Nitro-capable runner for live attestation validation and protected lineage flows
