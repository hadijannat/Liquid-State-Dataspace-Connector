# Next Milestone

## Phase 3 Hardening

The current repo now exposes a runnable reference stack. The next milestone is to harden that stack without overstating the research frontier.

Acceptance criteria:

- default workspace stays green with the HTTP and gRPC boundary tests included
- the Phase 3 reference configs and local run script stay usable on macOS and Linux
- the feature-gated `RISC Zero` HTTP path stays green on a runner with the external toolchain installed
- `nitro-live` configuration remains pinned-measurement only and clearly separated from live enclave orchestration
- pricing remains advisory-only and sanction output remains proposal-only

## Boundaries

- Keep the current parameterized Aya/XDP design and the `liquid-agent` boundary.
- Keep the domain scope on deterministic CSV transformations.
- Do not expand the ODRL subset until new semantics have a real enforcement or evidence path.
- Keep Nitro as the only live TEE target in scope.
- Keep recursive proofs, live enclave launch orchestration, automatic sanctions, and billing mutation out of this phase.

## CI Expectations

- `host-ci`: default Rust and Python suites
- `linux-xdp`: privileged Linux runner for the ignored `liquid-agent` XDP test
- `zk-nightly`: install the external `cargo risczero` toolchain and run the feature-gated control-plane HTTP lineage test
- `nitro-integration`: Nitro-capable runner for live attestation validation and protected lineage flows through the control API
