# Architecture Index

Use the current documentation layers instead of treating this file as a full design spec:

- Vision: [vision.md](vision.md)
- Current state: [current-state.md](current-state.md)
- Roadmap: [roadmap.md](roadmap.md)
- Research track: [research/README.md](research/README.md)

This repo intentionally separates visionary architecture from implemented behavior so runtime claims remain truthful.

Current internal layering is:

- `lsdc-policy`: policy lowering and requested/actual capability truthfulness
- `lsdc-contracts`: DSP-facing contracts, transfers, lineage jobs, and settlements
- `lsdc-evidence`: receipts, attestation, deletion evidence, and pricing evidence
- `control-plane`: application services over contracts, transport, proof, TEE, and pricing capabilities
- `liquid-agent-core`: planner, projection, runtime, and backend adapters for transport realization

Temporary compatibility facades remain in place:

- `lsdc-common`
- `proof-plane-host`
