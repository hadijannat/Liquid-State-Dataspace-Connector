# RFC: Pillar 1 Selector-Aware Liquid Transport

## Goal

Advance the liquid data plane through truthful transport enforcement only:

- protocol-aware selector keying
- packet and byte counters
- deterministic expiry teardown
- explicit runtime status and selector visibility

## Out of Scope

- arbitrary ODRL-to-eBPF code generation
- payload transforms inside the XDP path
- SmartNIC or DPU offload
- geographic enforcement

## Current Repo Boundary

Phase 4 implements selector-aware guarded transfer on Aya/XDP or simulation. The current codebase now separates:

- policy lowering into a backend-neutral transport plan
- projection of that plan into XDP map state
- runtime lifecycle tracking
- Linux XDP and simulated realization backends

Negotiated `spatial` clauses remain metadata-only until a real enforcement path exists.
