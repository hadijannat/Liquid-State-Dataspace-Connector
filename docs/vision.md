# LSDC Vision

## Long-Horizon Goal

LSDC aims at a connector architecture with three cooperating planes:

- Control plane: negotiate DSP and ODRL contracts
- Liquid data plane: enforce selected transport policy as ephemeral kernel or hardware policy
- Proof plane: emit cryptographic evidence that downstream processing respected upstream constraints

Within those planes, the long-horizon target is a four-layer runtime:

- policy lowering
- execution planning
- backend realization
- evidence generation

The long-term research direction is still the same:

- policy lowering from semantic ODRL intent into executable transport and transform guards
- recursive provenance proofs for multi-hop dataspace flows
- hardware-anchored proof-of-forgetting
- utility-aware pricing tied to actual downstream model impact

## What This Repo Is Not Claiming Yet

- No recursive zk rollups are implemented.
- No arbitrary ODRL-to-eBPF code generation exists.
- No real multi-cloud TEE broker exists.
- No autonomous contract mutation or billing settlement exists.
- No hardware-rooted proof of deletion is implemented; the current dev deletion evidence is not equivalent to attested teardown evidence.

This vision document is intentionally aspirational. For truthful implementation details, use [current-state.md](current-state.md).
