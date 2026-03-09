# RFC: Pillar 2 Recursive Proof Plane

## Goal

Define a future recursive proof architecture for multi-hop provenance rollups while keeping the current repo truthful.

## Current Repo Boundary

- default proof path: dev receipts
- optional proof path: single-hop `RISC Zero`
- recursive rollups: not implemented
- canonical receipt and chain-verification types now live in `proof-plane-core`
- `proof-plane-risc0` is feature-gated; default workspace builds do not claim a live recursive prover

## Research Questions

- stable proof I/O contracts across tiers
- recursion composition and verifier strategy
- bounded workload shapes before general-purpose proving
