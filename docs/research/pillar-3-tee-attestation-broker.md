# RFC: Pillar 3 TEE Attestation Broker

## Goal

Evolve from local Nitro-oriented attestation validation toward a real enclave lifecycle and key-release broker.

## Current Repo Boundary

- `nitro-dev` produces deterministic local evidence
- `nitro-live` validates pinned attestation material
- live enclave launch and remote key release are not implemented

## Research Questions

- enclave launch ownership and trust boundaries
- attestation document verification chain
- proof-of-forgetting semantics across providers
