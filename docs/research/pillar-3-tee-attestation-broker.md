# RFC: Pillar 3 TEE Attestation Broker

## Goal

Evolve from local Nitro-oriented attestation validation toward a real enclave lifecycle and key-release broker.

## Current Repo Boundary

- `nitro-dev` produces deterministic local evidence
- `nitro-live` validates pinned attestation material
- current deletion evidence is dev-only secret-signed teardown evidence
- current deletion-evidence verification is tied to dev attestation semantics, not hardware-rooted live teardown evidence
- live enclave launch and remote key release are not implemented
- hardware-rooted attested teardown evidence is not implemented

## Research Questions

- enclave launch ownership and trust boundaries
- attestation document verification chain
- deletion-evidence semantics across providers
