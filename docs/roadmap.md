# Roadmap

## Now

- keep the default workspace truthful and green
- keep the reference stack runnable across three nodes with shared fixtures
- keep pricing advisory-only with explicit heuristic metadata
- keep the platform track stable while documenting the long-horizon research track separately
- keep the new domain and service splits stable while `lsdc-common` and `proof-plane-host` act as temporary compatibility facades

## Next

1. Finish migrating callers from `lsdc-common`/`proof-plane-host` onto `lsdc-policy`, `lsdc-contracts`, `lsdc-evidence`, `proof-plane-core`, `proof-plane-dev`, and `proof-plane-risc0`.
2. Expand parity and characterization coverage around planner/projection/backend boundaries, `evidence_records`, and startup lineage-job recovery.
3. Keep the feature-gated recursive `RISC Zero` path green on a runner with the external toolchain installed and keep its advertised capability semantics aligned across docs, `/health`, and `/lsdc/v1/capabilities`.
4. Harden `nitro-live` around real attestation material, attested-recipient-key pinning, and move from dev deletion evidence toward attested teardown evidence on Nitro-capable infrastructure.

## Later

1. Real enclave launch orchestration.
2. Non-advisory pricing and contract mutation.
