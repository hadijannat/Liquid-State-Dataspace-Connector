# Phase 3 Reference Stack

The Phase 3 stack turns the Phase 2 crates into a runnable three-node reference system:

- `apps/control-plane-api`: DSP-style HTTP boundary plus async lineage execution and settlement views
- `apps/liquid-agent`: node-local gRPC daemon for transport enforcement
- `python/pricing-oracle`: advisory pricing sidecar

This is still a truthful prototype. The default local stack demonstrates guarded transfer, protected CSV transforms, provenance receipts, proof-of-forgetting, and advisory pricing with `dev_receipt`. The feature-gated `RISC Zero` backend now implements recursive transform chaining and receipt composition on prepared runners, but that path is not enabled in the default local demo.

## Local Topology

- `tier-a`: provider API on `127.0.0.1:7001`, liquid agent on `127.0.0.1:7101`
- `tier-b`: intermediary API on `127.0.0.1:7002`, liquid agent on `127.0.0.1:7102`
- `tier-c`: downstream consumer API on `127.0.0.1:7003`, liquid agent on `127.0.0.1:7103`
- pricing oracle: gRPC on `127.0.0.1:50051`, health on `127.0.0.1:8000`

Reference configs live in `configs/phase3/`.

## Start the Stack

Bootstrap the toolchain first:

```bash
./scripts/bootstrap-ubuntu.sh
```

Start the local stack:

```bash
./scripts/run-phase3-demo.sh
```

The script launches the pricing oracle, three liquid agents, and three control-plane API processes. By default all agents run in simulated mode so the topology is runnable on macOS and Linux without privileges.

## HTTP Surface

DSP-style endpoints:

- `POST /dsp/contracts/request`
- `POST /dsp/contracts/finalize`
- `POST /dsp/transfers/start`
- `POST /dsp/transfers/{transfer_id}/complete`

LSDC runtime endpoints:

- `POST /lsdc/lineage/jobs`
- `GET /lsdc/lineage/jobs/{job_id}`
- `POST /lsdc/evidence/verify-chain`
- `GET /lsdc/agreements/{agreement_id}/settlement`
- `GET /health`

`/lsdc/lineage/jobs` accepts a full agreement, CSV input as UTF-8, a transform manifest, training metrics, and an optional prior receipt. The service persists the agreement locally, runs lineage asynchronously, and returns a `job_id` for polling.

`/health` returns additive structured JSON with node name, configured backends, resolved actual backends, and enabled feature flags.

## Demo Flow

1. Finalize an agreement on `tier-a` for `tier-b`.
2. Start a guarded transfer on `tier-a`.
3. Submit a lineage job on `tier-b` using the finalized agreement and the source CSV.
4. Finalize a downstream agreement on `tier-b` for `tier-c`.
5. Submit a downstream lineage job on `tier-c` using the upstream receipt as `prior_receipt`.
6. Verify the two-hop receipt chain on `tier-c`.
7. Inspect settlement on `tier-b` and `tier-c`.

The integration test `apps/control-plane-api/tests/http_api_tests.rs` exercises this full A -> B -> C path.

## Truthfulness Boundary

- Default multi-hop sovereignty is demonstrated with `DevReceiptProofEngine`.
- `RISC Zero` is feature-gated. Recursive transform chaining and receipt composition are implemented behind `risc0`, but the default reference stack does not enable that path.
- `nitro-live` validates pinned attestation material only; the reference stack does not launch real enclaves.
- Pricing stays advisory-only.
- Sanctions remain proposal artifacts and do not mutate DIDs or registries.
