# LSDC Execution Overlay

## Purpose

LSDC does not replace DSP. It overlays DSP negotiation and transfer with an execution-trust protocol that binds negotiated capabilities to per-run execution sessions, challenge-based attestation, proof receipts, and transparency receipts.

The base assumptions are:

- DSP remains the contract and transfer protocol.
- LSDC adds execution-session semantics and evidence anchoring on top of DSP agreements.
- The repo stays truthful about what is locally implemented versus what is only modeled for later production backends.

## Core Model

The execution overlay adds these canonical objects:

- `ExecutionCapabilityDescriptor`: what this runtime can actually enforce or emit.
- `ExecutionOverlayCommitment`: hash binding over canonical policy, capability descriptor, evidence requirements, and truthfulness mode.
- `ExecutionSession`: a persisted execution attempt tied to one agreement commitment.
- `ExecutionSessionChallenge`: nonce, selector hash, requester ephemeral key, and expiry for one session.
- `ExecutionStatement`: canonical statement for an agreement, attestation result, proof receipt, transparency receipt, key-erasure evidence, price decision, or settlement.
- `TransparencyReceipt`: inclusion receipt from the local append-only log.
- `EvidenceDag`: canonical execution evidence graph rooted at one `evidence_root_hash`.

## Session Lifecycle

The overlay session flow is:

1. Finalize a DSP agreement.
2. Derive a canonical overlay commitment from policy plus runtime capabilities.
3. Create an execution session for that agreement commitment.
4. Mint a challenge that binds nonce, selector hash, and requester key material.
5. Run the workload under that session.
6. Verify attestation into an `AttestationResult`.
7. Emit a provenance receipt that carries the session and commitment bindings.
8. Register canonical statements in the transparency log.
9. Build an `EvidenceDag` and anchor settlement to its root hash.

Legacy lineage routes may create a server-managed execution session automatically, but they still map onto this lifecycle internally.

## HTTP Surface

The additive versioned overlay routes are:

- `GET /lsdc/v1/capabilities`
- `POST /lsdc/v1/sessions`
- `POST /lsdc/v1/sessions/:id/challenge`
- `POST /lsdc/v1/sessions/:id/attestation-result`
- `POST /lsdc/v1/evidence/register`
- `GET /lsdc/v1/evidence/:statement_id/receipt`
- `POST /lsdc/v1/evidence/verify`

Existing `/dsp/*`, `/lsdc/lineage/*`, `/lsdc/evidence/verify-chain`, and settlement routes remain valid compatibility routes.

## Truthful Local-First Semantics

This branch is intentionally local-first:

- the default proof backend can compose and verify receipt DAGs without claiming zk recursion
- `nitro-dev` can produce verifier-bound attestation results without claiming hardware-rooted key release
- the transparency service is a local append-only Merkle log
- the runtime advertises strict versus permissive truthfulness mode explicitly

The overlay must never imply production claims the current runtime cannot verify.

## Out Of Scope

These are not claimed as implemented by the current overlay:

- AWS certificate-chain validation for Nitro attestation
- AWS KMS-backed attested key release
- recursive `RISC Zero` proving in the default workspace
- hardware-rooted deletion proof
- autonomous pricing or ledger mutation

Those capabilities may be represented in descriptors or policy clauses, but the runtime must classify them truthfully as unsupported or metadata-only until real implementations land.
