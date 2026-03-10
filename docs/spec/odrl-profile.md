# LSDC ODRL Profile

## Goal

The LSDC ODRL profile defines how DSP-carried ODRL policies are normalized into contractual and evidence semantics for the LSDC execution overlay.

This profile is intentionally narrower than generic ODRL. It focuses on clauses that can be mapped to transport enforcement, attestation appraisal, proof generation, and teardown evidence. Session mechanics such as challenge issuance, resolved selector binding, and transparency registration mode belong to the overlay, not the policy language.

## Base Subset

The currently supported base policy subset remains:

- actions: `read`, `transfer`, `anonymize`
- constraints: `count`, `purpose`, `validUntil`
- duties: `transform-required`, `delete-after`
- negotiated but not enforced by all current backends: `spatial`

Base lowering still produces `LiquidPolicyIr` for the current transport and transform pipeline.

## Overlay Operands

The execution overlay extends the profile with these LSDC-specific operands:

- `teeImageSha384`
- `attestationFreshnessSeconds`
- `proofKind`
- `keyReleaseProfile`
- `maxEgressBytes`
- `deletionMode`

These operands are normalized even when the current runtime cannot fully enforce them, because they participate in overlay capability matching and truthfulness reporting.

## Truthfulness Modes

The profile supports two truthfulness modes:

- `permissive`: unsupported overlay clauses are preserved and surfaced as `metadata_only`
- `strict`: unsupported overlay clauses reject agreement finalization

If no explicit truthfulness mode is supplied, the profile defaults to `permissive`.

## Lowering Rules

Lowering occurs in two layers:

1. Base ODRL lowering into `LiquidPolicyIr` for transport, transform, and runtime guards.
2. Overlay normalization into `NormalizedPolicy` plus `ClauseRealization` records.

`ClauseRealization` must identify:

- the clause id
- whether it is `executable`, `metadata_only`, or `rejected`
- which primitives are required
- which evidence artifacts are required
- why a downgrade or rejection happened

This keeps the current compatibility classification while making the execution overlay explicit and machine-readable.

## Capability Mapping

The intended overlay-to-runtime mapping is:

- `maxEgressBytes` -> transport byte-cap enforcement
- `teeImageSha384` -> attestation appraisal against measured image identity
- `attestationFreshnessSeconds` -> challenge expiry and verifier freshness checks
- `proofKind` -> proof backend selection and receipt format requirements
- `keyReleaseProfile` -> modeled key-broker semantics until a real attested broker exists
- `deletionMode` -> teardown evidence mode selection

Overlay evidence requirements, not ODRL operands, carry:

- challenge nonce requirements
- resolved selector hash binding requirements
- transparency registration mode
- proof-composition mode

## Current Truthful Limits

The branch should document these limits rather than hiding them:

- `keyReleaseProfile` is modeled before real AWS-backed key release exists
- `deletionMode` is executable only for the truthful local `dev_deletion` path in the default build
- `teeImageSha384` is represented through current attestation appraisal data, not a full provider PKI chain

The profile exists to sharpen semantics, not to overstate implementation maturity.
