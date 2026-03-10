# LSDC ODRL Profile

## Goal

The LSDC ODRL profile defines how DSP-carried ODRL policies are normalized into execution and evidence requirements for the LSDC execution overlay.

This profile is intentionally narrower than generic ODRL. It focuses on clauses that can be mapped to transport enforcement, session binding, attestation, proof generation, transparency logging, and teardown evidence.

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
- `proofRecursionDepth`
- `transparencyRegistrationRequired`
- `keyReleaseProfile`
- `maxEgressBytes`
- `selectorHashBindingRequired`

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
- `selectorHashBindingRequired` -> session challenge plus selector-hash binding
- `teeImageSha384` -> attestation appraisal against measured image identity
- `attestationFreshnessSeconds` -> challenge expiry and verifier freshness checks
- `proofKind` -> proof backend selection and receipt format requirements
- `proofRecursionDepth` -> receipt-DAG or recursive-composition support
- `transparencyRegistrationRequired` -> statement registration in the transparency log
- `keyReleaseProfile` -> attested key-release or key-erasure semantics

## Current Truthful Limits

The branch should document these limits rather than hiding them:

- `proofRecursionDepth` above single-hop is modeled truthfully even when only the dev receipt backend can realize DAG composition in the local stack
- `keyReleaseProfile` is modeled before real AWS-backed key release exists
- `transparencyRegistrationRequired` is satisfied by a local transparency log, not an external SCITT deployment
- `teeImageSha384` is represented through current attestation appraisal data, not a full provider PKI chain

The profile exists to sharpen semantics, not to overstate implementation maturity.
