use lsdc_execution_protocol::{
    clause_set_hash, ExecutionCapabilityDescriptor, ExecutionOverlayCommitment,
    SelectorSemantics, TruthfulnessMode, LOCAL_TRANSPARENCY_PROFILE,
    LSDC_EXECUTION_PROTOCOL_VERSION,
};
use lsdc_evidence::Sha256Hash;

fn sample_descriptor() -> ExecutionCapabilityDescriptor {
    let supported_clause_ids = vec![
        "maxEgressBytes".to_string(),
        "proofKind".to_string(),
        "teeImageSha384".to_string(),
    ];

    ExecutionCapabilityDescriptor {
        protocol_version: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
        attestation_profile: "nitro-dev-attestation-result-v1".into(),
        proof_profile: "dev-receipt-dag-v1".into(),
        transparency_profile: LOCAL_TRANSPARENCY_PROFILE.into(),
        key_release_profile: "session-bound-local-key-erasure-v1".into(),
        selector_semantics: SelectorSemantics {
            protocol_bound: true,
            session_port_bound: true,
            selector_hash_binding_required: true,
        },
        required_clause_set_hash: clause_set_hash(&supported_clause_ids).unwrap(),
        supported_clause_ids,
    }
}

#[test]
fn capability_descriptor_hash_is_stable() {
    let descriptor = sample_descriptor();
    let hash_a = descriptor.canonical_hash().expect("hash");
    let hash_b = sample_descriptor().canonical_hash().expect("hash");
    assert_eq!(hash_a, hash_b);
}

#[test]
fn overlay_commitment_hash_changes_when_truthfulness_changes() {
    let descriptor = sample_descriptor();
    let policy_hash = Sha256Hash::digest_bytes(b"policy");
    let evidence_hash = Sha256Hash::digest_bytes(b"evidence");

    let permissive = ExecutionOverlayCommitment::build(
        TruthfulnessMode::Permissive,
        policy_hash.clone(),
        descriptor.clone(),
        evidence_hash.clone(),
    )
    .expect("commitment");
    let strict = ExecutionOverlayCommitment::build(
        TruthfulnessMode::Strict,
        policy_hash,
        descriptor,
        evidence_hash,
    )
    .expect("commitment");

    assert_ne!(
        permissive.agreement_commitment_hash,
        strict.agreement_commitment_hash
    );
    assert_eq!(
        permissive.capability_descriptor_hash,
        strict.capability_descriptor_hash
    );
}
