use lsdc_evidence::Sha256Hash;
use lsdc_execution_protocol::{
    AdvertisedProfiles, CapabilitySupportLevel, ExecutionCapabilityDescriptor,
    ExecutionEvidenceRequirements, ExecutionOverlayCommitment, ProofCompositionMode,
    TransparencyMode, TruthfulnessMode, LOCAL_TRANSPARENCY_PROFILE,
    LSDC_EXECUTION_PROTOCOL_VERSION,
};
use std::collections::BTreeMap;

fn sample_descriptor() -> ExecutionCapabilityDescriptor {
    ExecutionCapabilityDescriptor {
        overlay_version: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
        truthfulness_default: TruthfulnessMode::Permissive,
        advertised_profiles: AdvertisedProfiles {
            attestation_profile: "nitro-dev-attestation-result-v1".into(),
            proof_profile: "dev-receipt-dag-v1".into(),
            transparency_profile: LOCAL_TRANSPARENCY_PROFILE.into(),
            teardown_profile: "dev-deletion-v1".into(),
        },
        support: BTreeMap::from([
            (
                "attestation.nitro_dev".into(),
                CapabilitySupportLevel::Implemented,
            ),
            (
                "proof.dev_receipt_dag".into(),
                CapabilitySupportLevel::Implemented,
            ),
            (
                "teardown.dev_deletion".into(),
                CapabilitySupportLevel::Experimental,
            ),
        ]),
    }
}

fn sample_evidence_requirements() -> ExecutionEvidenceRequirements {
    ExecutionEvidenceRequirements {
        challenge_nonce_required: true,
        selector_hash_binding_required: true,
        transparency_registration_mode: TransparencyMode::Required,
        proof_composition_mode: ProofCompositionMode::Dag,
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
    let evidence_requirements = sample_evidence_requirements();

    let permissive = ExecutionOverlayCommitment::build(
        "agreement-1",
        TruthfulnessMode::Permissive,
        policy_hash.clone(),
        descriptor.clone(),
        evidence_requirements.clone(),
    )
    .expect("commitment");
    let strict = ExecutionOverlayCommitment::build(
        "agreement-1",
        TruthfulnessMode::Strict,
        policy_hash,
        descriptor,
        evidence_requirements,
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
