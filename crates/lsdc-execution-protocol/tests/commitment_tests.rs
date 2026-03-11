use lsdc_evidence::Sha256Hash;
use lsdc_execution_protocol::{
    AdvertisedProfiles, CapabilitySupportLevel, ExecutionCapabilityDescriptor,
    ExecutionEvidenceRequirements, ExecutionOverlayCommitment, ProofCompositionMode,
    TransparencyMode, TruthfulnessMode, LOCAL_TRANSPARENCY_PROFILE,
    LSDC_POLICY_COMMITMENT_PROFILE_V1, LSDC_POLICY_COMMITMENT_PROFILE_V2,
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
        LSDC_POLICY_COMMITMENT_PROFILE_V1,
        policy_hash.clone(),
        descriptor.clone(),
        evidence_requirements.clone(),
    )
    .expect("commitment");
    let strict = ExecutionOverlayCommitment::build(
        "agreement-1",
        TruthfulnessMode::Strict,
        LSDC_POLICY_COMMITMENT_PROFILE_V1,
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

#[test]
fn overlay_commitment_hash_changes_when_policy_commitment_profile_changes() {
    let descriptor = sample_descriptor();
    let evidence_requirements = sample_evidence_requirements();
    let policy_hash = Sha256Hash::digest_bytes(b"policy");

    let v1 = ExecutionOverlayCommitment::build(
        "agreement-1",
        TruthfulnessMode::Permissive,
        LSDC_POLICY_COMMITMENT_PROFILE_V1,
        policy_hash.clone(),
        descriptor.clone(),
        evidence_requirements.clone(),
    )
    .expect("v1 commitment");
    let v2 = ExecutionOverlayCommitment::build(
        "agreement-1",
        TruthfulnessMode::Permissive,
        LSDC_POLICY_COMMITMENT_PROFILE_V2,
        policy_hash,
        descriptor,
        evidence_requirements,
    )
    .expect("v2 commitment");

    assert_ne!(v1.agreement_commitment_hash, v2.agreement_commitment_hash);
    assert_eq!(v1.policy_commitment_profile, LSDC_POLICY_COMMITMENT_PROFILE_V1);
    assert_eq!(v2.policy_commitment_profile, LSDC_POLICY_COMMITMENT_PROFILE_V2);
}

#[test]
fn old_overlay_commitments_deserialize_as_v1_profile() {
    let legacy = serde_json::json!({
        "overlay_version": LSDC_EXECUTION_PROTOCOL_VERSION,
        "hash_alg": "sha-256",
        "truthfulness_mode": "permissive",
        "policy_commitment_hash": Sha256Hash::digest_bytes(b"policy"),
        "capability_descriptor_hash": Sha256Hash::digest_bytes(b"capability"),
        "evidence_requirements_hash": Sha256Hash::digest_bytes(b"requirements"),
        "agreement_commitment_hash": Sha256Hash::digest_bytes(b"agreement"),
        "capability_descriptor": sample_descriptor(),
        "evidence_requirements": sample_evidence_requirements()
    });

    let parsed: ExecutionOverlayCommitment =
        serde_json::from_value(legacy).expect("legacy v1 overlay");
    assert_eq!(parsed.policy_commitment_profile, LSDC_POLICY_COMMITMENT_PROFILE_V1);
}
