use lsdc_policy::{
    runtime_capability_semantics, PolicyClauseStatus, ProofBackend, RuntimeCapabilityContext,
    RuntimeCapabilityLevel, RuntimeProofCompositionMode, TeeBackend, TransportBackend,
};

#[test]
fn runtime_capability_semantics_reports_recursive_risc0_consistently() {
    let semantics = runtime_capability_semantics(RuntimeCapabilityContext {
        transport_backend: TransportBackend::Simulated,
        proof_backend: ProofBackend::RiscZero,
        tee_backend: TeeBackend::NitroLive,
        dev_backends_allowed: false,
        attested_key_release_supported: true,
        attested_teardown_supported: true,
    });

    assert_eq!(
        semantics.proof_composition_mode,
        RuntimeProofCompositionMode::Recursive
    );
    assert_eq!(
        semantics.support["proof.risc0_recursive"],
        RuntimeCapabilityLevel::Implemented
    );
    assert_eq!(
        semantics.advertised_profiles.proof_profile,
        "risc0-recursive-dag-v1"
    );

    let recursive_rollups = semantics
        .classification
        .clauses
        .iter()
        .find(|clause| clause.clause == "proof.recursive_rollups")
        .expect("proof.recursive_rollups classification");
    assert_eq!(recursive_rollups.status, PolicyClauseStatus::Executable);
    assert_eq!(
        recursive_rollups.detail.as_deref(),
        Some("recursive transform chaining and receipt composition are implemented for the risc0 backend")
    );
}
