use crate::DevReceiptProofEngine;
#[cfg(feature = "risc0")]
use crate::Risc0ProofEngine;
use lsdc_common::crypto::{ProvenanceReceipt, ReceiptKind, Sha256Hash};
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement};
#[cfg(feature = "risc0")]
use lsdc_common::error::LsdcError;
#[cfg(not(feature = "risc0"))]
use lsdc_common::execution_overlay::ExecutionStatementKind;
#[cfg(feature = "risc0")]
use lsdc_common::execution_overlay::{
    AdvertisedProfiles, CapabilitySupportLevel, ExecutionCapabilityDescriptor,
    ExecutionEvidenceRequirements, ExecutionOverlayCommitment, ExecutionSession,
    ExecutionSessionChallenge, ExecutionSessionState, ExecutionStatementKind, ProofCompositionMode,
    TransparencyMode, TruthfulnessMode,
};
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::odrl::parser::lower_policy;
use lsdc_common::runtime_model::{
    DependencyType, EvidenceDag, EvidenceEdge, EvidenceNode, NodeStatus,
};
#[cfg(feature = "risc0")]
use lsdc_ports::ExecutionBindings;
use lsdc_ports::{CompositionContext, ProofEngine};
#[cfg(feature = "risc0")]
use std::collections::BTreeMap;
#[cfg(feature = "risc0")]
use std::future::Future;
use std::sync::Once;

fn ensure_test_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
        std::env::set_var("RISC0_DEV_MODE", "1");
    });
}

#[cfg(feature = "risc0")]
fn run_risc0_test<F>(name: &str, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    ensure_test_env();
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(future);
        })
        .unwrap()
        .join()
        .unwrap();
}

fn agreement() -> ContractAgreement {
    let odrl_policy: serde_json::Value =
        lsdc_common::fixtures::read_json("odrl/supported_policy.json").unwrap();
    let evidence_requirements = vec![EvidenceRequirement::ProvenanceReceipt];

    ContractAgreement {
        agreement_id: PolicyId("agreement-proof".into()),
        asset_id: "asset-1".into(),
        provider_id: "did:web:provider".into(),
        consumer_id: "did:web:consumer".into(),
        odrl_policy: odrl_policy.clone(),
        policy_hash: "policy-hash".into(),
        evidence_requirements: evidence_requirements.clone(),
        liquid_policy: lower_policy(&odrl_policy, &evidence_requirements).unwrap(),
    }
}

fn manifest() -> CsvTransformManifest {
    lsdc_common::fixtures::read_json("liquid/analytics_manifest.json").unwrap()
}

#[cfg(feature = "risc0")]
fn recursive_execution_bindings() -> ExecutionBindings {
    let agreement = agreement();
    let now = chrono::Utc::now();
    let selector_hash = Sha256Hash::digest_bytes(b"selector-binding");
    let capability_descriptor = ExecutionCapabilityDescriptor {
        overlay_version: "lsdc-execution-overlay/v1".into(),
        truthfulness_default: TruthfulnessMode::Strict,
        advertised_profiles: AdvertisedProfiles {
            attestation_profile: "nitro-dev-attestation-result-v1".into(),
            proof_profile: "risc0-recursive-dag-v1".into(),
            transparency_profile: "local".into(),
            teardown_profile: "dev-deletion-v1".into(),
        },
        support: BTreeMap::from([(
            "proof.risc0_recursive".into(),
            CapabilitySupportLevel::Implemented,
        )]),
    };
    let evidence_requirements = ExecutionEvidenceRequirements {
        challenge_nonce_required: true,
        selector_hash_binding_required: true,
        transparency_registration_mode: TransparencyMode::Required,
        proof_composition_mode: ProofCompositionMode::Recursive,
    };
    let overlay_commitment = ExecutionOverlayCommitment::build(
        &agreement.agreement_id.0,
        TruthfulnessMode::Strict,
        Sha256Hash::digest_bytes(b"policy"),
        capability_descriptor,
        evidence_requirements,
    )
    .unwrap();
    let session = ExecutionSession {
        session_id: "00000000-0000-0000-0000-000000000123".parse().unwrap(),
        agreement_id: agreement.agreement_id.0,
        agreement_commitment_hash: overlay_commitment.agreement_commitment_hash.clone(),
        capability_descriptor_hash: overlay_commitment.capability_descriptor_hash.clone(),
        evidence_requirements_hash: overlay_commitment.evidence_requirements_hash.clone(),
        resolved_selector_hash: Some(selector_hash.clone()),
        requester_ephemeral_pubkey: vec![1, 2, 3, 4],
        expected_attestation_public_key_hash: None,
        state: ExecutionSessionState::Challenged,
        created_at: now,
        expires_at: Some(now + chrono::Duration::minutes(5)),
    };
    let challenge = ExecutionSessionChallenge::issue(&session, selector_hash, now);

    ExecutionBindings {
        overlay_commitment,
        session,
        challenge: Some(challenge),
        resolved_transport: None,
        attestation_result_hash: Some(Sha256Hash::digest_bytes(b"stable-attestation-binding")),
    }
}

#[tokio::test]
async fn test_proves_and_verifies_transform() {
    ensure_test_env();
    let engine = DevReceiptProofEngine::new().unwrap();
    let expected = lsdc_common::fixtures::read_bytes("proof/expected_redacted.csv").unwrap();
    let result = engine
        .execute_csv_transform(
            &agreement(),
            &lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            &manifest(),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.output_csv, expected);
    assert!(engine.verify_receipt(&result.receipt).await.unwrap());
}

#[tokio::test]
async fn test_verifies_receipt_chain() {
    ensure_test_env();
    let engine = DevReceiptProofEngine::new().unwrap();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(
            &agreement,
            first.output_csv.as_slice(),
            &manifest,
            Some(&first.receipt),
            None,
        )
        .await
        .unwrap();

    assert!(engine
        .verify_chain(&[first.receipt, second.receipt])
        .await
        .unwrap());
}

fn proof_node(node_id: &str, receipt: &ProvenanceReceipt) -> EvidenceNode {
    EvidenceNode {
        node_id: node_id.into(),
        kind: ExecutionStatementKind::ProofReceiptRegistered,
        canonical_hash: receipt.receipt_hash.clone(),
        status: NodeStatus::Verified,
        payload_json: serde_json::to_value(receipt).unwrap(),
    }
}

#[tokio::test]
async fn test_composes_receipts_and_rejects_tampered_dag_node() {
    ensure_test_env();
    let engine = DevReceiptProofEngine::new().unwrap();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(&agreement, input.as_slice(), &manifest, None, None)
        .await
        .unwrap();

    let composed = engine
        .compose_receipts(
            &[first.receipt.clone(), second.receipt.clone()],
            CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(composed.receipt_kind, ReceiptKind::Composition);
    assert_eq!(composed.recursion_depth, 1);
    assert_eq!(
        composed.parent_receipt_hashes,
        vec![
            first.receipt.receipt_hash.clone(),
            second.receipt.receipt_hash.clone()
        ]
    );

    let dag = EvidenceDag::new(
        vec![
            proof_node("proof-1", &first.receipt),
            proof_node("proof-2", &second.receipt),
            proof_node("proof-composed", &composed),
        ],
        vec![
            EvidenceEdge {
                from_node_id: "proof-1".into(),
                to_node_id: "proof-composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: "proof-2".into(),
                to_node_id: "proof-composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
        ],
    )
    .unwrap();
    assert!(engine.verify_receipt_dag(&dag).await.unwrap());

    let mut tampered = composed.clone();
    tampered.receipt_hash = Sha256Hash::digest_bytes(b"tampered-receipt");
    let tampered_dag =
        EvidenceDag::new(vec![proof_node("proof-tampered", &tampered)], Vec::new()).unwrap();
    assert!(!engine.verify_receipt_dag(&tampered_dag).await.unwrap());
}

#[cfg(feature = "risc0")]
async fn assert_risc0_single_hop_proves_and_verifies_transform() {
    let engine = Risc0ProofEngine::new();
    let expected = lsdc_common::fixtures::read_bytes("proof/expected_redacted.csv").unwrap();
    let result = engine
        .execute_csv_transform(
            &agreement(),
            &lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            &manifest(),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.output_csv, expected);
    assert_eq!(
        result.receipt.proof_method_id,
        "risc0.csv_transform_recursive.v1"
    );
    assert!(engine.verify_receipt(&result.receipt).await.unwrap());
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_single_hop_proves_and_verifies_transform() {
    run_risc0_test(
        "risc0-single-hop",
        assert_risc0_single_hop_proves_and_verifies_transform(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_matches_dev_receipt_output_for_same_manifest() {
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let agreement = agreement();
    let manifest = manifest();

    let dev_output = DevReceiptProofEngine::new()
        .unwrap()
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap()
        .output_csv;
    let risc0_output = Risc0ProofEngine::new()
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap()
        .output_csv;

    assert_eq!(dev_output, risc0_output);
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_matches_dev_receipt_output_for_same_manifest() {
    run_risc0_test(
        "risc0-matches-dev",
        assert_risc0_matches_dev_receipt_output_for_same_manifest(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_recursive_transform_succeeds() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();

    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(
            &agreement,
            &first.output_csv,
            &manifest,
            Some(&first.receipt),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        first.receipt.proof_method_id,
        "risc0.csv_transform_recursive.v1"
    );
    assert_eq!(
        second.receipt.proof_method_id,
        "risc0.csv_transform_recursive.v1"
    );
    assert_eq!(
        second.receipt.prior_receipt_hash,
        Some(first.receipt.receipt_hash.clone())
    );
    assert!(engine
        .verify_chain(&[first.receipt.clone(), second.receipt.clone()])
        .await
        .unwrap());
    assert!(engine.verify_receipt(&second.receipt).await.unwrap());
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_recursive_transform_succeeds() {
    run_risc0_test(
        "risc0-recursive-transform",
        assert_risc0_recursive_transform_succeeds(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_recursive_transform_preserves_non_null_bindings() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let bindings = recursive_execution_bindings();

    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, Some(&bindings))
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(
            &agreement,
            &first.output_csv,
            &manifest,
            Some(&first.receipt),
            Some(&bindings),
        )
        .await
        .unwrap();

    assert_eq!(
        second.receipt.session_id,
        Some(bindings.session.session_id.to_string())
    );
    assert_eq!(
        second.receipt.challenge_nonce_hash,
        bindings
            .challenge
            .as_ref()
            .map(|challenge| challenge.challenge_nonce_hash.clone())
    );
    assert_eq!(
        second.receipt.selector_hash,
        bindings
            .challenge
            .as_ref()
            .map(|challenge| challenge.resolved_selector_hash.clone())
    );
    assert_eq!(
        second.receipt.attestation_result_hash,
        bindings.attestation_result_hash
    );
    assert_eq!(
        second.receipt.capability_commitment_hash,
        Some(
            bindings
                .overlay_commitment
                .capability_descriptor_hash
                .clone()
        )
    );
    assert!(engine
        .verify_chain(&[first.receipt.clone(), second.receipt.clone()])
        .await
        .unwrap());
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_recursive_transform_preserves_non_null_bindings() {
    run_risc0_test(
        "risc0-recursive-bindings",
        assert_risc0_recursive_transform_preserves_non_null_bindings(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_rejects_dev_receipt_as_recursive_parent() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let prior = DevReceiptProofEngine::new()
        .unwrap()
        .execute_csv_transform(
            &agreement,
            &lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            &manifest,
            None,
            None,
        )
        .await
        .unwrap();

    let err = engine
        .execute_csv_transform(
            &agreement,
            prior.output_csv.as_slice(),
            &manifest,
            Some(&prior.receipt),
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        LsdcError::Unsupported(message)
            if message == "risc0 recursive proving only supports prior and child receipts produced by the risc0 backend"
    ));
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_rejects_dev_receipt_as_recursive_parent() {
    run_risc0_test(
        "risc0-reject-dev-parent",
        assert_risc0_rejects_dev_receipt_as_recursive_parent(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_rejects_tampered_recursive_receipts() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();

    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(
            &agreement,
            &first.output_csv,
            &manifest,
            Some(&first.receipt),
            None,
        )
        .await
        .unwrap();

    let mut tampered_parent = second.receipt.clone();
    tampered_parent.parent_receipt_hashes[0] = Sha256Hash::digest_bytes(b"bad-parent");
    match engine.verify_receipt(&tampered_parent).await {
        Ok(valid) => assert!(!valid),
        Err(_) => {}
    }

    let mut tampered_depth = second.receipt.clone();
    tampered_depth.recursion_depth += 1;
    match engine.verify_receipt(&tampered_depth).await {
        Ok(valid) => assert!(!valid),
        Err(_) => {}
    }

    let mut tampered_method = second.receipt.clone();
    tampered_method.proof_method_id = "risc0.csv_transform.v1".into();
    match engine.verify_receipt(&tampered_method).await {
        Ok(valid) => assert!(!valid),
        Err(_) => {}
    }

    let mut tampered_bytes = second.receipt.clone();
    tampered_bytes.receipt_bytes[0] ^= 0x01;
    match engine.verify_receipt(&tampered_bytes).await {
        Ok(valid) => assert!(!valid),
        Err(_) => {}
    }
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_rejects_tampered_recursive_receipts() {
    run_risc0_test(
        "risc0-tampered-recursive",
        assert_risc0_rejects_tampered_recursive_receipts(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_composes_receipts_and_rejects_tampered_dag_node() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let mut second_manifest = manifest.clone();
    second_manifest.dataset_id = "dataset-proof-compose-sibling".into();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(&agreement, input.as_slice(), &second_manifest, None, None)
        .await
        .unwrap();

    let composed = engine
        .compose_receipts(
            &[first.receipt.clone(), second.receipt.clone()],
            CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(composed.receipt_kind, ReceiptKind::Composition);
    assert_eq!(composed.proof_method_id, "risc0.receipt_composition.v1");
    assert_eq!(composed.recursion_depth, 1);
    assert_eq!(
        composed.parent_receipt_hashes,
        vec![
            first.receipt.receipt_hash.clone(),
            second.receipt.receipt_hash.clone()
        ]
    );

    let dag = EvidenceDag::new(
        vec![
            proof_node("proof-1", &first.receipt),
            proof_node("proof-2", &second.receipt),
            proof_node("proof-composed", &composed),
        ],
        vec![
            EvidenceEdge {
                from_node_id: "proof-1".into(),
                to_node_id: "proof-composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: "proof-2".into(),
                to_node_id: "proof-composed".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
        ],
    )
    .unwrap();
    assert!(engine.verify_receipt_dag(&dag).await.unwrap());

    let mut tampered = composed.clone();
    tampered.parent_receipt_hashes.swap(0, 1);
    let tampered_dag = EvidenceDag::new(
        vec![
            proof_node("proof-1", &first.receipt),
            proof_node("proof-2", &second.receipt),
            proof_node("proof-tampered", &tampered),
        ],
        vec![
            EvidenceEdge {
                from_node_id: "proof-1".into(),
                to_node_id: "proof-tampered".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
            EvidenceEdge {
                from_node_id: "proof-2".into(),
                to_node_id: "proof-tampered".into(),
                dependency_type: DependencyType::DerivedFrom,
            },
        ],
    )
    .unwrap();
    assert!(!engine.verify_receipt_dag(&tampered_dag).await.unwrap());
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_composes_receipts_and_rejects_tampered_dag_node() {
    run_risc0_test(
        "risc0-compose",
        assert_risc0_composes_receipts_and_rejects_tampered_dag_node(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_multi_hop_composition_can_be_parent() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(&agreement, input.as_slice(), &manifest, None, None)
        .await
        .unwrap();
    let third = engine
        .execute_csv_transform(&agreement, input.as_slice(), &manifest, None, None)
        .await
        .unwrap();
    let composed = engine
        .compose_receipts(
            &[first.receipt.clone(), second.receipt.clone()],
            CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();
    let recursive = engine
        .compose_receipts(
            &[composed.clone(), third.receipt.clone()],
            CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(recursive.proof_method_id, "risc0.receipt_composition.v1");
    assert_eq!(
        recursive.parent_receipt_hashes,
        vec![
            composed.receipt_hash.clone(),
            third.receipt.receipt_hash.clone()
        ]
    );
    assert_eq!(recursive.recursion_depth, 2);
    assert!(engine.verify_receipt(&recursive).await.unwrap());
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_multi_hop_composition_can_be_parent() {
    run_risc0_test(
        "risc0-multi-hop",
        assert_risc0_multi_hop_composition_can_be_parent(),
    );
}

#[cfg(feature = "risc0")]
async fn assert_risc0_verify_chain_rejects_composition_nodes() {
    let engine = Risc0ProofEngine::new();
    let agreement = agreement();
    let manifest = manifest();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let first = engine
        .execute_csv_transform(&agreement, &input, &manifest, None, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(&agreement, input.as_slice(), &manifest, None, None)
        .await
        .unwrap();
    let composed = engine
        .compose_receipts(
            &[first.receipt.clone(), second.receipt.clone()],
            CompositionContext {
                agreement_id: agreement.agreement_id.0.clone(),
                agreement_commitment_hash: None,
                session_id: None,
                selector_hash: None,
                capability_commitment_hash: None,
            },
        )
        .await
        .unwrap();

    assert!(!engine
        .verify_chain(&[first.receipt, composed])
        .await
        .unwrap());
}

#[cfg(feature = "risc0")]
#[test]
fn test_risc0_verify_chain_rejects_composition_nodes() {
    run_risc0_test(
        "risc0-chain-rejects-composition",
        assert_risc0_verify_chain_rejects_composition_nodes(),
    );
}
