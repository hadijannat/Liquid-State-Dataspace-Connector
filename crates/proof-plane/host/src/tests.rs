use crate::DevReceiptProofEngine;
#[cfg(feature = "risc0")]
use crate::Risc0ProofEngine;
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement};
#[cfg(feature = "risc0")]
use lsdc_common::error::LsdcError;
use lsdc_common::liquid::CsvTransformManifest;
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::odrl::parser::lower_policy;
use lsdc_ports::ProofEngine;
use std::sync::Once;

fn ensure_test_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
    });
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
        .execute_csv_transform(&agreement, &input, &manifest, None)
        .await
        .unwrap();
    let second = engine
        .execute_csv_transform(
            &agreement,
            first.output_csv.as_slice(),
            &manifest,
            Some(&first.receipt),
        )
        .await
        .unwrap();

    assert!(engine
        .verify_chain(&[first.receipt, second.receipt])
        .await
        .unwrap());
}

#[cfg(feature = "risc0")]
#[tokio::test]
async fn test_risc0_single_hop_proves_and_verifies_transform() {
    let engine = Risc0ProofEngine::new();
    let expected = lsdc_common::fixtures::read_bytes("proof/expected_redacted.csv").unwrap();
    let result = engine
        .execute_csv_transform(
            &agreement(),
            &lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            &manifest(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.output_csv, expected);
    assert!(engine.verify_receipt(&result.receipt).await.unwrap());
}

#[cfg(feature = "risc0")]
#[tokio::test]
async fn test_risc0_matches_dev_receipt_output_for_same_manifest() {
    ensure_test_env();
    let input = lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap();
    let agreement = agreement();
    let manifest = manifest();

    let dev_output = DevReceiptProofEngine::new()
        .unwrap()
        .execute_csv_transform(&agreement, &input, &manifest, None)
        .await
        .unwrap()
        .output_csv;
    let risc0_output = Risc0ProofEngine::new()
        .execute_csv_transform(&agreement, &input, &manifest, None)
        .await
        .unwrap()
        .output_csv;

    assert_eq!(dev_output, risc0_output);
}

#[cfg(feature = "risc0")]
#[tokio::test]
async fn test_risc0_rejects_recursive_receipts() {
    ensure_test_env();
    let agreement = agreement();
    let manifest = manifest();
    let prior_receipt = DevReceiptProofEngine::new()
        .unwrap()
        .execute_csv_transform(
            &agreement,
            &lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            &manifest,
            None,
        )
        .await
        .unwrap()
        .receipt;

    let err = Risc0ProofEngine::new()
        .execute_csv_transform(
            &agreement,
            &lsdc_common::fixtures::read_bytes("csv/lineage_input.csv").unwrap(),
            &manifest,
            Some(&prior_receipt),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        LsdcError::Unsupported(message)
            if message == "recursive proving not implemented for risc0 backend"
    ));
}
