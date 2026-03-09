use chrono::{Duration, Utc};
use control_plane_store::Store;
use lsdc_common::crypto::{
    AttestationDocument, AttestationMeasurements, MetricsWindow, PriceDecision, PricingAuditContext,
    ProofBundle, ProofOfForgetting, ProvenanceReceipt, SanctionProposal, Sha256Hash, ShapleyValue,
};
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement};
use lsdc_common::execution::{
    ActualExecutionProfile, PolicyExecutionClassification, PricingMode, ProofBackend, TeeBackend,
    TransportBackend, TransportSelector,
};
use lsdc_common::liquid::{
    CsvTransformManifest, CsvTransformOp, CsvTransformOpKind, LiquidPolicyIr, RuntimeGuard,
    TransformGuard, TransportGuard, TransportProtocol,
};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_ports::{
    EnforcementHandle, EnforcementIdentity, EnforcementRuntimeStatus, EnforcementStatus,
    ResolvedTransportGuard, TrainingMetrics,
};
use lsdc_service_types::{LineageJobRecord, LineageJobRequest, LineageJobResult, LineageJobState};
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn test_set_job_result_dual_writes_legacy_and_canonical_evidence_tables() {
    let db_path = temp_db_path("dual-write");
    let store = Store::new(db_path.to_str().unwrap()).unwrap();
    let agreement = sample_agreement();
    let job_id = "job-dual-write";

    store
        .insert_job(&LineageJobRecord {
            job_id: job_id.into(),
            agreement_id: agreement.agreement_id.0.clone(),
            state: LineageJobState::Pending,
            request: sample_request(agreement.clone()),
            result: None,
            error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .unwrap();

    let result = sample_result(&agreement);
    store
        .set_job_result(job_id, &agreement.agreement_id.0, &result)
        .unwrap();

    let connection = Connection::open(&db_path).unwrap();
    let evidence_rows = {
        let mut statement = connection
            .prepare(
                "SELECT evidence_kind, schema_version, anchor_hash
                 FROM evidence_records
                 WHERE job_id = ?1
                 ORDER BY evidence_kind ASC",
            )
            .unwrap();
        statement
            .query_map([job_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    };

    assert_eq!(
        evidence_rows,
        vec![
            (
                "price_decision".into(),
                1,
                Some(result.price_decision.signature_hex.clone()),
            ),
            (
                "proof_bundle".into(),
                1,
                Some(result.proof_bundle.job_audit_hash.to_hex()),
            ),
            (
                "sanction_proposal".into(),
                1,
                result
                    .sanction_proposal
                    .as_ref()
                    .map(|proposal| proposal.evidence_hash.to_hex()),
            ),
        ]
    );

    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM proof_bundles WHERE job_id = ?1", [job_id], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM price_decisions WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sanction_proposals WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn test_list_restartable_jobs_returns_only_pending_and_running_in_order() {
    let db_path = temp_db_path("restartable");
    let store = Store::new(db_path.to_str().unwrap()).unwrap();
    let agreement = sample_agreement();
    let base_time = Utc::now();

    for (job_id, state, offset_seconds) in [
        ("job-pending", LineageJobState::Pending, 0),
        ("job-running", LineageJobState::Running, 5),
        ("job-succeeded", LineageJobState::Succeeded, 10),
        ("job-failed", LineageJobState::Failed, 15),
    ] {
        store
            .insert_job(&LineageJobRecord {
                job_id: job_id.into(),
                agreement_id: agreement.agreement_id.0.clone(),
                state,
                request: sample_request(agreement.clone()),
                result: None,
                error: None,
                created_at: base_time + Duration::seconds(offset_seconds),
                updated_at: base_time + Duration::seconds(offset_seconds),
            })
            .unwrap();
    }

    let restartable = store.list_restartable_jobs().unwrap();
    let ordered_ids: Vec<_> = restartable.iter().map(|record| record.job_id.as_str()).collect();
    let ordered_ifaces: Vec<_> = restartable
        .iter()
        .map(|record| record.request.iface.as_deref())
        .collect();

    assert_eq!(ordered_ids, vec!["job-pending", "job-running"]);
    assert_eq!(ordered_ifaces, vec![Some("lo0"), Some("lo0")]);

    let _ = std::fs::remove_file(db_path);
}

fn temp_db_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "lsdc-{label}-{}-{}.sqlite",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    path
}

fn sample_agreement() -> ContractAgreement {
    ContractAgreement {
        agreement_id: PolicyId("agreement-store-test".into()),
        asset_id: "asset-1".into(),
        provider_id: "did:web:provider".into(),
        consumer_id: "did:web:consumer".into(),
        odrl_policy: json!({"uid": "agreement-store-test"}),
        policy_hash: "policy-hash".into(),
        evidence_requirements: vec![
            EvidenceRequirement::ProvenanceReceipt,
            EvidenceRequirement::ProofOfForgetting,
            EvidenceRequirement::PriceApproval,
        ],
        liquid_policy: LiquidPolicyIr {
            transport_guard: TransportGuard {
                allow_read: true,
                allow_transfer: true,
                packet_cap: Some(100),
                byte_cap: Some(2048),
                allowed_regions: vec!["EU".into()],
                valid_until: Some(Utc::now() + Duration::hours(1)),
                protocol: TransportProtocol::Udp,
                session_port: Some(31_337),
            },
            transform_guard: TransformGuard {
                allow_anonymize: true,
                allowed_purposes: vec!["analytics".into()],
                required_ops: vec![CsvTransformOpKind::RedactColumns],
            },
            runtime_guard: RuntimeGuard {
                delete_after_seconds: Some(3600),
                evidence_requirements: vec![
                    EvidenceRequirement::ProvenanceReceipt,
                    EvidenceRequirement::ProofOfForgetting,
                    EvidenceRequirement::PriceApproval,
                ],
                approval_required: true,
            },
        },
    }
}

fn sample_request(agreement: ContractAgreement) -> LineageJobRequest {
    let now = Utc::now();
    LineageJobRequest {
        agreement,
        iface: Some("lo0".into()),
        input_csv_utf8: "id,email\n1,a@example.com\n".into(),
        manifest: CsvTransformManifest {
            dataset_id: "dataset-1".into(),
            purpose: "analytics".into(),
            ops: vec![CsvTransformOp::RedactColumns {
                columns: vec!["email".into()],
                replacement: "[redacted]".into(),
            }],
        },
        current_price: 10.0,
        metrics: TrainingMetrics {
            loss_with_dataset: 0.2,
            loss_without_dataset: 0.3,
            accuracy_with_dataset: 0.9,
            accuracy_without_dataset: 0.8,
            model_run_id: "run-1".into(),
            metrics_window_started_at: now,
            metrics_window_ended_at: now,
        },
        prior_receipt: None,
    }
}

fn sample_result(agreement: &ContractAgreement) -> LineageJobResult {
    let now = Utc::now();
    let resolved_transport = ResolvedTransportGuard {
        selector: TransportSelector {
            protocol: TransportProtocol::Udp,
            port: 31_337,
        },
        enforcement: EnforcementIdentity {
            agreement_id: agreement.agreement_id.0.clone(),
            enforcement_key: 7,
        },
        packet_cap: Some(100),
        byte_cap: Some(2048),
        expires_at: Some(now + Duration::hours(1)),
    };

    LineageJobResult {
        agreement_id: agreement.agreement_id.0.clone(),
        actual_execution_profile: ActualExecutionProfile {
            transport_backend: TransportBackend::Simulated,
            proof_backend: ProofBackend::DevReceipt,
            tee_backend: TeeBackend::NitroDev,
            pricing_mode: PricingMode::Advisory,
        },
        enforcement_handle: EnforcementHandle {
            id: agreement.agreement_id.0.clone(),
            interface: "lo0".into(),
            session_port: 31_337,
            active: false,
            transport_selector: Some(TransportSelector {
                protocol: TransportProtocol::Udp,
                port: 31_337,
            }),
            resolved_transport: Some(resolved_transport.clone()),
            runtime: Some(EnforcementRuntimeStatus {
                transport_backend: TransportBackend::Simulated,
                rule_active: false,
                kernel_program_attached: false,
            }),
        },
        enforcement_status: EnforcementStatus::Revoked,
        policy_execution: Some(PolicyExecutionClassification::classify_agreement(
            agreement,
            TransportBackend::Simulated,
            ProofBackend::DevReceipt,
            TeeBackend::NitroDev,
        )),
        resolved_transport: Some(resolved_transport),
        enforcement_runtime: Some(EnforcementRuntimeStatus {
            transport_backend: TransportBackend::Simulated,
            rule_active: false,
            kernel_program_attached: false,
        }),
        transformed_csv_utf8: "id,email\n1,[redacted]\n".into(),
        proof_bundle: sample_proof_bundle(agreement, now),
        price_decision: sample_price_decision(agreement, now),
        sanction_proposal: Some(SanctionProposal {
            subject_id: agreement.consumer_id.clone(),
            agreement_id: agreement.agreement_id.0.clone(),
            reason: "manual review".into(),
            approval_required: true,
            evidence_hash: Sha256Hash::digest_bytes(b"sanction"),
        }),
        settlement_allowed: true,
        completed_at: now,
    }
}

fn sample_proof_bundle(agreement: &ContractAgreement, now: chrono::DateTime<chrono::Utc>) -> ProofBundle {
    let attestation = sample_attestation(now);
    let provenance_receipt = ProvenanceReceipt {
        agreement_id: agreement.agreement_id.0.clone(),
        input_hash: Sha256Hash::digest_bytes(b"input"),
        output_hash: Sha256Hash::digest_bytes(b"output"),
        policy_hash: Sha256Hash::digest_bytes(agreement.policy_hash.as_bytes()),
        transform_manifest_hash: Sha256Hash::digest_bytes(b"manifest"),
        prior_receipt_hash: None,
        receipt_hash: Sha256Hash::digest_bytes(b"receipt"),
        proof_backend: ProofBackend::DevReceipt,
        receipt_format_version: "lsdc.dev.receipt.v1".into(),
        proof_method_id: "dev.csv_transform.v1".into(),
        receipt_bytes: b"receipt".to_vec(),
        timestamp: now,
    };

    ProofBundle {
        proof_backend: ProofBackend::DevReceipt,
        receipt_format_version: "lsdc.dev.receipt.v1".into(),
        proof_method_id: "dev.csv_transform.v1".into(),
        prior_receipt_hash: None,
        raw_receipt_bytes: b"receipt".to_vec(),
        provenance_receipt,
        attestation: attestation.clone(),
        proof_of_forgetting: ProofOfForgetting {
            attestation,
            destruction_timestamp: now,
            data_hash: Sha256Hash::digest_bytes(b"input"),
            proof_hash: Sha256Hash::digest_bytes(b"forgetting"),
            signature_hex: "forget-signature".into(),
        },
        job_audit_hash: Sha256Hash::digest_bytes(b"audit"),
    }
}

fn sample_attestation(now: chrono::DateTime<chrono::Utc>) -> AttestationDocument {
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, "pcr0".into());

    AttestationDocument {
        enclave_id: "enclave-1".into(),
        platform: "nitro-dev".into(),
        binary_hash: Sha256Hash::digest_bytes(b"binary"),
        measurements: AttestationMeasurements {
            image_hash: Sha256Hash::digest_bytes(b"image"),
            pcrs,
            debug: false,
        },
        document_hash: Sha256Hash::digest_bytes(b"document"),
        timestamp: now,
        raw_attestation_document: b"doc".to_vec(),
        certificate_chain_pem: vec!["cert".into()],
        signature_hex: "attest-signature".into(),
    }
}

fn sample_price_decision(
    agreement: &ContractAgreement,
    now: chrono::DateTime<chrono::Utc>,
) -> PriceDecision {
    PriceDecision {
        agreement_id: agreement.agreement_id.0.clone(),
        dataset_id: "dataset-1".into(),
        original_price: 10.0,
        adjusted_price: 22.5,
        approval_required: true,
        pricing_mode: PricingMode::Advisory,
        shapley_value: ShapleyValue {
            dataset_id: "dataset-1".into(),
            transformed_asset_hash: "asset-hash".into(),
            marginal_contribution: 0.18,
            confidence: 0.91,
            algorithm_version: "heuristic_marginal_v0".into(),
            audit_context: PricingAuditContext {
                dataset_id: "dataset-1".into(),
                transformed_asset_hash: "asset-hash".into(),
                proof_receipt_hash: Some(Sha256Hash::digest_bytes(b"receipt")),
                model_run_id: "run-1".into(),
                metrics_window: MetricsWindow {
                    started_at: now,
                    ended_at: now,
                },
            },
        },
        signed_by: "pricing-oracle".into(),
        signature_hex: "price-signature".into(),
    }
}
