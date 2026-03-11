use chrono::{Duration, Utc};
use control_plane_store::Store;
use lsdc_common::crypto::{
    AppraisalStatus, AttestationDocument, AttestationEvidence, AttestationMeasurements,
    AttestationResult, MetricsWindow, PriceDecision, PricingAuditContext, ProofBundle,
    ProofOfForgetting, ProvenanceReceipt, ReceiptKind, SanctionProposal, Sha256Hash, ShapleyValue,
};
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement};
use lsdc_common::execution::{
    ActualExecutionProfile, PolicyExecutionClassification, PricingMode, ProofBackend, TeeBackend,
    TransportBackend, TransportSelector,
};
use lsdc_common::execution_overlay::{
    AdvertisedProfiles, CapabilitySupportLevel, ExecutionCapabilityDescriptor,
    ExecutionEvidenceRequirements, ExecutionSession, ExecutionSessionChallenge,
    ExecutionSessionState, ExecutionStatement, ExecutionStatementKind, ProofCompositionMode,
    TransparencyMode, TransparencyReceipt, TruthfulnessMode as OverlayTruthfulnessMode,
    LOCAL_TRANSPARENCY_PROFILE, LSDC_EXECUTION_PROTOCOL_VERSION,
};
use lsdc_common::liquid::{
    CsvTransformManifest, CsvTransformOp, CsvTransformOpKind, LiquidPolicyIr, RuntimeGuard,
    TransformGuard, TransportGuard, TransportProtocol,
};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_common::runtime_model::{
    DependencyType, EvidenceDag, EvidenceEdge, EvidenceNode, NodeStatus,
};
use lsdc_ports::{
    EnforcementHandle, EnforcementIdentity, EnforcementRuntimeStatus, EnforcementStatus,
    ResolvedTransportGuard, TrainingMetrics,
};
use lsdc_service_types::{
    ExecutionOverlaySummary, LineageJobRecord, LineageJobRequest, LineageJobResult, LineageJobState,
};
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
            .query_row(
                "SELECT COUNT(*) FROM proof_bundles WHERE job_id = ?1",
                [job_id],
                |row| { row.get::<_, i64>(0) }
            )
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
    let ordered_ids: Vec<_> = restartable
        .iter()
        .map(|record| record.job_id.as_str())
        .collect();
    let ordered_ifaces: Vec<_> = restartable
        .iter()
        .map(|record| record.request.iface.as_deref())
        .collect();

    assert_eq!(ordered_ids, vec!["job-pending", "job-running"]);
    assert_eq!(ordered_ifaces, vec![Some("lo0"), Some("lo0")]);

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn test_claim_stale_jobs_claims_each_job_once() {
    let db_path = temp_db_path("claim-stale");
    let store = Store::new(db_path.to_str().unwrap()).unwrap();
    let agreement = sample_agreement();
    let stale_at = Utc::now() - Duration::minutes(5);
    let cutoff = stale_at + Duration::minutes(1);
    let claimed_at = cutoff + Duration::seconds(1);
    let job_id = "job-stale-1";

    store
        .insert_job(&LineageJobRecord {
            job_id: job_id.into(),
            agreement_id: agreement.agreement_id.0.clone(),
            state: LineageJobState::Pending,
            request: sample_request(agreement.clone()),
            result: None,
            error: None,
            created_at: stale_at - Duration::minutes(1),
            updated_at: stale_at,
        })
        .unwrap();

    let claimed = store.claim_stale_jobs(cutoff, claimed_at).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].job_id, job_id);
    assert_eq!(claimed[0].request.iface.as_deref(), Some("lo0"));

    let claimed_again = store
        .claim_stale_jobs(cutoff, claimed_at + Duration::seconds(1))
        .unwrap();
    assert!(claimed_again.is_empty());

    let persisted = store.get_job(job_id).unwrap().unwrap();
    assert_eq!(persisted.state, LineageJobState::Running);
    assert_eq!(persisted.updated_at, claimed_at);

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn test_execution_overlay_session_and_evidence_round_trip() {
    let db_path = temp_db_path("execution-overlay-round-trip");
    let store = Store::new(db_path.to_str().unwrap()).unwrap();
    let overlay = sample_execution_overlay();
    let session = sample_execution_session(&overlay);
    let challenge = sample_execution_challenge(&session);
    let attestation_evidence = sample_attestation_evidence();
    let attestation_result = sample_attestation_result(&session);
    let dag = sample_evidence_dag();
    let statement = sample_execution_statement(&session, &dag);
    let receipt = sample_transparency_receipt(&statement);

    store
        .upsert_agreement_overlay(&session.agreement_id, &overlay)
        .unwrap();
    let persisted_overlay = store
        .get_agreement_overlay(&session.agreement_id)
        .unwrap()
        .expect("expected persisted execution overlay");
    assert_eq!(
        persisted_overlay.agreement_commitment_hash,
        overlay.agreement_commitment_hash
    );

    store
        .upsert_execution_session(&session, Some(&challenge))
        .unwrap();
    store
        .save_attestation_evidence_and_result(
            &session.session_id.to_string(),
            &ExecutionSession {
                state: ExecutionSessionState::AttestationVerified,
                ..session.clone()
            },
            &challenge,
            &attestation_evidence,
            &attestation_result,
        )
        .unwrap();

    let (persisted_session, persisted_challenge, persisted_attestation) = store
        .get_execution_session(&session.session_id.to_string())
        .unwrap()
        .expect("expected persisted execution session");
    assert_eq!(persisted_session.session_id, session.session_id);
    let persisted_challenge = persisted_challenge.expect("challenge");
    assert_eq!(
        persisted_challenge.challenge_nonce_hash,
        challenge.challenge_nonce_hash
    );
    assert_eq!(
        persisted_challenge.expected_attestation_public_key_hash,
        challenge.expected_attestation_public_key_hash
    );
    assert_eq!(
        persisted_attestation.expect("attestation").doc_hash,
        attestation_result.doc_hash
    );

    let connection = Connection::open(&db_path).unwrap();
    let persisted_pin_hash = connection
        .query_row(
            "SELECT expected_attestation_public_key_hash
             FROM session_challenges
             WHERE challenge_id = ?1",
            [challenge.challenge_id.to_string()],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap();
    assert_eq!(
        persisted_pin_hash,
        challenge
            .expected_attestation_public_key_hash
            .as_ref()
            .map(Sha256Hash::to_hex)
    );

    store
        .persist_evidence_dag("job-overlay-round-trip", &session.agreement_id, &dag)
        .unwrap();
    let persisted_dag = store
        .get_evidence_dag("job-overlay-round-trip")
        .unwrap()
        .expect("expected persisted evidence dag");
    assert_eq!(persisted_dag.root_hash, dag.root_hash);
    assert_eq!(persisted_dag.nodes.len(), dag.nodes.len());

    store
        .insert_transparency_receipt(&statement, &receipt)
        .unwrap();
    let persisted_receipt = store
        .get_transparency_receipt(&statement.statement_id)
        .unwrap()
        .expect("expected transparency receipt");
    assert_eq!(persisted_receipt.root_hash, receipt.root_hash);

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
        execution_bindings: None,
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
        session_id: None,
        evidence_root_hash: None,
        transparency_receipt_hash: None,
        settlement_allowed: true,
        completed_at: now,
    }
}

fn sample_proof_bundle(
    agreement: &ContractAgreement,
    now: chrono::DateTime<chrono::Utc>,
) -> ProofBundle {
    let attestation = sample_attestation(now);
    let provenance_receipt = ProvenanceReceipt {
        agreement_id: agreement.agreement_id.0.clone(),
        input_hash: Sha256Hash::digest_bytes(b"input"),
        output_hash: Sha256Hash::digest_bytes(b"output"),
        policy_hash: Sha256Hash::digest_bytes(agreement.policy_hash.as_bytes()),
        transform_manifest_hash: Sha256Hash::digest_bytes(b"manifest"),
        prior_receipt_hash: None,
        agreement_commitment_hash: None,
        session_id: None,
        challenge_nonce_hash: None,
        selector_hash: None,
        attestation_result_hash: None,
        capability_commitment_hash: None,
        transparency_statement_hash: None,
        parent_receipt_hashes: vec![],
        recursion_depth: 0,
        receipt_kind: ReceiptKind::Transform,
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
        attestation_result: None,
        teardown_evidence: None,
        key_erasure_evidence: None,
        evidence_root_hash: None,
        transparency_receipt_hash: None,
        job_audit_hash: Sha256Hash::digest_bytes(b"audit"),
    }
}

fn sample_attestation_evidence() -> AttestationEvidence {
    AttestationEvidence {
        evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
        document: sample_attestation(Utc::now()),
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
        nonce: None,
        public_key: None,
        user_data_hash: None,
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

fn sample_execution_overlay() -> ExecutionOverlaySummary {
    let support_summary = BTreeMap::from([
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
    ]);
    let capability_descriptor = ExecutionCapabilityDescriptor {
        overlay_version: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
        truthfulness_default: OverlayTruthfulnessMode::Permissive,
        advertised_profiles: AdvertisedProfiles {
            attestation_profile: "nitro-dev-attestation-result-v1".into(),
            proof_profile: "dev-receipt-dag-v1".into(),
            transparency_profile: LOCAL_TRANSPARENCY_PROFILE.into(),
            teardown_profile: "dev-deletion-v1".into(),
        },
        support: support_summary.clone(),
    };
    let evidence_requirements = ExecutionEvidenceRequirements {
        challenge_nonce_required: true,
        selector_hash_binding_required: true,
        transparency_registration_mode: TransparencyMode::Required,
        proof_composition_mode: ProofCompositionMode::Dag,
    };
    ExecutionOverlaySummary {
        overlay_version: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
        capability_descriptor_hash: capability_descriptor.canonical_hash().unwrap(),
        agreement_commitment_hash: Sha256Hash::digest_bytes(b"agreement-commitment"),
        truthfulness_mode: lsdc_common::profile::TruthfulnessMode::Permissive,
        evidence_requirements_hash: evidence_requirements.canonical_hash().unwrap(),
        support_summary,
    }
}

fn sample_execution_session(overlay: &ExecutionOverlaySummary) -> ExecutionSession {
    ExecutionSession {
        session_id: uuid::Uuid::new_v4(),
        agreement_id: "agreement-store-test".into(),
        agreement_commitment_hash: overlay.agreement_commitment_hash.clone(),
        capability_descriptor_hash: overlay.capability_descriptor_hash.clone(),
        evidence_requirements_hash: overlay.evidence_requirements_hash.clone(),
        resolved_selector_hash: Some(Sha256Hash::digest_bytes(b"selector")),
        requester_ephemeral_pubkey: vec![1, 2, 3, 4],
        expected_attestation_public_key_hash: Some(Sha256Hash::digest_bytes(
            b"attested-public-key",
        )),
        state: ExecutionSessionState::Created,
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + Duration::minutes(15)),
    }
}

fn sample_execution_challenge(session: &ExecutionSession) -> ExecutionSessionChallenge {
    ExecutionSessionChallenge::issue(
        session,
        session
            .resolved_selector_hash
            .clone()
            .expect("resolved selector hash should exist"),
        Utc::now(),
    )
}

fn sample_attestation_result(session: &ExecutionSession) -> AttestationResult {
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, "pcr0".into());
    AttestationResult {
        profile: "nitro-dev-attestation-result-v1".into(),
        doc_hash: Sha256Hash::digest_bytes(b"attestation-doc"),
        session_id: Some(session.session_id.to_string()),
        nonce: Some("feedbeef".into()),
        image_sha384: "image-sha384".into(),
        pcrs,
        public_key: Some(vec![7, 8, 9]),
        user_data_hash: Some(Sha256Hash::digest_bytes(b"user-data")),
        cert_chain_verified: true,
        freshness_ok: true,
        appraisal: AppraisalStatus::Accepted,
    }
}

fn sample_evidence_dag() -> EvidenceDag {
    let nodes = vec![
        EvidenceNode {
            node_id: "statement-1".into(),
            kind: ExecutionStatementKind::ProofReceiptRegistered,
            canonical_hash: Sha256Hash::digest_bytes(b"statement-1"),
            status: NodeStatus::Verified,
            payload_json: serde_json::json!({
                "agreement_id": "agreement-store-test",
                "input_hash": Sha256Hash::digest_bytes(b"input"),
                "output_hash": Sha256Hash::digest_bytes(b"output"),
                "policy_hash": Sha256Hash::digest_bytes(b"policy"),
                "transform_manifest_hash": Sha256Hash::digest_bytes(b"manifest"),
                "prior_receipt_hash": null,
                "agreement_commitment_hash": null,
                "session_id": null,
                "challenge_nonce_hash": null,
                "selector_hash": null,
                "attestation_result_hash": null,
                "capability_commitment_hash": null,
                "transparency_statement_hash": null,
                "parent_receipt_hashes": [],
                "recursion_depth": 0,
                "receipt_kind": "transform",
                "receipt_hash": Sha256Hash::digest_bytes(b"receipt"),
                "proof_backend": "dev_receipt",
                "receipt_format_version": "lsdc.dev.receipt.v1",
                "proof_method_id": "dev.csv_transform.v1",
                "receipt_bytes": [114, 101, 99, 101, 105, 112, 116],
                "timestamp": Utc::now(),
            }),
        },
        EvidenceNode {
            node_id: "statement-2".into(),
            kind: ExecutionStatementKind::TransparencyAnchored,
            canonical_hash: Sha256Hash::digest_bytes(b"statement-2"),
            status: NodeStatus::Anchored,
            payload_json: serde_json::json!({"root": "hash"}),
        },
    ];
    let edges = vec![EvidenceEdge {
        from_node_id: "statement-1".into(),
        to_node_id: "statement-2".into(),
        dependency_type: DependencyType::AnchoredBy,
    }];
    EvidenceDag::new(nodes, edges).unwrap()
}

fn sample_execution_statement(session: &ExecutionSession, dag: &EvidenceDag) -> ExecutionStatement {
    ExecutionStatement {
        statement_id: "statement-2".into(),
        statement_hash: Sha256Hash::digest_bytes(b"statement-2"),
        agreement_id: session.agreement_id.clone(),
        session_id: Some(session.session_id),
        statement_kind: ExecutionStatementKind::SettlementRecorded,
        payload_hash: dag.root_hash.clone(),
        parent_hashes: dag
            .nodes
            .iter()
            .map(|node| node.canonical_hash.clone())
            .collect(),
        producer: "store-test".into(),
        profile: LSDC_EXECUTION_PROTOCOL_VERSION.into(),
        created_at: Utc::now(),
    }
    .with_computed_hash()
    .unwrap()
}

fn sample_transparency_receipt(statement: &ExecutionStatement) -> TransparencyReceipt {
    TransparencyReceipt {
        statement_id: statement.statement_id.clone(),
        receipt_profile: LOCAL_TRANSPARENCY_PROFILE.into(),
        log_id: "local-log".into(),
        statement_hash: statement.statement_hash.clone(),
        leaf_index: 0,
        tree_size: 1,
        root_hash: Sha256Hash::digest_bytes(b"transparency-root"),
        inclusion_path: vec![],
        consistency_proof: vec![],
        signature_hex: "signature".into(),
        signed_at: Utc::now(),
    }
}
