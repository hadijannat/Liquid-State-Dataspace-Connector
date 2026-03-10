use lsdc_common::crypto::{
    canonical_json_bytes, AppraisalStatus, ProofBundle, SanctionProposal, Sha256Hash,
    TeardownEvidence,
};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use tee_orchestrator::forgetting_dev_signature::verify_dev_deletion_evidence;

pub struct BreachAssessment {
    pub sanction_proposal: Option<SanctionProposal>,
    pub settlement_allowed: bool,
}

pub fn assess_evidence(
    agreement: &ContractAgreement,
    proof_bundle: &ProofBundle,
) -> Result<BreachAssessment> {
    let settlement_allowed = match proof_bundle.teardown_evidence.as_ref() {
        Some(TeardownEvidence::DevDeletion(_)) => {
            verify_dev_deletion_evidence(&proof_bundle.proof_of_forgetting)?
        }
        Some(TeardownEvidence::KeyErasure(evidence)) => {
            let attestation_result_hash = proof_bundle
                .attestation_result
                .as_ref()
                .map(|result| {
                    let payload = serde_json::to_value(result)
                        .and_then(|value| canonical_json_bytes(&value).map_err(Into::into))
                        .map_err(lsdc_common::error::LsdcError::from)?;
                    Ok::<Sha256Hash, lsdc_common::error::LsdcError>(Sha256Hash::digest_bytes(
                        &payload,
                    ))
                })
                .transpose()?;
            proof_bundle.attestation.platform == "aws-nitro-live"
                && proof_bundle
                    .attestation_result
                    .as_ref()
                    .is_some_and(|result| {
                        result.appraisal == AppraisalStatus::Accepted
                            && result.cert_chain_verified
                            && result.freshness_ok
                    })
                && attestation_result_hash.as_ref() == Some(&evidence.attestation_result_hash)
        }
        Some(TeardownEvidence::AttestedTeardown(_)) => false,
        None if proof_bundle.attestation.platform == "aws-nitro-live" => false,
        None => verify_dev_deletion_evidence(&proof_bundle.proof_of_forgetting)?,
    };
    let sanction_proposal = (!settlement_allowed).then(|| SanctionProposal {
        subject_id: agreement.consumer_id.clone(),
        agreement_id: agreement.agreement_id.0.clone(),
        reason: "execution teardown evidence verification failed; settlement must remain blocked"
            .into(),
        approval_required: true,
        evidence_hash: proof_bundle.job_audit_hash.clone(),
    });

    Ok(BreachAssessment {
        sanction_proposal,
        settlement_allowed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsdc_common::crypto::{
        AttestationDocument, AttestationMeasurements, AttestationResult, EvidenceClass,
        ExecutionEvidenceBundle, ProofOfForgetting, ProvenanceReceipt,
    };
    use lsdc_common::dsp::EvidenceRequirement;
    use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};
    use lsdc_common::odrl::ast::PolicyId;
    use tee_orchestrator::forgetting::build_key_erasure_evidence;

    fn sample_agreement() -> ContractAgreement {
        ContractAgreement {
            agreement_id: PolicyId("agreement-live".into()),
            asset_id: "asset-1".into(),
            provider_id: "did:web:provider".into(),
            consumer_id: "did:web:consumer".into(),
            odrl_policy: serde_json::json!({ "permission": [] }),
            policy_hash: "policy".into(),
            evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
            liquid_policy: LiquidPolicyIr {
                transport_guard: TransportGuard {
                    allow_read: true,
                    allow_transfer: true,
                    packet_cap: None,
                    byte_cap: None,
                    allowed_regions: vec!["EU".into()],
                    valid_until: None,
                    protocol: lsdc_common::dsp::TransportProtocol::Udp,
                    session_port: Some(31337),
                },
                transform_guard: TransformGuard {
                    allow_anonymize: true,
                    allowed_purposes: vec!["analytics".into()],
                    required_ops: Vec::new(),
                },
                runtime_guard: RuntimeGuard {
                    delete_after_seconds: Some(60),
                    evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                    approval_required: false,
                },
            },
        }
    }

    fn sample_live_attestation_document() -> AttestationDocument {
        AttestationDocument {
            enclave_id: "enc-live".into(),
            platform: "aws-nitro-live".into(),
            binary_hash: Sha256Hash::digest_bytes(b"binary"),
            measurements: AttestationMeasurements {
                image_hash: Sha256Hash::digest_bytes(b"binary"),
                pcrs: std::collections::BTreeMap::from([(0, "deadbeef".into())]),
                debug: false,
            },
            nonce: Some("aa".repeat(16)),
            public_key: Some(vec![1, 2, 3, 4]),
            user_data_hash: Some(Sha256Hash::digest_bytes(b"selector")),
            document_hash: Sha256Hash::digest_bytes(b"document"),
            timestamp: chrono::Utc::now(),
            raw_attestation_document: vec![1, 2, 3],
            certificate_chain_pem: Vec::new(),
            signature_hex: String::new(),
        }
    }

    fn sample_live_proof_bundle(include_teardown: bool) -> ProofBundle {
        let attestation = sample_live_attestation_document();
        let attestation_result = AttestationResult {
            profile: "aws-nitro-live".into(),
            doc_hash: attestation.document_hash.clone(),
            session_id: Some("session-1".into()),
            nonce: attestation.nonce.clone(),
            image_sha384: "11".repeat(48),
            pcrs: std::collections::BTreeMap::from([(0, "11".repeat(48))]),
            public_key: attestation.public_key.clone(),
            user_data_hash: attestation.user_data_hash.clone(),
            cert_chain_verified: true,
            freshness_ok: true,
            appraisal: AppraisalStatus::Accepted,
        };
        let attestation_result_hash = Sha256Hash::digest_bytes(
            &canonical_json_bytes(&serde_json::to_value(&attestation_result).unwrap()).unwrap(),
        );
        let teardown_evidence = include_teardown.then(|| {
            let mut evidence = build_key_erasure_evidence(
                "session-1",
                &attestation_result_hash,
                chrono::Utc::now(),
                EvidenceClass::Attested,
            )
            .unwrap();
            evidence.released_key_id = "kms-key-1".into();
            TeardownEvidence::KeyErasure(evidence)
        });
        let execution_bundle = ExecutionEvidenceBundle {
            attestation_evidence: lsdc_common::crypto::AttestationEvidence {
                evidence_profile: "aws-nitro-live".into(),
                document: attestation.clone(),
            },
            provenance_receipt: ProvenanceReceipt {
                agreement_id: "agreement-live".into(),
                input_hash: Sha256Hash::digest_bytes(b"input"),
                output_hash: Sha256Hash::digest_bytes(b"output"),
                policy_hash: Sha256Hash::digest_bytes(b"policy"),
                transform_manifest_hash: Sha256Hash::digest_bytes(b"manifest"),
                prior_receipt_hash: None,
                agreement_commitment_hash: None,
                session_id: None,
                challenge_nonce_hash: None,
                selector_hash: None,
                attestation_result_hash: None,
                capability_commitment_hash: None,
                transparency_statement_hash: None,
                parent_receipt_hashes: Vec::new(),
                recursion_depth: 0,
                receipt_kind: Default::default(),
                receipt_hash: Sha256Hash::digest_bytes(b"receipt"),
                proof_backend: lsdc_common::execution::ProofBackend::DevReceipt,
                receipt_format_version: "receipt/v1".into(),
                proof_method_id: "dev-receipt".into(),
                receipt_bytes: b"receipt".to_vec(),
                timestamp: chrono::Utc::now(),
            },
            attestation_result: Some(attestation_result),
            teardown_evidence,
            transparency_receipt_hash: None,
            evidence_root_hash: Sha256Hash::digest_bytes(b"evidence-root"),
            job_audit_hash: Sha256Hash::digest_bytes(b"audit"),
        };
        let mut proof_bundle = execution_bundle.into_legacy_proof_bundle();
        proof_bundle.proof_of_forgetting = ProofOfForgetting {
            attestation,
            destruction_timestamp: chrono::Utc::now(),
            data_hash: Sha256Hash::digest_bytes(b"input"),
            proof_hash: Sha256Hash::digest_bytes(b"forgetting"),
            signature_hex: "invalid-dev-signature".into(),
        };
        proof_bundle
    }

    #[test]
    fn test_live_key_erasure_teardown_allows_settlement() {
        let assessment = assess_evidence(&sample_agreement(), &sample_live_proof_bundle(true))
            .unwrap();

        assert!(assessment.settlement_allowed);
        assert!(assessment.sanction_proposal.is_none());
    }

    #[test]
    fn test_live_missing_teardown_blocks_settlement() {
        let assessment = assess_evidence(&sample_agreement(), &sample_live_proof_bundle(false))
            .unwrap();

        assert!(!assessment.settlement_allowed);
        assert!(assessment.sanction_proposal.is_some());
    }
}
