use lsdc_common::crypto::{ProofBundle, SanctionProposal};
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
    let forgetting_valid = verify_dev_deletion_evidence(&proof_bundle.proof_of_forgetting)?;
    let sanction_proposal = (!forgetting_valid).then(|| SanctionProposal {
        subject_id: agreement.consumer_id.clone(),
        agreement_id: agreement.agreement_id.0.clone(),
        reason: "dev deletion evidence verification failed; settlement must remain blocked".into(),
        approval_required: true,
        evidence_hash: proof_bundle.job_audit_hash.clone(),
    });

    Ok(BreachAssessment {
        sanction_proposal,
        settlement_allowed: forgetting_valid,
    })
}
