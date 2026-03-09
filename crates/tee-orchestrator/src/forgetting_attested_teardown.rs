use lsdc_evidence::AttestedTeardownEvidence;
use lsdc_common::Result;

pub fn verify_attested_teardown(_evidence: &AttestedTeardownEvidence) -> Result<bool> {
    Ok(false)
}
