use lsdc_common::Result;
use lsdc_evidence::AttestedTeardownEvidence;

pub fn verify_attested_teardown(_evidence: &AttestedTeardownEvidence) -> Result<bool> {
    Ok(false)
}
