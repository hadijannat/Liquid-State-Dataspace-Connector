use crate::attestation::verify_attestation;
use lsdc_common::crypto::{
    sign_bytes, verify_signature, ErasureMode, EvidenceClass, KeyErasureEvidence,
    ProofOfForgetting, Sha256Hash,
};
use lsdc_common::error::{LsdcError, Result};
#[cfg(test)]
use std::sync::{Mutex, MutexGuard, OnceLock};

pub(crate) const DEFAULT_FORGETTING_SECRET: &str = "lsdc-forgetting-dev-secret";
const FORGETTING_SECRET_ENV: &str = "LSDC_FORGETTING_SECRET";
const ALLOW_DEV_DEFAULTS_ENV: &str = "LSDC_ALLOW_DEV_DEFAULTS";

pub fn build_proof_of_forgetting(
    attestation: lsdc_common::crypto::AttestationDocument,
    destruction_timestamp: chrono::DateTime<chrono::Utc>,
    data_hash: &Sha256Hash,
) -> Result<ProofOfForgetting> {
    let payload = forgetting_payload_bytes(&attestation, destruction_timestamp, data_hash)?;
    let proof_hash = Sha256Hash::digest_bytes(&payload);
    let signature_hex = sign_bytes(&forgetting_secret()?, &payload);

    Ok(ProofOfForgetting {
        attestation,
        destruction_timestamp,
        data_hash: data_hash.clone(),
        proof_hash,
        signature_hex,
    })
}

pub fn verify_proof_of_forgetting(proof: &ProofOfForgetting) -> Result<bool> {
    let payload = forgetting_payload_bytes(
        &proof.attestation,
        proof.destruction_timestamp,
        &proof.data_hash,
    )?;
    let attestation_valid = verify_attestation(&proof.attestation)?;

    Ok(attestation_valid
        && proof.proof_hash == Sha256Hash::digest_bytes(&payload)
        && verify_signature(&forgetting_secret()?, &payload, &proof.signature_hex))
}

pub fn build_key_erasure_evidence(
    session_id: &str,
    attestation_result_hash: &Sha256Hash,
    teardown_timestamp: chrono::DateTime<chrono::Utc>,
    evidence_class: EvidenceClass,
) -> Result<KeyErasureEvidence> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "session_id": session_id,
        "attestation_result_hash": attestation_result_hash.to_hex(),
        "teardown_timestamp": teardown_timestamp.to_rfc3339(),
        "evidence_class": evidence_class,
    }))
    .map_err(LsdcError::from)?;
    let evidence_hash = Sha256Hash::digest_bytes(&payload);

    Ok(KeyErasureEvidence {
        session_id: session_id.to_string(),
        attestation_result_hash: attestation_result_hash.clone(),
        released_key_id: format!("local-key-{session_id}"),
        erasure_mode: ErasureMode::SessionTeardown,
        teardown_timestamp,
        evidence_class,
        evidence_hash,
    })
}

pub(crate) fn forgetting_secret() -> Result<String> {
    resolve_forgetting_secret(
        std::env::var(FORGETTING_SECRET_ENV).ok(),
        allow_dev_defaults(),
    )
}

pub(crate) fn validate_forgetting_secret() -> Result<()> {
    forgetting_secret().map(|_| ())
}

fn allow_dev_defaults() -> bool {
    matches!(std::env::var(ALLOW_DEV_DEFAULTS_ENV).as_deref(), Ok("1"))
}

fn resolve_forgetting_secret(
    explicit_secret: Option<String>,
    allow_dev_defaults: bool,
) -> Result<String> {
    if let Some(secret) = explicit_secret.filter(|secret| !secret.trim().is_empty()) {
        return Ok(secret);
    }

    if allow_dev_defaults {
        return Ok(DEFAULT_FORGETTING_SECRET.to_string());
    }

    Err(LsdcError::Attestation(format!(
        "{FORGETTING_SECRET_ENV} must be set unless {ALLOW_DEV_DEFAULTS_ENV}=1"
    )))
}

#[cfg(test)]
pub(crate) fn env_lock_for_tests() -> MutexGuard<'static, ()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn forgetting_payload_bytes(
    attestation: &lsdc_common::crypto::AttestationDocument,
    destruction_timestamp: chrono::DateTime<chrono::Utc>,
    data_hash: &Sha256Hash,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": attestation.enclave_id,
        "attestation_hash": attestation.document_hash.to_hex(),
        "destruction_timestamp": destruction_timestamp.to_rfc3339(),
        "data_hash": data_hash.to_hex(),
    }))
    .map_err(LsdcError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::build_attestation_document;

    #[test]
    fn test_resolve_forgetting_secret_rejects_missing_secret_without_dev_defaults() {
        let err = resolve_forgetting_secret(None, false).unwrap_err();
        assert!(err
            .to_string()
            .contains("LSDC_FORGETTING_SECRET must be set unless LSDC_ALLOW_DEV_DEFAULTS=1"));
    }

    #[test]
    fn test_resolve_forgetting_secret_rejects_blank_secret_without_dev_defaults() {
        let err = resolve_forgetting_secret(Some("".into()), false).unwrap_err();
        assert!(err
            .to_string()
            .contains("LSDC_FORGETTING_SECRET must be set unless LSDC_ALLOW_DEV_DEFAULTS=1"));
    }

    #[test]
    fn test_build_and_verify_forgetting_proof() {
        let _guard = env_lock_for_tests();
        let old_allow_dev_defaults = std::env::var("LSDC_ALLOW_DEV_DEFAULTS").ok();
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
        let attestation = build_attestation_document(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            chrono::Utc::now(),
        )
        .unwrap();
        let proof = build_proof_of_forgetting(
            attestation,
            chrono::Utc::now(),
            &Sha256Hash::digest_bytes(b"input"),
        )
        .unwrap();
        let verification = verify_proof_of_forgetting(&proof).unwrap();

        match old_allow_dev_defaults {
            Some(value) => std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", value),
            None => std::env::remove_var("LSDC_ALLOW_DEV_DEFAULTS"),
        }
        assert!(verification);
    }

    #[test]
    fn test_rejects_forgetting_proof_with_invalid_attestation() {
        let _guard = env_lock_for_tests();
        let old_allow_dev_defaults = std::env::var("LSDC_ALLOW_DEV_DEFAULTS").ok();
        std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", "1");
        let attestation = build_attestation_document(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            chrono::Utc::now(),
        )
        .unwrap();
        let mut proof = build_proof_of_forgetting(
            attestation,
            chrono::Utc::now(),
            &Sha256Hash::digest_bytes(b"input"),
        )
        .unwrap();
        proof.attestation.signature_hex = "tampered".into();
        let verification = verify_proof_of_forgetting(&proof).unwrap();

        match old_allow_dev_defaults {
            Some(value) => std::env::set_var("LSDC_ALLOW_DEV_DEFAULTS", value),
            None => std::env::remove_var("LSDC_ALLOW_DEV_DEFAULTS"),
        }
        assert!(!verification);
    }
}
