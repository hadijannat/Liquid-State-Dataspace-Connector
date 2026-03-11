use ::time::OffsetDateTime;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc as RawNitroAttestationDoc;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use coset::{CborSerializable, CoseSign1};
use lsdc_common::crypto::{
    sign_bytes, verify_signature, AppraisalStatus, AttestationDocument, AttestationEvidence,
    AttestationMeasurements, AttestationResult, Sha256Hash,
};
use lsdc_common::error::{LsdcError, Result};
use lsdc_ports::AttestationVerifier;
use ring::{
    digest::{self, SHA256},
    signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED},
};
use std::collections::BTreeMap;
use std::iter::once;
use std::path::Path;
use x509_parser::{
    certificate::X509Certificate,
    oid_registry::OID_SIG_ECDSA_WITH_SHA384,
    pem::parse_x509_pem,
    prelude::*,
    validate::{VecLogger, X509StructureValidator},
};

use lsdc_common::execution_overlay::ExecutionSessionChallenge;

pub(crate) const DEFAULT_ATTESTATION_SECRET: &str = "lsdc-attestation-dev-secret";
const NITRO_PLATFORM_DEV: &str = "aws-nitro-dev";
const NITRO_PLATFORM_LIVE: &str = "aws-nitro-live";
const AWS_NITRO_ROOT_FINGERPRINT_HEX: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";
const MAX_ATTESTATION_AGE_SECONDS: i64 = 300;
const MAX_ATTESTATION_FUTURE_SKEW_SECONDS: i64 = 30;

#[derive(Debug, Clone)]
pub(crate) struct AttestationBinding<'a> {
    pub challenge_nonce_hex: &'a str,
    pub public_key: Option<&'a [u8]>,
    pub user_data_hash: Option<&'a Sha256Hash>,
}

struct AttestationPayload<'a> {
    enclave_id: &'a str,
    platform: &'a str,
    binary_hash: &'a Sha256Hash,
    measurements: &'a AttestationMeasurements,
    nonce: Option<&'a str>,
    public_key: Option<&'a [u8]>,
    user_data_hash: Option<&'a Sha256Hash>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct AwsNitroAttestationVerifier {
    expected_image_sha384_hex: Option<String>,
    trusted_root_fingerprints: Vec<Vec<u8>>,
}

impl AwsNitroAttestationVerifier {
    pub fn new(
        expected_image_sha384_hex: Option<String>,
        trust_bundle_path: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            expected_image_sha384_hex,
            trusted_root_fingerprints: load_trusted_root_fingerprints(trust_bundle_path)?,
        })
    }
}

#[derive(Clone, Debug)]
struct ParsedCert<'a> {
    der: &'a [u8],
    idx: usize,
    x509: X509Certificate<'a>,
}

impl<'a> ParsedCert<'a> {
    fn parse(der: &'a [u8], idx: usize) -> Result<Self> {
        let (_, x509) = X509Certificate::from_der(der).map_err(|err| {
            LsdcError::Attestation(format!("nitro certificate {idx} failed to parse: {err}"))
        })?;
        let mut logger = VecLogger::default();
        if !X509StructureValidator.validate(&x509, &mut logger) {
            return Err(LsdcError::Attestation(format!(
                "nitro certificate {idx} has malformed structure: {logger:?}"
            )));
        }

        Ok(Self { der, idx, x509 })
    }

    fn cn(&'a self) -> Result<&'a str> {
        self.x509
            .subject()
            .iter_common_name()
            .next()
            .ok_or_else(|| {
                LsdcError::Attestation(format!(
                    "nitro certificate {} is missing a common name",
                    self.idx
                ))
            })?
            .as_str()
            .map_err(|err| LsdcError::Attestation(format!("nitro common name malformed: {err}")))
    }

    fn fingerprint(&self) -> Vec<u8> {
        digest::digest(&SHA256, self.der).as_ref().to_vec()
    }

    fn verify(self, parent: Option<&ParsedCert<'_>>, trusted_roots: &[Vec<u8>]) -> Result<Self> {
        let cn = self.cn()?.to_string();
        let algorithm = self.x509.signature_algorithm.oid();
        if algorithm != &OID_SIG_ECDSA_WITH_SHA384 {
            return Err(LsdcError::Attestation(format!(
                "nitro certificate {} ({cn}) has unexpected signature algorithm {algorithm}",
                self.idx
            )));
        }

        match parent {
            Some(parent) => self
                .x509
                .verify_signature(Some(parent.x509.public_key()))
                .map_err(|err| {
                    LsdcError::Attestation(format!(
                        "nitro certificate {} ({cn}) signature verification failed: {err}",
                        self.idx
                    ))
                })?,
            None => {
                let fingerprint = self.fingerprint();
                if !trusted_roots.iter().any(|root| root == &fingerprint) {
                    return Err(LsdcError::Attestation(format!(
                        "nitro root certificate fingerprint {} is not trusted",
                        hex::encode(fingerprint)
                    )));
                }
            }
        }

        Ok(self)
    }

    fn validate_at(self, now: OffsetDateTime) -> Result<Self> {
        let cn = self.cn()?.to_string();
        let not_before = self.x509.validity().not_before.to_datetime();
        let not_after = self.x509.validity().not_after.to_datetime();
        if now < not_before {
            return Err(LsdcError::Attestation(format!(
                "nitro certificate {} ({cn}) is not valid before {not_before}",
                self.idx
            )));
        }
        if now > not_after {
            return Err(LsdcError::Attestation(format!(
                "nitro certificate {} ({cn}) expired at {not_after}",
                self.idx
            )));
        }

        Ok(self)
    }
}

#[derive(Debug)]
struct ParsedNitroDocument {
    module_id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    pcrs: BTreeMap<u16, Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    certificate_chain_pem: Vec<String>,
}

#[derive(Debug, Clone)]
struct NitroMeasurementClaims {
    image_sha384_hex: String,
    pcrs_hex: BTreeMap<u16, String>,
    debug: bool,
}

pub(crate) fn build_attestation_document(
    enclave_id: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<AttestationDocument> {
    build_attestation_document_with_binding(enclave_id, binary_hash, timestamp, None)
}

pub(crate) fn build_attestation_document_with_binding(
    enclave_id: &str,
    binary_hash: &Sha256Hash,
    timestamp: chrono::DateTime<chrono::Utc>,
    binding: Option<AttestationBinding<'_>>,
) -> Result<AttestationDocument> {
    let nonce = binding
        .as_ref()
        .map(|binding| binding.challenge_nonce_hex.to_string());
    let public_key = binding
        .as_ref()
        .and_then(|binding| binding.public_key.map(|bytes| bytes.to_vec()));
    let user_data_hash = binding
        .as_ref()
        .and_then(|binding| binding.user_data_hash.cloned());
    let measurements = AttestationMeasurements {
        image_hash: binary_hash.clone(),
        pcrs: BTreeMap::from([
            (0_u16, binary_hash.to_hex()),
            (
                1_u16,
                Sha256Hash::digest_bytes(enclave_id.as_bytes()).to_hex(),
            ),
            (
                2_u16,
                Sha256Hash::digest_bytes(timestamp.to_rfc3339().as_bytes()).to_hex(),
            ),
        ]),
        debug: false,
    };
    let payload = attestation_payload_bytes(&AttestationPayload {
        enclave_id,
        platform: NITRO_PLATFORM_DEV,
        binary_hash,
        measurements: &measurements,
        nonce: binding.as_ref().map(|binding| binding.challenge_nonce_hex),
        public_key: binding.as_ref().and_then(|binding| binding.public_key),
        user_data_hash: binding.as_ref().and_then(|binding| binding.user_data_hash),
        timestamp,
    })?;
    let document_hash = Sha256Hash::digest_bytes(&payload);
    let signature_hex = sign_bytes(&attestation_secret(), &payload);

    Ok(AttestationDocument {
        enclave_id: enclave_id.to_string(),
        platform: NITRO_PLATFORM_DEV.to_string(),
        binary_hash: binary_hash.clone(),
        measurements,
        nonce,
        public_key,
        user_data_hash,
        document_hash,
        timestamp,
        raw_attestation_document: payload,
        certificate_chain_pem: Vec::new(),
        signature_hex,
    })
}

pub(crate) fn build_aws_nitro_attestation_document(
    expected_image_sha384_hex: Option<&str>,
    raw_attestation_document: &[u8],
    trusted_root_fingerprints: &[Vec<u8>],
) -> Result<AttestationDocument> {
    let parsed =
        parse_and_verify_nitro_document(raw_attestation_document, trusted_root_fingerprints)?;
    let measurements = parse_nitro_measurement_claims(&parsed)?;
    if measurements.debug {
        return Err(LsdcError::Attestation(
            "nitro-live attestation rejected debug-mode zero-PCR measurements".into(),
        ));
    }
    if let Some(expected_image_sha384_hex) = expected_image_sha384_hex {
        if measurements.image_sha384_hex != expected_image_sha384_hex {
            return Err(LsdcError::Attestation(
                "nitro-live attestation image hash does not match the pinned EIF measurement"
                    .into(),
            ));
        }
    }

    let projected_measurements = AttestationMeasurements {
        // Compatibility-only projection for existing APIs. Nitro live decisions use SHA-384 PCRs.
        image_hash: digest_hex_payload(&measurements.image_sha384_hex),
        pcrs: measurements.pcrs_hex.clone(),
        debug: measurements.debug,
    };
    let document_hash = Sha256Hash::digest_bytes(raw_attestation_document);
    let user_data_hash = parsed
        .user_data
        .as_ref()
        .map(|value| as_user_data_hash(value));

    Ok(AttestationDocument {
        enclave_id: parsed.module_id,
        platform: NITRO_PLATFORM_LIVE.into(),
        // Compatibility-only projection for existing APIs. Nitro live decisions use image_sha384.
        binary_hash: digest_hex_payload(&measurements.image_sha384_hex),
        measurements: projected_measurements,
        nonce: parsed.nonce.as_ref().map(hex::encode),
        public_key: parsed.public_key,
        user_data_hash,
        document_hash,
        timestamp: parsed.timestamp,
        raw_attestation_document: raw_attestation_document.to_vec(),
        certificate_chain_pem: parsed.certificate_chain_pem,
        signature_hex: String::new(),
    })
}

pub fn build_aws_nitro_attestation_document_from_bundle(
    expected_image_sha384_hex: Option<&str>,
    raw_attestation_document: &[u8],
    trust_bundle_path: Option<&str>,
) -> Result<AttestationDocument> {
    let trusted_roots = load_trusted_root_fingerprints(trust_bundle_path)?;
    build_aws_nitro_attestation_document(
        expected_image_sha384_hex,
        raw_attestation_document,
        &trusted_roots,
    )
}

pub fn verify_attestation(doc: &AttestationDocument) -> Result<bool> {
    if doc.platform == NITRO_PLATFORM_LIVE {
        return Ok(!doc.raw_attestation_document.is_empty()
            && !doc.measurements.debug
            && doc.measurements.pcrs.contains_key(&0));
    }
    if !doc.platform.starts_with("aws-nitro") {
        return Ok(false);
    }

    let payload = attestation_payload_bytes(&AttestationPayload {
        enclave_id: &doc.enclave_id,
        platform: &doc.platform,
        binary_hash: &doc.binary_hash,
        measurements: &doc.measurements,
        nonce: doc.nonce.as_deref(),
        public_key: doc.public_key.as_deref(),
        user_data_hash: doc.user_data_hash.as_ref(),
        timestamp: doc.timestamp,
    })?;

    Ok(doc.raw_attestation_document == payload
        && doc.document_hash == Sha256Hash::digest_bytes(&payload)
        && doc.measurements.image_hash == doc.binary_hash
        && !doc.measurements.debug
        && verify_signature(&attestation_secret(), &payload, &doc.signature_hex))
}

fn parse_nitro_measurement_claims(parsed: &ParsedNitroDocument) -> Result<NitroMeasurementClaims> {
    let image_sha384_hex = parsed.pcrs.get(&0).map(hex::encode).ok_or_else(|| {
        LsdcError::Attestation(
            "nitro attestation document is missing PCR0/image measurement".into(),
        )
    })?;
    let debug = [0_u16, 1_u16, 2_u16].into_iter().all(|pcr| {
        parsed
            .pcrs
            .get(&pcr)
            .is_none_or(|value| is_zero_bytes(value))
    });

    Ok(NitroMeasurementClaims {
        image_sha384_hex,
        pcrs_hex: parsed
            .pcrs
            .iter()
            .map(|(index, value)| (*index, hex::encode(value)))
            .collect(),
        debug,
    })
}

pub(crate) fn attestation_secret() -> String {
    std::env::var("LSDC_ATTESTATION_SECRET")
        .unwrap_or_else(|_| DEFAULT_ATTESTATION_SECRET.to_string())
}

fn attestation_payload_bytes(payload: &AttestationPayload<'_>) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "enclave_id": payload.enclave_id,
        "platform": payload.platform,
        "binary_hash": payload.binary_hash.to_hex(),
        "measurements": payload.measurements,
        "nonce": payload.nonce,
        "public_key": payload.public_key.map(hex::encode),
        "user_data_hash": payload.user_data_hash.map(Sha256Hash::to_hex),
        "timestamp": payload.timestamp.to_rfc3339(),
    }))
    .map_err(LsdcError::from)
}

#[derive(Default)]
pub struct LocalAttestationVerifier;

impl LocalAttestationVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for LocalAttestationVerifier {
    fn appraise_attestation_evidence(
        &self,
        evidence: &AttestationEvidence,
        challenge: Option<&ExecutionSessionChallenge>,
    ) -> Result<AttestationResult> {
        let doc = &evidence.document;
        let document_valid = verify_attestation(doc)?;
        let freshness_ok = challenge
            .map(|challenge| challenge.expires_at >= chrono::Utc::now())
            .unwrap_or(true);
        let nonce_matches = challenge
            .map(|challenge| doc.nonce.as_deref() == Some(challenge.challenge_nonce_hex.as_str()))
            .unwrap_or(true);
        let public_key_matches = challenge
            .map(|challenge| {
                challenge
                    .expected_attestation_recipient_public_key
                    .as_deref()
                    .is_none_or(|expected| doc.public_key.as_deref() == Some(expected))
            })
            .unwrap_or(true);
        let user_data_matches = challenge
            .map(|challenge| doc.user_data_hash.as_ref() == Some(&challenge.resolved_selector_hash))
            .unwrap_or(true);
        let appraisal = if document_valid
            && freshness_ok
            && nonce_matches
            && public_key_matches
            && user_data_matches
        {
            AppraisalStatus::Accepted
        } else {
            AppraisalStatus::Rejected
        };

        Ok(AttestationResult {
            profile: evidence.evidence_profile.clone(),
            doc_hash: doc.document_hash.clone(),
            session_id: challenge.map(|challenge| challenge.session_id.to_string()),
            nonce: doc.nonce.clone(),
            image_sha384: doc.binary_hash.to_hex(),
            pcrs: doc
                .measurements
                .pcrs
                .iter()
                .map(|(index, value)| (*index as u8, value.clone()))
                .collect(),
            public_key: doc.public_key.clone(),
            user_data_hash: doc.user_data_hash.clone(),
            cert_chain_verified: document_valid,
            freshness_ok,
            appraisal,
        })
    }
}

impl AttestationVerifier for AwsNitroAttestationVerifier {
    fn appraise_attestation_evidence(
        &self,
        evidence: &AttestationEvidence,
        challenge: Option<&ExecutionSessionChallenge>,
    ) -> Result<AttestationResult> {
        let document = build_aws_nitro_attestation_document(
            self.expected_image_sha384_hex.as_deref(),
            &evidence.document.raw_attestation_document,
            &self.trusted_root_fingerprints,
        )?;
        let image_sha384 = document.measurements.pcrs.get(&0).cloned().ok_or_else(|| {
            LsdcError::Attestation(
                "nitro attestation document is missing PCR0/image measurement".into(),
            )
        })?;
        let now = chrono::Utc::now();
        let freshness_ok = match challenge {
            Some(challenge) => {
                now <= challenge.expires_at
                    && document.timestamp <= challenge.expires_at
                    && document.timestamp
                        + chrono::Duration::seconds(MAX_ATTESTATION_FUTURE_SKEW_SECONDS)
                        >= challenge.issued_at
            }
            None => {
                let age = now.signed_duration_since(document.timestamp).num_seconds();
                (-MAX_ATTESTATION_FUTURE_SKEW_SECONDS..=MAX_ATTESTATION_AGE_SECONDS).contains(&age)
            }
        };
        let nonce_matches = challenge
            .map(|challenge| {
                document.nonce.as_deref() == Some(challenge.challenge_nonce_hex.as_str())
            })
            .unwrap_or(true);
        let public_key_matches = challenge
            .map(|challenge| {
                challenge
                    .expected_attestation_recipient_public_key
                    .as_deref()
                    .is_none_or(|expected| document.public_key.as_deref() == Some(expected))
            })
            .unwrap_or(true);
        let user_data_matches = challenge
            .map(|challenge| {
                document.user_data_hash.as_ref() == Some(&challenge.resolved_selector_hash)
            })
            .unwrap_or(true);
        let cert_chain_verified = !document.measurements.debug;
        let appraisal = if cert_chain_verified
            && freshness_ok
            && nonce_matches
            && public_key_matches
            && user_data_matches
        {
            AppraisalStatus::Accepted
        } else {
            AppraisalStatus::Rejected
        };

        Ok(AttestationResult {
            profile: evidence.evidence_profile.clone(),
            doc_hash: document.document_hash,
            session_id: challenge.map(|challenge| challenge.session_id.to_string()),
            nonce: document.nonce,
            image_sha384,
            pcrs: document
                .measurements
                .pcrs
                .iter()
                .map(|(index, value)| (*index as u8, value.clone()))
                .collect(),
            public_key: document.public_key,
            user_data_hash: document.user_data_hash,
            cert_chain_verified,
            freshness_ok,
            appraisal,
        })
    }
}

fn parse_and_verify_nitro_document(
    raw_attestation_document: &[u8],
    trusted_root_fingerprints: &[Vec<u8>],
) -> Result<ParsedNitroDocument> {
    let document = CoseSign1::from_slice(raw_attestation_document).map_err(|err| {
        LsdcError::Attestation(format!("nitro attestation COSE malformed: {err}"))
    })?;
    let payload = document.payload.clone().ok_or_else(|| {
        LsdcError::Attestation("nitro attestation document payload missing".into())
    })?;
    let doc = RawNitroAttestationDoc::from_binary(payload.as_slice()).map_err(|err| {
        LsdcError::Attestation(format!("nitro attestation payload malformed: {err:?}"))
    })?;
    let timestamp =
        chrono::DateTime::from_timestamp_millis(doc.timestamp as i64).ok_or_else(|| {
            LsdcError::Attestation(format!(
                "nitro attestation timestamp {} is invalid",
                doc.timestamp
            ))
        })?;
    let validity_time =
        OffsetDateTime::from_unix_timestamp(timestamp.timestamp()).map_err(|err| {
            LsdcError::Attestation(format!("nitro attestation timestamp invalid: {err}"))
        })?;

    let cert_der = doc.certificate.as_ref().to_vec();
    let cabundle = doc
        .cabundle
        .iter()
        .map(|item| item.as_ref().to_vec())
        .collect::<Vec<_>>();
    let certs = cabundle
        .iter()
        .chain(once(&cert_der))
        .enumerate()
        .map(|(idx, cert)| ParsedCert::parse(cert.as_slice(), idx))
        .collect::<Result<Vec<_>>>()?;
    let leaf = certs
        .into_iter()
        .try_fold::<Option<ParsedCert<'_>>, _, Result<_>>(None, |parent, cert| {
            let cert = cert.verify(parent.as_ref(), trusted_root_fingerprints)?;
            let cert = cert.validate_at(validity_time)?;
            Ok(Some(cert))
        })?
        .ok_or_else(|| LsdcError::Attestation("nitro certificate chain is empty".into()))?;

    let public_key = leaf.x509.public_key().subject_public_key.as_ref();
    document
        .verify_signature(&[], |signature, data| {
            let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key);
            key.verify(data, signature).map_err(|_| {
                LsdcError::Attestation(
                    "nitro attestation COSE signature verification failed".into(),
                )
            })
        })
        .map_err(|err| LsdcError::Attestation(format!("{err}")))?;

    Ok(ParsedNitroDocument {
        module_id: doc.module_id,
        timestamp,
        pcrs: doc
            .pcrs
            .iter()
            .map(|(index, value)| (*index as u16, value.as_ref().to_vec()))
            .collect(),
        public_key: doc.public_key.map(|value| value.as_ref().to_vec()),
        user_data: doc.user_data.map(|value| value.as_ref().to_vec()),
        nonce: doc.nonce.map(|value| value.as_ref().to_vec()),
        certificate_chain_pem: cabundle
            .iter()
            .chain(once(&cert_der))
            .map(|item| der_to_pem(item))
            .collect(),
    })
}

fn load_trusted_root_fingerprints(trust_bundle_path: Option<&str>) -> Result<Vec<Vec<u8>>> {
    match trust_bundle_path {
        Some(path) => {
            let bytes = std::fs::read(Path::new(path)).map_err(|err| {
                LsdcError::Attestation(format!("failed to read nitro trust bundle: {err}"))
            })?;
            let mut roots = Vec::new();
            let mut remaining = bytes.as_slice();
            while let Ok((rest, pem)) = parse_x509_pem(remaining) {
                roots.push(
                    digest::digest(&SHA256, pem.contents.as_slice())
                        .as_ref()
                        .to_vec(),
                );
                if rest.is_empty() {
                    break;
                }
                remaining = rest;
            }
            if roots.is_empty() {
                roots.push(digest::digest(&SHA256, bytes.as_slice()).as_ref().to_vec());
            }
            Ok(roots)
        }
        None => Ok(vec![hex::decode(AWS_NITRO_ROOT_FINGERPRINT_HEX).map_err(
            |err| LsdcError::Attestation(format!("embedded nitro trust bundle invalid: {err}")),
        )?]),
    }
}

fn as_user_data_hash(value: &[u8]) -> Sha256Hash {
    if value.len() == 32 {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(value);
        Sha256Hash(digest)
    } else {
        Sha256Hash::digest_bytes(value)
    }
}

fn digest_hex_payload(hex_value: &str) -> Sha256Hash {
    hex::decode(hex_value)
        .map(|bytes| Sha256Hash::digest_bytes(&bytes))
        .unwrap_or_else(|_| Sha256Hash::digest_bytes(hex_value.as_bytes()))
}

fn is_zero_bytes(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|byte| *byte == 0)
}

fn der_to_pem(der: &[u8]) -> String {
    let body = BASE64_STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_nitro_enclaves_cose::{
        crypto::Openssl, header_map::HeaderMap as AwsHeaderMap, CoseSign1 as AwsCoseSign1,
    };
    use aws_nitro_enclaves_nsm_api::api::{AttestationDoc as RawNitroAttestationDoc, Digest};
    use lsdc_common::execution_overlay::{
        ExecutionSession, ExecutionSessionChallenge, ExecutionSessionState,
    };
    use nitro_attest::builder;
    use openssl::pkey::PKey;
    use std::collections::BTreeMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_challenge(timestamp: chrono::DateTime<chrono::Utc>) -> ExecutionSessionChallenge {
        let session = ExecutionSession {
            session_id: uuid::Uuid::new_v4(),
            agreement_id: "agreement-1".into(),
            agreement_commitment_hash: Sha256Hash::digest_bytes(b"agreement"),
            capability_descriptor_hash: Sha256Hash::digest_bytes(b"capability"),
            evidence_requirements_hash: Sha256Hash::digest_bytes(b"requirements"),
            resolved_selector_hash: Some(Sha256Hash::digest_bytes(b"selector")),
            requester_ephemeral_pubkey: vec![1, 2, 3, 4],
            expected_attestation_recipient_public_key: Some(vec![7, 8, 9, 10]),
            state: ExecutionSessionState::Challenged,
            created_at: timestamp,
            expires_at: Some(timestamp + chrono::Duration::minutes(5)),
        };

        ExecutionSessionChallenge::issue(&session, Sha256Hash::digest_bytes(b"selector"), timestamp)
    }

    fn synthetic_nitro_attestation(
        challenge: &ExecutionSessionChallenge,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> (NamedTempFile, Vec<u8>, String, Vec<u8>) {
        let chain = builder::chain();
        let mut trust_bundle = NamedTempFile::new().unwrap();
        write!(trust_bundle, "{}", chain[0].cert.pem()).unwrap();

        let image_pcr = vec![0x11; 48];
        let recipient_public_key = challenge
            .expected_attestation_recipient_public_key
            .clone()
            .unwrap_or_else(|| vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let document = RawNitroAttestationDoc::new(
            "module-1".into(),
            Digest::SHA384,
            timestamp.timestamp_millis() as u64,
            BTreeMap::from([
                (0, image_pcr.clone()),
                (1, vec![0x22; 48]),
                (2, vec![0x33; 48]),
            ]),
            chain[4].cert.der().to_vec(),
            chain[..4]
                .iter()
                .map(|cert| cert.cert.der().to_vec())
                .collect(),
            Some(challenge.resolved_selector_hash.0.to_vec()),
            Some(hex::decode(&challenge.challenge_nonce_hex).unwrap()),
            Some(recipient_public_key.clone()),
        );
        let payload = document.to_binary();
        let signing_key = PKey::private_key_from_der(&chain[4].keys.serialize_der()).unwrap();
        let cose =
            AwsCoseSign1::new::<Openssl>(&payload, &AwsHeaderMap::new(), &signing_key).unwrap();

        (
            trust_bundle,
            cose.as_bytes(false).unwrap(),
            hex::encode(image_pcr),
            recipient_public_key,
        )
    }

    fn placeholder_attestation_evidence(raw_attestation_document: Vec<u8>) -> AttestationEvidence {
        let placeholder_hash = Sha256Hash::digest_bytes(b"placeholder");
        AttestationEvidence {
            evidence_profile: NITRO_PLATFORM_LIVE.into(),
            document: AttestationDocument {
                enclave_id: "placeholder".into(),
                platform: NITRO_PLATFORM_LIVE.into(),
                binary_hash: placeholder_hash.clone(),
                measurements: AttestationMeasurements {
                    image_hash: placeholder_hash.clone(),
                    pcrs: BTreeMap::new(),
                    debug: false,
                },
                nonce: None,
                public_key: None,
                user_data_hash: None,
                document_hash: Sha256Hash::digest_bytes(&raw_attestation_document),
                timestamp: chrono::Utc::now(),
                raw_attestation_document,
                certificate_chain_pem: Vec::new(),
                signature_hex: String::new(),
            },
        }
    }

    #[test]
    fn test_build_and_verify_attestation() {
        let doc = build_attestation_document(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            chrono::Utc::now(),
        )
        .unwrap();

        assert!(verify_attestation(&doc).unwrap());
    }

    #[test]
    fn test_build_and_appraise_attestation_with_binding() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let doc = build_attestation_document_with_binding(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            timestamp,
            Some(AttestationBinding {
                challenge_nonce_hex: &challenge.challenge_nonce_hex,
                public_key: challenge
                    .expected_attestation_recipient_public_key
                    .as_deref(),
                user_data_hash: Some(&challenge.resolved_selector_hash),
            }),
        )
        .unwrap();

        assert!(verify_attestation(&doc).unwrap());
        assert_eq!(
            doc.nonce.as_deref(),
            Some(challenge.challenge_nonce_hex.as_str())
        );
        assert_eq!(
            doc.public_key.as_deref(),
            challenge
                .expected_attestation_recipient_public_key
                .as_deref()
        );
        assert_eq!(
            doc.user_data_hash.as_ref(),
            Some(&challenge.resolved_selector_hash)
        );

        let result = LocalAttestationVerifier::new()
            .appraise_attestation_evidence(
                &AttestationEvidence {
                    evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
                    document: doc,
                },
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Accepted);
    }

    #[test]
    fn test_appraisal_rejects_attestation_binding_mismatch() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let wrong_selector_hash = Sha256Hash::digest_bytes(b"wrong-selector");
        let doc = build_attestation_document_with_binding(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            timestamp,
            Some(AttestationBinding {
                challenge_nonce_hex: &challenge.challenge_nonce_hex,
                public_key: Some(&[9, 9, 9, 9]),
                user_data_hash: Some(&wrong_selector_hash),
            }),
        )
        .unwrap();

        let result = LocalAttestationVerifier::new()
            .appraise_attestation_evidence(
                &AttestationEvidence {
                    evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
                    document: doc,
                },
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Rejected);
    }

    #[test]
    fn test_appraisal_rejects_attested_recipient_public_key_mismatch() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let doc = build_attestation_document_with_binding(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            timestamp,
            Some(AttestationBinding {
                challenge_nonce_hex: &challenge.challenge_nonce_hex,
                public_key: challenge
                    .expected_attestation_recipient_public_key
                    .as_deref(),
                user_data_hash: Some(&challenge.resolved_selector_hash),
            }),
        )
        .unwrap();
        let mut mismatched_challenge = challenge.clone();
        mismatched_challenge.expected_attestation_recipient_public_key = Some(vec![0, 0, 0, 0]);

        let result = LocalAttestationVerifier::new()
            .appraise_attestation_evidence(
                &AttestationEvidence {
                    evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
                    document: doc,
                },
                Some(&mismatched_challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Rejected);
    }

    #[test]
    fn test_appraisal_accepts_attested_recipient_public_key_without_pin() {
        let timestamp = chrono::Utc::now();
        let mut challenge = sample_challenge(timestamp);
        challenge.expected_attestation_recipient_public_key = None;
        challenge.requester_ephemeral_pubkey = vec![0, 0, 0, 0];

        let doc = build_attestation_document_with_binding(
            "enclave-1",
            &Sha256Hash::digest_bytes(b"binary"),
            timestamp,
            Some(AttestationBinding {
                challenge_nonce_hex: &challenge.challenge_nonce_hex,
                public_key: Some(&[9, 9, 9, 9]),
                user_data_hash: Some(&challenge.resolved_selector_hash),
            }),
        )
        .unwrap();

        let result = LocalAttestationVerifier::new()
            .appraise_attestation_evidence(
                &AttestationEvidence {
                    evidence_profile: "nitro-dev-attestation-evidence-v1".into(),
                    document: doc,
                },
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Accepted);
    }

    #[test]
    fn test_aws_nitro_verifier_accepts_bound_attestation() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (trust_bundle, raw_document, expected_image_sha384_hex, recipient_public_key) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap();

        let result = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Accepted);
        assert!(result.cert_chain_verified);
        assert!(result.freshness_ok);
        assert_eq!(
            result.public_key.as_deref(),
            Some(recipient_public_key.as_slice())
        );
        assert_eq!(
            result.user_data_hash,
            Some(challenge.resolved_selector_hash)
        );
    }

    #[test]
    fn test_aws_nitro_verifier_rejects_attested_recipient_public_key_mismatch() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (trust_bundle, raw_document, expected_image_sha384_hex, _) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap();
        let mut mismatched_challenge = challenge.clone();
        mismatched_challenge.expected_attestation_recipient_public_key = Some(vec![0, 0, 0, 0]);

        let result = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&mismatched_challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Rejected);
    }

    #[test]
    fn test_aws_nitro_verifier_accepts_attested_recipient_public_key_without_pin() {
        let timestamp = chrono::Utc::now();
        let mut challenge = sample_challenge(timestamp);
        challenge.expected_attestation_recipient_public_key = None;
        challenge.requester_ephemeral_pubkey = vec![0, 0, 0, 0];
        let (trust_bundle, raw_document, expected_image_sha384_hex, recipient_public_key) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap();

        let result = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Accepted);
        assert_eq!(
            result.public_key.as_deref(),
            Some(recipient_public_key.as_slice())
        );
    }

    #[test]
    fn test_aws_nitro_verifier_accepts_valid_attestation_without_fixture_pin() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (trust_bundle, raw_document, _expected_image_sha384_hex, recipient_public_key) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let verifier =
            AwsNitroAttestationVerifier::new(None, Some(trust_bundle.path().to_str().unwrap()))
                .unwrap();

        let result = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Accepted);
        assert_eq!(
            result.public_key.as_deref(),
            Some(recipient_public_key.as_slice())
        );
    }

    #[test]
    fn test_aws_nitro_verifier_rejects_bad_signature() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (trust_bundle, mut raw_document, expected_image_sha384_hex, _) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap();
        let last = raw_document.len() - 1;
        raw_document[last] ^= 0x01;

        let err = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&challenge),
            )
            .unwrap_err();

        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn test_aws_nitro_verifier_rejects_wrong_trust_bundle() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (_trust_bundle, raw_document, expected_image_sha384_hex, _) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let mut wrong_bundle = NamedTempFile::new().unwrap();
        write!(wrong_bundle, "not a trusted nitro root").unwrap();
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(wrong_bundle.path().to_str().unwrap()),
        )
        .unwrap();

        let err = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&challenge),
            )
            .unwrap_err();

        assert!(err.to_string().contains("not trusted"));
    }

    #[test]
    fn test_aws_nitro_verifier_rejects_stale_challenge_binding() {
        let document_timestamp = chrono::Utc::now() - chrono::Duration::minutes(10);
        let challenge = sample_challenge(document_timestamp);
        let (trust_bundle, raw_document, expected_image_sha384_hex, _) =
            synthetic_nitro_attestation(&challenge, document_timestamp);
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap();

        let result = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Rejected);
        assert!(!result.freshness_ok);
    }

    #[test]
    fn test_aws_nitro_verifier_rejects_nonce_and_selector_mismatch() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (trust_bundle, raw_document, expected_image_sha384_hex, _) =
            synthetic_nitro_attestation(&challenge, timestamp);
        let verifier = AwsNitroAttestationVerifier::new(
            Some(expected_image_sha384_hex),
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap();
        let mut mismatched_challenge = challenge.clone();
        mismatched_challenge.challenge_nonce_hex = "00".repeat(8);
        mismatched_challenge.resolved_selector_hash = Sha256Hash::digest_bytes(b"wrong-selector");

        let result = verifier
            .appraise_attestation_evidence(
                &placeholder_attestation_evidence(raw_document),
                Some(&mismatched_challenge),
            )
            .unwrap();

        assert_eq!(result.appraisal, AppraisalStatus::Rejected);
    }

    #[test]
    fn test_build_aws_nitro_attestation_document_rejects_wrong_image_hash() {
        let timestamp = chrono::Utc::now();
        let challenge = sample_challenge(timestamp);
        let (trust_bundle, raw_document, _expected_image_sha384_hex, _) =
            synthetic_nitro_attestation(&challenge, timestamp);

        let err = build_aws_nitro_attestation_document_from_bundle(
            Some(&"ff".repeat(48)),
            &raw_document,
            Some(trust_bundle.path().to_str().unwrap()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("pinned EIF measurement"));
    }
}
