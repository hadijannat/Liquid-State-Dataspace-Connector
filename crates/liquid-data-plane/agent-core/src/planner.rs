use crate::projection::{selector_key, CompiledPolicy};
use chrono::Utc;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::TransportSelector;
use lsdc_common::odrl::ast::PolicyId;

/// Compile a negotiated agreement into the executable transport guard.
pub fn compile_agreement(agreement: &ContractAgreement) -> Result<CompiledPolicy> {
    let transport = &agreement.liquid_policy.transport_guard;

    if let Some(valid_until) = transport.valid_until {
        if valid_until <= Utc::now() {
            return Err(LsdcError::PolicyCompile(
                "agreement transport guard is already expired".into(),
            ));
        }
    }

    if !transport.allow_read && !transport.allow_transfer {
        return Err(LsdcError::PolicyCompile(
            "agreement does not allow transport admission".into(),
        ));
    }

    let session_port = transport
        .session_port
        .unwrap_or_else(|| agreement_id_to_session_port(&agreement.agreement_id));
    let transport_selector = resolved_selector(agreement, session_port);

    Ok(CompiledPolicy {
        agreement_id: agreement.agreement_id.0.clone(),
        enforcement_key: agreement_id_to_enforcement_key(&agreement.agreement_id),
        selector_key: selector_key(&transport_selector),
        transport_selector,
        max_packets: transport.packet_cap,
        max_bytes: transport.byte_cap,
        expires_at: transport.valid_until,
    })
}

fn resolved_selector(agreement: &ContractAgreement, port: u16) -> TransportSelector {
    TransportSelector {
        protocol: agreement.liquid_policy.transport_guard.protocol,
        port,
    }
}

fn agreement_id_to_enforcement_key(agreement_id: &PolicyId) -> u32 {
    let bytes = agreement_id.0.as_bytes();
    let mut hash: u32 = 2_166_136_261;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn agreement_id_to_session_port(agreement_id: &PolicyId) -> u16 {
    let key = agreement_id_to_enforcement_key(agreement_id);
    let port = 20_000 + (key % 40_000);
    port as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
    use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};

    fn make_test_agreement() -> ContractAgreement {
        ContractAgreement {
            agreement_id: PolicyId("agreement-1".into()),
            asset_id: "asset-1".into(),
            provider_id: "did:web:provider".into(),
            consumer_id: "did:web:consumer".into(),
            odrl_policy: serde_json::json!({ "permission": [{ "action": "transfer" }] }),
            policy_hash: "policy-hash".into(),
            evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
            liquid_policy: LiquidPolicyIr {
                transport_guard: TransportGuard {
                    allow_read: true,
                    allow_transfer: true,
                    packet_cap: Some(500),
                    byte_cap: Some(2048),
                    allowed_regions: vec!["EU".into()],
                    valid_until: None,
                    protocol: TransportProtocol::Udp,
                    session_port: None,
                },
                transform_guard: TransformGuard {
                    allow_anonymize: true,
                    allowed_purposes: vec!["analytics".into()],
                    required_ops: vec![],
                },
                runtime_guard: RuntimeGuard {
                    delete_after_seconds: Some(60),
                    evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                    approval_required: false,
                },
            },
        }
    }

    #[test]
    fn test_compile_transport_guard() {
        let agreement = make_test_agreement();
        let compiled = compile_agreement(&agreement).unwrap();

        assert_eq!(compiled.agreement_id, "agreement-1");
        assert_eq!(compiled.max_packets, Some(500));
        assert_eq!(compiled.max_bytes, Some(2048));
        assert!(compiled.transport_selector.port >= 20_000);
        assert_eq!(compiled.transport_selector.protocol, TransportProtocol::Udp);
    }

    #[test]
    fn test_compile_honors_expiry() {
        let mut agreement = make_test_agreement();
        let future = Utc::now() + chrono::Duration::hours(1);
        agreement.liquid_policy.transport_guard.valid_until = Some(future);

        let compiled = compile_agreement(&agreement).unwrap();
        assert_eq!(compiled.expires_at, Some(future));
    }

    #[test]
    fn test_compile_rejects_expired_guard() {
        let mut agreement = make_test_agreement();
        agreement.liquid_policy.transport_guard.valid_until =
            Some(Utc::now() - chrono::Duration::seconds(1));

        let result = compile_agreement(&agreement);
        assert!(result.is_err());
    }
}
