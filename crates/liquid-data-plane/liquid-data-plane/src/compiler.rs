use crate::maps::CompiledPolicy;
use chrono::Utc;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::odrl::ast::{Constraint, PolicyId};
// FNV-1a constants for deterministic hashing (stable across Rust versions)

/// Compile a ContractAgreement into the reduced Sprint 0 XDP policy.
///
/// Sprint 0 deliberately supports only:
/// - `Constraint::Count { max }`
/// - agreement-level `valid_until`
///
/// Everything else is rejected with an explicit error so the runtime,
/// eBPF maps, and tests all describe the same MVP surface.
pub fn compile_agreement(agreement: &ContractAgreement) -> Result<CompiledPolicy> {
    let policy = &agreement.policy;

    if !policy.prohibitions.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "Sprint 0 does not support prohibitions".into(),
        ));
    }

    if !policy.obligations.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "Sprint 0 does not support obligations".into(),
        ));
    }

    if policy.permissions.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "Sprint 0 requires at least one permission".into(),
        ));
    }

    let mut packet_limits = Vec::new();
    for permission in &policy.permissions {
        if !permission.duties.is_empty() {
            return Err(LsdcError::PolicyCompile(
                "Sprint 0 does not support duties".into(),
            ));
        }

        for constraint in &permission.constraints {
            match constraint {
                Constraint::Count { max } => packet_limits.push(*max),
                Constraint::Spatial { .. } => {
                    return Err(unsupported_constraint("Spatial"));
                }
                Constraint::Temporal { .. } => {
                    return Err(unsupported_constraint("Temporal"));
                }
                Constraint::Purpose { .. } => {
                    return Err(unsupported_constraint("Purpose"));
                }
                Constraint::RateLimit { .. } => {
                    return Err(unsupported_constraint("RateLimit"));
                }
                Constraint::Custom { key, .. } => {
                    return Err(LsdcError::PolicyCompile(format!(
                        "Sprint 0 does not support custom constraint `{key}`"
                    )));
                }
            }
        }
    }

    let max_packets = packet_limits.into_iter().min().ok_or_else(|| {
        LsdcError::PolicyCompile(
            "Sprint 0 requires at least one Count constraint for packet-cap enforcement".into(),
        )
    })?;

    if let Some(valid_until) = policy.valid_until {
        if valid_until <= Utc::now() {
            return Err(LsdcError::PolicyCompile(
                "Agreement is already expired".into(),
            ));
        }
    }

    Ok(CompiledPolicy {
        agreement_id: agreement.agreement_id.0.clone(),
        enforcement_key: agreement_id_to_enforcement_key(&agreement.agreement_id),
        max_packets,
        expires_at: policy.valid_until,
    })
}

fn unsupported_constraint(kind: &str) -> LsdcError {
    LsdcError::PolicyCompile(format!(
        "Sprint 0 does not support {kind} constraints; only Count plus valid_until are enforceable"
    ))
}

/// Derive a stable 32-bit enforcement key from the agreement identifier.
///
/// Uses FNV-1a (not `DefaultHasher`) because `DefaultHasher` output is
/// explicitly not guaranteed to be stable across Rust versions.
fn agreement_id_to_enforcement_key(agreement_id: &PolicyId) -> u32 {
    let bytes = agreement_id.0.as_bytes();
    let mut hash: u32 = 2_166_136_261; // FNV-1a offset basis
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16_777_619); // FNV-1a prime
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lsdc_common::dsp::ContractAgreement;
    use lsdc_common::odrl::ast::*;

    fn make_test_agreement(constraints: Vec<Constraint>) -> ContractAgreement {
        ContractAgreement {
            agreement_id: PolicyId("agreement-1".into()),
            policy: PolicyAgreement {
                id: PolicyId("policy-1".into()),
                provider: "did:web:provider".into(),
                consumer: "did:web:consumer".into(),
                target: "urn:data:test".into(),
                permissions: vec![Permission {
                    action: Action::Stream,
                    constraints,
                    duties: vec![],
                }],
                prohibitions: vec![],
                obligations: vec![],
                valid_from: Utc::now(),
                valid_until: None,
            },
        }
    }

    #[test]
    fn test_compile_rate_limit() {
        let agreement = make_test_agreement(vec![Constraint::Count { max: 500 }]);
        let compiled = compile_agreement(&agreement).unwrap();

        assert_eq!(compiled.agreement_id, "agreement-1");
        assert_eq!(compiled.max_packets, 500);
    }

    #[test]
    fn test_compile_valid_until_as_expiry() {
        let future = Utc::now() + chrono::Duration::hours(1);
        let mut agreement = make_test_agreement(vec![Constraint::Count { max: 500 }]);
        agreement.policy.valid_until = Some(future);
        let compiled = compile_agreement(&agreement).unwrap();

        assert_eq!(compiled.expires_at, Some(future));
    }

    #[test]
    fn test_compile_spatial_constraint_fails() {
        let agreement = make_test_agreement(vec![Constraint::Spatial {
            allowed_regions: vec![GeoRegion::EU],
        }]);
        let result = compile_agreement(&agreement);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_rate_per_second_constraint_fails() {
        let agreement = make_test_agreement(vec![Constraint::RateLimit {
            max_per_second: 100,
        }]);
        let result = compile_agreement(&agreement);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_empty_policy_fails() {
        let agreement = make_test_agreement(vec![]);
        let result = compile_agreement(&agreement);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_uses_strictest_count_constraint() {
        let agreement = make_test_agreement(vec![
            Constraint::Count { max: 1000 },
            Constraint::Count { max: 100 },
        ]);
        let compiled = compile_agreement(&agreement).unwrap();
        assert_eq!(compiled.max_packets, 100);
    }

    #[test]
    fn test_compile_rejects_permission_duties() {
        let mut agreement = make_test_agreement(vec![Constraint::Count { max: 10 }]);
        agreement.policy.permissions[0].duties.push(Duty {
            action: Action::Delete,
            constraints: vec![],
        });

        let result = compile_agreement(&agreement);
        assert!(result.is_err());
    }
}
