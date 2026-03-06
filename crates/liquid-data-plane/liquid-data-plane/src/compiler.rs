use crate::maps::{CompiledPolicy, MapEntry};
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::odrl::ast::{Constraint, PolicyAgreement};
use std::hash::{DefaultHasher, Hash, Hasher};

/// Compile an ODRL PolicyAgreement into eBPF map entries.
///
/// This translates high-level semantic constraints into concrete
/// key-value pairs that the XDP program reads at packet-processing time.
pub fn compile_policy(policy: &PolicyAgreement) -> Result<CompiledPolicy> {
    let contract_id = policy_to_contract_id(policy);
    let mut entries = Vec::new();

    for permission in &policy.permissions {
        for constraint in &permission.constraints {
            let entry = compile_constraint(contract_id, constraint)?;
            entries.push(entry);
        }
    }

    // If the policy has a valid_until, add an expiry entry
    if let Some(until) = &policy.valid_until {
        entries.push(MapEntry::Expiry {
            contract_id,
            expiry_ts: until.timestamp(),
        });
    }

    if entries.is_empty() {
        return Err(LsdcError::PolicyCompile(
            "Policy produced no enforceable constraints".into(),
        ));
    }

    Ok(CompiledPolicy {
        contract_id,
        entries,
    })
}

fn compile_constraint(contract_id: u32, constraint: &Constraint) -> Result<MapEntry> {
    match constraint {
        Constraint::Count { max } => Ok(MapEntry::RateLimit {
            contract_id,
            max_packets: *max,
        }),
        Constraint::RateLimit { max_per_second } => Ok(MapEntry::RatePerSecond {
            contract_id,
            max_per_second: *max_per_second,
        }),
        Constraint::Temporal { not_after } => Ok(MapEntry::Expiry {
            contract_id,
            expiry_ts: not_after.timestamp(),
        }),
        Constraint::Spatial { allowed_regions } => {
            // In a real implementation, GeoRegion would map to IP CIDR blocks
            // via a GeoIP database. For Sprint 0, we use placeholder CIDRs.
            let cidrs: Vec<u32> = allowed_regions
                .iter()
                .enumerate()
                .map(|(i, _)| i as u32 + 1) // placeholder
                .collect();
            Ok(MapEntry::GeoFence {
                allowed_cidrs: cidrs,
            })
        }
        Constraint::Purpose { .. } => Err(LsdcError::PolicyCompile(
            "Purpose constraints cannot be enforced at packet level".into(),
        )),
        Constraint::Custom { key, .. } => Err(LsdcError::PolicyCompile(format!(
            "Unknown constraint type: {key}"
        ))),
    }
}

/// Derive a stable 32-bit contract ID from the policy's string ID.
fn policy_to_contract_id(policy: &PolicyAgreement) -> u32 {
    let mut hasher = DefaultHasher::new();
    policy.id.0.hash(&mut hasher);
    hasher.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lsdc_common::odrl::ast::*;

    fn make_test_policy(constraints: Vec<Constraint>) -> PolicyAgreement {
        PolicyAgreement {
            id: PolicyId("test-1".into()),
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
        }
    }

    #[test]
    fn test_compile_rate_limit() {
        let policy = make_test_policy(vec![Constraint::Count { max: 500 }]);
        let compiled = compile_policy(&policy).unwrap();

        assert_eq!(compiled.entries.len(), 1);
        match &compiled.entries[0] {
            MapEntry::RateLimit { max_packets, .. } => assert_eq!(*max_packets, 500),
            other => panic!("Expected RateLimit, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_temporal_constraint() {
        let future = Utc::now() + chrono::Duration::hours(1);
        let policy = make_test_policy(vec![Constraint::Temporal { not_after: future }]);
        let compiled = compile_policy(&policy).unwrap();

        assert_eq!(compiled.entries.len(), 1);
        match &compiled.entries[0] {
            MapEntry::Expiry { expiry_ts, .. } => {
                assert_eq!(*expiry_ts, future.timestamp());
            }
            other => panic!("Expected Expiry, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_geo_fence() {
        let policy = make_test_policy(vec![Constraint::Spatial {
            allowed_regions: vec![GeoRegion::EU, GeoRegion::US],
        }]);
        let compiled = compile_policy(&policy).unwrap();

        assert_eq!(compiled.entries.len(), 1);
        match &compiled.entries[0] {
            MapEntry::GeoFence { allowed_cidrs } => assert_eq!(allowed_cidrs.len(), 2),
            other => panic!("Expected GeoFence, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_purpose_constraint_fails() {
        let policy = make_test_policy(vec![Constraint::Purpose {
            allowed: vec!["research".into()],
        }]);
        let result = compile_policy(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_empty_policy_fails() {
        let policy = make_test_policy(vec![]);
        let result = compile_policy(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_multiple_constraints() {
        let policy = make_test_policy(vec![
            Constraint::Count { max: 1000 },
            Constraint::RateLimit { max_per_second: 100 },
        ]);
        let compiled = compile_policy(&policy).unwrap();
        assert_eq!(compiled.entries.len(), 2);
    }
}
