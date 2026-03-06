use super::ast::PolicyAgreement;
use crate::error::{LsdcError, Result};

/// Parse the internal Sprint 0 policy JSON shape.
///
/// This is intentionally not a JSON-LD / RDF parser yet; the current MVP
/// accepts the serde representation of `PolicyAgreement` as a reduced policy DSL.
pub fn parse_policy_json(json: &str) -> Result<PolicyAgreement> {
    serde_json::from_str(json).map_err(|e| LsdcError::OdrlParse(e.to_string()))
}
