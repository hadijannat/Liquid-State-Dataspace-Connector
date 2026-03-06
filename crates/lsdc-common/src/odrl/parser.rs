use super::ast::PolicyAgreement;
use crate::error::{LsdcError, Result};

pub fn parse_policy_json(json: &str) -> Result<PolicyAgreement> {
    serde_json::from_str(json).map_err(|e| LsdcError::OdrlParse(e.to_string()))
}
