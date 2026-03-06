use thiserror::Error;

#[derive(Debug, Error)]
pub enum LsdcError {
    #[error("ODRL parsing error: {0}")]
    OdrlParse(String),

    #[error("Policy compilation error: {0}")]
    PolicyCompile(String),

    #[error("Unsupported capability: {0}")]
    Unsupported(String),

    #[error("Enforcement error: {0}")]
    Enforcement(String),

    #[error("Proof generation error: {0}")]
    ProofGeneration(String),

    #[error("Attestation error: {0}")]
    Attestation(String),

    #[error("Pricing error: {0}")]
    Pricing(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, LsdcError>;
