use lsdc_common::error::{LsdcError, Result};

pub(crate) fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(LsdcError::from)
}

pub(crate) fn option_to_json<T: serde::Serialize>(value: &Option<T>) -> Result<Option<String>> {
    value.as_ref().map(to_json).transpose()
}

pub(crate) fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(LsdcError::from)
}

pub(crate) fn parse_timestamp(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .map_err(|err| LsdcError::Database(format!("invalid stored timestamp: {err}")))
}
