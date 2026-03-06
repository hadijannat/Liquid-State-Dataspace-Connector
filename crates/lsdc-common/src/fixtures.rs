use crate::error::{LsdcError, Result};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::PathBuf;

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root should be two levels above lsdc-common")
        .to_path_buf()
}

pub fn fixture_path(relative_path: &str) -> PathBuf {
    workspace_root().join("fixtures").join(relative_path)
}

pub fn read_text(relative_path: &str) -> Result<String> {
    fs::read_to_string(fixture_path(relative_path)).map_err(LsdcError::from)
}

pub fn read_bytes(relative_path: &str) -> Result<Vec<u8>> {
    fs::read(fixture_path(relative_path)).map_err(LsdcError::from)
}

pub fn read_json<T>(relative_path: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(&read_text(relative_path)?).map_err(LsdcError::from)
}
