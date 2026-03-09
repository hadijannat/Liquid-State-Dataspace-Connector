use crate::sqlite_error;
use lsdc_common::error::Result;
use rusqlite::Connection;
use std::fs;
use std::path::Path;

pub(crate) fn open_connection(path: &str) -> Result<Connection> {
    if path != ":memory:" {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
    }

    Connection::open(path).map_err(sqlite_error)
}
