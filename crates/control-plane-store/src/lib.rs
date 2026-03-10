mod agreements_repo;
mod db;
mod evidence_repo;
mod execution_overlay_repo;
mod lineage_jobs_repo;
mod migrations;
mod ser;
mod settlements_repo;
mod transfers_repo;

use lsdc_common::error::{LsdcError, Result};
use rusqlite::Connection;
use std::sync::{Arc, Mutex, MutexGuard};

pub use lineage_jobs_repo::RestartableLineageJob;

#[derive(Clone)]
pub struct Store {
    connection: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn new(path: &str) -> Result<Self> {
        let connection = db::open_connection(path)?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| LsdcError::Database("sqlite connection mutex poisoned".into()))
    }
}

pub(crate) fn sqlite_error(err: rusqlite::Error) -> LsdcError {
    LsdcError::Database(err.to_string())
}
