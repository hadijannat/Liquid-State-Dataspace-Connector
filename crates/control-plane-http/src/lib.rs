mod bootstrap;
mod error;
mod job_runner;
mod router;
mod state;

pub mod handlers {
    pub mod contracts;
    pub mod execution;
    pub mod evidence;
    pub mod lineage;
    pub mod settlement;
    pub mod transfers;
}

pub use bootstrap::state_from_config;
pub use router::router;
pub use state::{ApiState, ApiStateInit, BackendSummary};

use anyhow::{anyhow, Result as AnyhowResult};

pub async fn serve(listener: tokio::net::TcpListener, state: ApiState) -> AnyhowResult<()> {
    state.lineage_job_runner().resume_pending_jobs().await?;
    axum::serve(listener, router(state))
        .await
        .map_err(|err| anyhow!("control-plane-api server failed: {err}"))
}
