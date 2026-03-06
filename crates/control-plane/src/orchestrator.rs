use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::Result;
use lsdc_common::traits::{DataPlane, EnforcementHandle};
use std::sync::Arc;

/// The Orchestrator dispatches finalized agreements to the appropriate planes.
pub struct Orchestrator {
    data_plane: Arc<dyn DataPlane>,
}

impl Orchestrator {
    pub fn new(data_plane: Arc<dyn DataPlane>) -> Self {
        Self { data_plane }
    }

    /// After a contract is signed, enforce the policy on the data plane.
    pub async fn activate_agreement(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle> {
        tracing::info!(
            agreement_id = %agreement.agreement_id.0,
            "Activating agreement on data plane"
        );

        self.data_plane.enforce(&agreement.policy, iface).await
    }

    /// Revoke an active agreement.
    pub async fn revoke_agreement(&self, handle: &EnforcementHandle) -> Result<()> {
        self.data_plane.revoke(handle).await
    }
}
