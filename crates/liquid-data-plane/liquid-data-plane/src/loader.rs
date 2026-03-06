use crate::compiler::compile_policy;
use crate::maps::CompiledPolicy;
use lsdc_common::error::Result;
use lsdc_common::odrl::ast::PolicyAgreement;
use lsdc_common::traits::{DataPlane, EnforcementHandle, EnforcementStatus};

/// The Liquid Data Plane enforces ODRL policies via eBPF/XDP.
///
/// On Linux, it attaches compiled XDP programs to network interfaces.
/// On other platforms, it runs in simulation mode for development.
pub struct LiquidDataPlane {
    // Tracks active enforcement handles
    active: std::sync::Arc<tokio::sync::Mutex<Vec<EnforcementHandle>>>,
}

impl LiquidDataPlane {
    pub fn new() -> Self {
        Self {
            active: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Compile and return the map entries without attaching.
    /// Useful for testing the compilation pipeline independently.
    pub fn compile(&self, policy: &PolicyAgreement) -> Result<CompiledPolicy> {
        compile_policy(policy)
    }
}

#[async_trait::async_trait]
impl DataPlane for LiquidDataPlane {
    async fn enforce(&self, policy: &PolicyAgreement, iface: &str) -> Result<EnforcementHandle> {
        let compiled = compile_policy(policy)?;
        tracing::info!(
            contract_id = compiled.contract_id,
            entries = compiled.entries.len(),
            interface = iface,
            "Enforcing policy"
        );

        #[cfg(target_os = "linux")]
        {
            self.enforce_linux(&compiled, iface).await?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("Non-Linux platform: running in simulation mode");
            let _ = &compiled; // suppress unused warning
        }

        let handle = EnforcementHandle {
            id: compiled.contract_id.to_string(),
            interface: iface.to_string(),
            active: true,
        };

        self.active.lock().await.push(handle.clone());
        Ok(handle)
    }

    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()> {
        tracing::info!(handle_id = %handle.id, "Revoking enforcement");

        #[cfg(target_os = "linux")]
        {
            self.revoke_linux(handle).await?;
        }

        let mut active = self.active.lock().await;
        active.retain(|h| h.id != handle.id);
        Ok(())
    }

    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus> {
        let active = self.active.lock().await;
        if active.iter().any(|h| h.id == handle.id) {
            Ok(EnforcementStatus::Active {
                packets_processed: 0, // Real impl reads from eBPF map
            })
        } else {
            Ok(EnforcementStatus::Revoked)
        }
    }
}

// Linux-specific eBPF operations
#[cfg(target_os = "linux")]
impl LiquidDataPlane {
    async fn enforce_linux(
        &self,
        _compiled: &CompiledPolicy,
        _iface: &str,
    ) -> Result<()> {
        // TODO: Load eBPF bytecode via aya::Ebpf::load()
        // TODO: Attach XDP program to interface
        // TODO: Populate eBPF maps with compiled entries
        // TODO: Spawn expiry timer task
        todo!("Linux eBPF enforcement — implement in Sprint 0 Week 2")
    }

    async fn revoke_linux(&self, _handle: &EnforcementHandle) -> Result<()> {
        // TODO: Detach XDP program from interface
        // TODO: Clean up eBPF maps
        todo!("Linux eBPF revocation")
    }
}
