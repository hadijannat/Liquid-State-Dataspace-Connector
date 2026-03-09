use crate::backend::simulated::ensure_interface_runtime;
use crate::planner::compile_agreement;
use crate::projection::{selector_key, CompiledPolicy};
use crate::runtime::{DataPlaneMode, LifecycleState, State, TrackedEnforcement};
use chrono::{DateTime, Utc};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::TransportBackend;
use lsdc_ports::{DataPlane, EnforcementHandle, EnforcementRuntimeStatus, EnforcementStatus};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use crate::backend::linux_xdp::{
    attach_linux, detach_linux, insert_linux_maps, read_counters, remove_linux_maps,
};
#[cfg(target_os = "linux")]
use crate::runtime::InterfaceRuntime;
#[cfg(target_os = "linux")]
use crate::runtime::LinuxAttachment;
#[cfg(target_os = "linux")]
use std::collections::HashSet;

const SESSION_PORT_START: u16 = 20_000;
const SESSION_PORT_END_EXCLUSIVE: u16 = 60_000;
const SESSION_PORT_RANGE_LEN: usize = (SESSION_PORT_END_EXCLUSIVE - SESSION_PORT_START) as usize;

pub struct LiquidDataPlane {
    inner: Arc<Mutex<State>>,
    mode: DataPlaneMode,
}

impl Default for LiquidDataPlane {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State::default())),
            mode: DataPlaneMode::Kernel,
        }
    }
}

impl LiquidDataPlane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_simulated() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State::default())),
            mode: DataPlaneMode::Simulated,
        }
    }

    pub fn compile(&self, agreement: &ContractAgreement) -> Result<CompiledPolicy> {
        compile_agreement(agreement)
    }

    fn spawn_expiry_task(&self, handle_id: String, expires_at: Option<DateTime<Utc>>) {
        let Some(expires_at) = expires_at else {
            return;
        };

        let Ok(delay) = expires_at.signed_duration_since(Utc::now()).to_std() else {
            return;
        };

        let inner = self.inner.clone();
        let use_kernel_enforcement = self.uses_kernel_enforcement();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = deactivate_inner(
                &inner,
                &handle_id,
                LifecycleState::Expired,
                use_kernel_enforcement,
            )
            .await;
        });
    }

    fn uses_kernel_enforcement(&self) -> bool {
        matches!(self.mode, DataPlaneMode::Kernel)
    }

    fn transport_backend(&self) -> TransportBackend {
        match self.mode {
            DataPlaneMode::Kernel => TransportBackend::AyaXdp,
            DataPlaneMode::Simulated => TransportBackend::Simulated,
        }
    }

    fn runtime_status(&self, rule_active: bool) -> EnforcementRuntimeStatus {
        EnforcementRuntimeStatus {
            transport_backend: self.transport_backend(),
            rule_active,
            kernel_program_attached: self.uses_kernel_enforcement(),
        }
    }
}

#[async_trait::async_trait]
impl DataPlane for LiquidDataPlane {
    async fn enforce(
        &self,
        agreement: &ContractAgreement,
        iface: &str,
    ) -> Result<EnforcementHandle> {
        let mut compiled = compile_agreement(agreement)?;
        #[cfg(target_os = "linux")]
        let use_kernel_enforcement = self.uses_kernel_enforcement();

        {
            let mut state = self.inner.lock().await;
            let State {
                tracked,
                interfaces,
            } = &mut *state;

            compiled.transport_selector = resolve_transport_selector(
                tracked,
                iface,
                agreement,
                &compiled.transport_selector,
            )?;
            compiled.selector_key = selector_key(&compiled.transport_selector);

            let transport_selector = compiled.transport_selector.clone();
            let resolved_transport = compiled.resolved_transport();
            let handle = EnforcementHandle {
                id: agreement.agreement_id.0.clone(),
                interface: iface.to_string(),
                session_port: compiled.session_port(),
                active: true,
                transport_selector: Some(transport_selector.clone()),
                resolved_transport: Some(resolved_transport.clone()),
                runtime: Some(self.runtime_status(true)),
            };

            if tracked
                .get(&handle.id)
                .is_some_and(|entry| entry.state == LifecycleState::Active)
            {
                return Err(LsdcError::Enforcement(format!(
                    "agreement `{}` is already active",
                    handle.id
                )));
            }

            if tracked.values().any(|entry| {
                entry.interface == handle.interface
                    && entry.transport_selector == compiled.transport_selector
                    && entry.state == LifecycleState::Active
            }) {
                return Err(LsdcError::Enforcement(format!(
                    "transport selector `{:?}` is already active on interface `{}`",
                    compiled.transport_selector, handle.interface
                )));
            }

            #[cfg(target_os = "linux")]
            {
                if use_kernel_enforcement {
                    if let Some(runtime) = interfaces.get_mut(iface) {
                        let attachment = runtime.attachment.as_mut().ok_or_else(|| {
                            LsdcError::Enforcement(format!(
                                "interface `{iface}` is missing its XDP attachment"
                            ))
                        })?;
                        insert_linux_maps(&mut attachment.ebpf, &compiled)?;
                    } else {
                        let mut attachment = attach_linux(iface)?;
                        insert_linux_maps(&mut attachment.ebpf, &compiled)?;
                        interfaces.insert(
                            iface.to_string(),
                            InterfaceRuntime {
                                active_handles: HashSet::new(),
                                attachment: Some(attachment),
                            },
                        );
                    }
                } else {
                    ensure_interface_runtime(interfaces, iface);
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                ensure_interface_runtime(interfaces, iface);
            }

            interfaces
                .get_mut(iface)
                .expect("interface runtime must exist after install")
                .active_handles
                .insert(handle.id.clone());

            tracked.insert(
                handle.id.clone(),
                TrackedEnforcement {
                    interface: handle.interface.clone(),
                    enforcement_key: compiled.enforcement_key,
                    selector_key: compiled.selector_key,
                    transport_selector,
                    resolved_transport,
                    max_packets: compiled.max_packets,
                    max_bytes: compiled.max_bytes,
                    expires_at: compiled.expires_at,
                    state: LifecycleState::Active,
                },
            );

            self.spawn_expiry_task(handle.id.clone(), compiled.expires_at);
            return Ok(handle);
        }
    }

    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()> {
        deactivate_inner(
            &self.inner,
            &handle.id,
            LifecycleState::Revoked,
            self.uses_kernel_enforcement(),
        )
        .await
    }

    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus> {
        let state = self.inner.lock().await;
        let tracked = &state.tracked;
        #[cfg(target_os = "linux")]
        let use_kernel_enforcement = self.uses_kernel_enforcement();
        #[cfg(target_os = "linux")]
        let interfaces = &state.interfaces;
        let Some(entry) = tracked.get(&handle.id) else {
            return Ok(EnforcementStatus::Revoked);
        };

        match &entry.state {
            LifecycleState::Active => {
                #[cfg(target_os = "linux")]
                let (packets_processed, bytes_processed) = if use_kernel_enforcement {
                    if let Some(interface) = interfaces.get(&entry.interface) {
                        let attachment = interface.attachment.as_ref().ok_or_else(|| {
                            LsdcError::Enforcement(format!(
                                "interface `{}` is missing its XDP attachment",
                                entry.interface
                            ))
                        })?;
                        read_counters(attachment, entry.enforcement_key)?
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };

                #[cfg(not(target_os = "linux"))]
                let (packets_processed, bytes_processed) = (0, 0);

                Ok(EnforcementStatus::Active {
                    packets_processed,
                    bytes_processed,
                    session_port: entry.transport_selector.port,
                })
            }
            LifecycleState::Expired => Ok(EnforcementStatus::Expired),
            LifecycleState::Revoked => Ok(EnforcementStatus::Revoked),
            LifecycleState::Error(message) => Ok(EnforcementStatus::Error(message.clone())),
        }
    }
}

async fn deactivate_inner(
    inner: &Arc<Mutex<State>>,
    handle_id: &str,
    next_state: LifecycleState,
    _use_kernel_enforcement: bool,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let mut detach: Option<LinuxAttachment> = None;
    #[cfg(target_os = "linux")]
    let use_kernel_enforcement = _use_kernel_enforcement;

    {
        let mut state = inner.lock().await;
        let State {
            tracked,
            interfaces,
        } = &mut *state;
        let Some(entry) = tracked.get_mut(handle_id) else {
            return Ok(());
        };

        if entry.state != LifecycleState::Active {
            return Ok(());
        }

        entry.state = next_state;
        let interface_name = entry.interface.clone();
        #[cfg(target_os = "linux")]
        let enforcement_key = entry.enforcement_key;
        #[cfg(target_os = "linux")]
        let selector_key = entry.selector_key;

        #[cfg(target_os = "linux")]
        {
            if let Some(interface) = interfaces.get_mut(&interface_name) {
                if use_kernel_enforcement {
                    let attachment = interface.attachment.as_mut().ok_or_else(|| {
                        LsdcError::Enforcement(format!(
                            "interface `{interface_name}` is missing its XDP attachment"
                        ))
                    })?;
                    if let Err(err) =
                        remove_linux_maps(&mut attachment.ebpf, enforcement_key, selector_key)
                    {
                        entry.state = LifecycleState::Error(err.to_string());
                        return Err(err);
                    }
                }

                interface.active_handles.remove(handle_id);
                if interface.active_handles.is_empty() {
                    if use_kernel_enforcement {
                        detach = interfaces
                            .remove(&interface_name)
                            .and_then(|runtime| runtime.attachment);
                    } else {
                        interfaces.remove(&interface_name);
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            if let Some(interface) = interfaces.get_mut(&interface_name) {
                interface.active_handles.remove(handle_id);
                if interface.active_handles.is_empty() {
                    interfaces.remove(&interface_name);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(attachment) = detach {
        detach_linux(attachment)?;
    }

    Ok(())
}

fn resolve_transport_selector(
    tracked: &std::collections::HashMap<String, TrackedEnforcement>,
    interface: &str,
    agreement: &ContractAgreement,
    preferred: &lsdc_common::execution::TransportSelector,
) -> Result<lsdc_common::execution::TransportSelector> {
    if agreement
        .liquid_policy
        .transport_guard
        .session_port
        .is_some()
    {
        return Ok(preferred.clone());
    }

    let base_offset = preferred
        .port
        .checked_sub(SESSION_PORT_START)
        .map(usize::from)
        .filter(|offset| *offset < SESSION_PORT_RANGE_LEN)
        .unwrap_or_default();

    for step in 0..SESSION_PORT_RANGE_LEN {
        let offset = (base_offset + step) % SESSION_PORT_RANGE_LEN;
        let candidate = lsdc_common::execution::TransportSelector {
            protocol: preferred.protocol,
            port: SESSION_PORT_START + offset as u16,
        };

        let in_use = tracked.values().any(|entry| {
            entry.interface == interface
                && entry.transport_selector == candidate
                && entry.state == LifecycleState::Active
        });
        if !in_use {
            return Ok(candidate);
        }
    }

    Err(LsdcError::Enforcement(format!(
        "no free dynamic session ports remain in {SESSION_PORT_START}..{SESSION_PORT_END_EXCLUSIVE}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
    use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};
    use lsdc_common::odrl::ast::PolicyId;
    use std::collections::HashMap;

    fn make_agreement(id: &str, valid_until: Option<DateTime<Utc>>) -> ContractAgreement {
        make_agreement_with_selector(id, TransportProtocol::Udp, None, valid_until)
    }

    fn make_agreement_with_selector(
        id: &str,
        protocol: TransportProtocol,
        session_port: Option<u16>,
        valid_until: Option<DateTime<Utc>>,
    ) -> ContractAgreement {
        ContractAgreement {
            agreement_id: PolicyId(id.into()),
            asset_id: format!("asset-{id}"),
            provider_id: "did:web:provider".into(),
            consumer_id: "did:web:consumer".into(),
            odrl_policy: serde_json::json!({ "permission": [{ "action": ["read", "transfer"] }] }),
            policy_hash: "policy-hash".into(),
            evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
            liquid_policy: LiquidPolicyIr {
                transport_guard: TransportGuard {
                    allow_read: true,
                    allow_transfer: true,
                    packet_cap: Some(5),
                    byte_cap: Some(1024),
                    allowed_regions: vec!["EU".into()],
                    valid_until,
                    protocol,
                    session_port,
                },
                transform_guard: TransformGuard {
                    allow_anonymize: true,
                    allowed_purposes: vec!["analytics".into()],
                    required_ops: vec![],
                },
                runtime_guard: RuntimeGuard {
                    delete_after_seconds: Some(30),
                    evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                    approval_required: false,
                },
            },
        }
    }

    #[tokio::test]
    async fn test_reuses_agreement_id_for_handle_identity() {
        let plane = LiquidDataPlane::new_simulated();
        let agreement = make_agreement("agreement-test", None);

        let handle = plane.enforce(&agreement, "lo").await.unwrap();

        assert_eq!(handle.id, agreement.agreement_id.0);
        assert_eq!(handle.interface, "lo");
        assert!(handle.session_port >= 20_000);
        assert!(handle.transport_selector.is_some());
        assert!(handle.resolved_transport.is_some());
        assert!(handle.runtime.is_some());
    }

    #[tokio::test]
    async fn test_allows_multiple_active_agreements_on_interface() {
        let plane = LiquidDataPlane::new_simulated();
        let first = make_agreement("agreement-test-1", None);
        let second = make_agreement("agreement-test-2", None);

        let first_handle = plane.enforce(&first, "lo").await.unwrap();
        let second_handle = plane.enforce(&second, "lo").await.unwrap();

        assert_ne!(first_handle.session_port, second_handle.session_port);
    }

    #[tokio::test]
    async fn test_dynamic_session_port_allocator_probes_hash_collisions() {
        let plane = LiquidDataPlane::new_simulated();
        let (first, second, preferred_port) = find_colliding_dynamic_agreements(&plane);

        let first_handle = plane.enforce(&first, "lo").await.unwrap();
        let second_handle = plane.enforce(&second, "lo").await.unwrap();

        assert_eq!(first_handle.session_port, preferred_port);
        assert_ne!(second_handle.session_port, preferred_port);
        assert_ne!(first_handle.session_port, second_handle.session_port);
    }

    #[tokio::test]
    async fn test_allows_same_port_for_different_protocol_selectors() {
        let plane = LiquidDataPlane::new_simulated();
        let udp = make_agreement_with_selector(
            "agreement-udp",
            TransportProtocol::Udp,
            Some(31_337),
            None,
        );
        let tcp = make_agreement_with_selector(
            "agreement-tcp",
            TransportProtocol::Tcp,
            Some(31_337),
            None,
        );

        let udp_handle = plane.enforce(&udp, "lo").await.unwrap();
        let tcp_handle = plane.enforce(&tcp, "lo").await.unwrap();

        assert_eq!(udp_handle.session_port, tcp_handle.session_port);
        assert_ne!(
            udp_handle.transport_selector.as_ref().unwrap().protocol,
            tcp_handle.transport_selector.as_ref().unwrap().protocol
        );
    }

    #[tokio::test]
    async fn test_expiry_transitions_status_to_expired() {
        let plane = LiquidDataPlane::new_simulated();
        let agreement = make_agreement(
            "agreement-expiring",
            Some(Utc::now() + Duration::milliseconds(20)),
        );

        let handle = plane.enforce(&agreement, "lo").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let status = plane.status(&handle).await.unwrap();
        assert!(matches!(status, EnforcementStatus::Expired));
    }

    #[tokio::test]
    async fn test_revoke_transitions_status_to_revoked() {
        let plane = LiquidDataPlane::new_simulated();
        let agreement = make_agreement("agreement-revoked", None);

        let handle = plane.enforce(&agreement, "lo").await.unwrap();
        plane.revoke(&handle).await.unwrap();

        let status = plane.status(&handle).await.unwrap();
        assert!(matches!(status, EnforcementStatus::Revoked));
    }

    #[tokio::test]
    async fn test_revoke_only_clears_targeted_agreement_on_interface() {
        let plane = LiquidDataPlane::new_simulated();
        let first = make_agreement("agreement-target-a", None);
        let second = make_agreement("agreement-target-b", None);

        let first_handle = plane.enforce(&first, "lo").await.unwrap();
        let second_handle = plane.enforce(&second, "lo").await.unwrap();

        plane.revoke(&first_handle).await.unwrap();

        assert!(matches!(
            plane.status(&first_handle).await.unwrap(),
            EnforcementStatus::Revoked
        ));
        assert!(matches!(
            plane.status(&second_handle).await.unwrap(),
            EnforcementStatus::Active { .. }
        ));
    }

    fn find_colliding_dynamic_agreements(
        plane: &LiquidDataPlane,
    ) -> (ContractAgreement, ContractAgreement, u16) {
        let mut seen = HashMap::new();

        for index in 0..10_000 {
            let agreement = make_agreement(&format!("agreement-collision-{index}"), None);
            let preferred_port = plane.compile(&agreement).unwrap().session_port();
            if let Some(first) = seen.insert(preferred_port, agreement.clone()) {
                return (first, agreement, preferred_port);
            }
        }

        panic!("failed to find two agreements with the same preferred dynamic session port");
    }
}
