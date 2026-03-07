use crate::compiler::compile_agreement;
use crate::maps::CompiledPolicy;
use chrono::{DateTime, Utc};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::execution::{TransportBackend, TransportSelector};
use lsdc_ports::{
    DataPlane, EnforcementHandle, EnforcementRuntimeStatus, EnforcementStatus,
    ResolvedTransportGuard,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use crate::maps::{
    BYTE_COUNT_MAP, BYTE_LIMIT_MAP, PACKET_COUNT_MAP, PACKET_LIMIT_MAP, SELECTOR_AGREEMENT_MAP,
};
#[cfg(target_os = "linux")]
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{xdp::XdpLinkId, Xdp, XdpFlags},
    Ebpf,
};
#[cfg(target_os = "linux")]
use std::convert::TryInto;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
const XDP_PROGRAM_NAME: &str = "lsdc_xdp";

pub struct LiquidDataPlane {
    inner: Arc<Mutex<State>>,
    mode: DataPlaneMode,
}

#[derive(Default)]
struct State {
    tracked: HashMap<String, TrackedEnforcement>,
    interfaces: HashMap<String, InterfaceRuntime>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataPlaneMode {
    Kernel,
    Simulated,
}

struct InterfaceRuntime {
    active_handles: HashSet<String>,
    #[cfg(target_os = "linux")]
    attachment: Option<LinuxAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecycleState {
    Active,
    Expired,
    Revoked,
    #[allow(dead_code)]
    Error(String),
}

struct TrackedEnforcement {
    interface: String,
    #[allow(dead_code)]
    enforcement_key: u32,
    #[allow(dead_code)]
    selector_key: u32,
    transport_selector: TransportSelector,
    #[allow(dead_code)]
    resolved_transport: ResolvedTransportGuard,
    #[allow(dead_code)]
    max_packets: Option<u64>,
    #[allow(dead_code)]
    max_bytes: Option<u64>,
    #[allow(dead_code)]
    expires_at: Option<DateTime<Utc>>,
    state: LifecycleState,
}

#[cfg(target_os = "linux")]
struct LinuxAttachment {
    ebpf: Ebpf,
    link_id: Option<XdpLinkId>,
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
        let compiled = compile_agreement(agreement)?;
        #[cfg(target_os = "linux")]
        let use_kernel_enforcement = self.uses_kernel_enforcement();
        let handle = EnforcementHandle {
            id: agreement.agreement_id.0.clone(),
            interface: iface.to_string(),
            session_port: compiled.session_port(),
            active: true,
            transport_selector: Some(compiled.transport_selector.clone()),
            resolved_transport: Some(compiled.resolved_transport()),
            runtime: Some(self.runtime_status(true)),
        };

        {
            let mut state = self.inner.lock().await;
            let State {
                tracked,
                interfaces,
            } = &mut *state;

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
                    interfaces
                        .entry(iface.to_string())
                        .or_insert_with(|| InterfaceRuntime {
                            active_handles: HashSet::new(),
                            attachment: None,
                        });
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                interfaces
                    .entry(iface.to_string())
                    .or_insert_with(|| InterfaceRuntime {
                        active_handles: HashSet::new(),
                    });
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
                    transport_selector: compiled.transport_selector.clone(),
                    resolved_transport: compiled.resolved_transport(),
                    max_packets: compiled.max_packets,
                    max_bytes: compiled.max_bytes,
                    expires_at: compiled.expires_at,
                    state: LifecycleState::Active,
                },
            );
        }

        self.spawn_expiry_task(handle.id.clone(), compiled.expires_at);
        Ok(handle)
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

#[cfg(target_os = "linux")]
fn attach_linux(iface: &str) -> Result<LinuxAttachment> {
    let mut ebpf = load_ebpf_object()?;
    let program: &mut Xdp = ebpf
        .program_mut(XDP_PROGRAM_NAME)
        .ok_or_else(|| {
            LsdcError::Enforcement(format!(
                "missing XDP program `{XDP_PROGRAM_NAME}` in eBPF object"
            ))
        })?
        .try_into()
        .map_err(|err| {
            LsdcError::Enforcement(format!("failed to convert program to XDP: {err}"))
        })?;

    program
        .load()
        .map_err(|err| LsdcError::Enforcement(format!("failed to load XDP program: {err}")))?;

    let link_id = program.attach(iface, XdpFlags::SKB_MODE).map_err(|err| {
        LsdcError::Enforcement(format!(
            "failed to attach XDP program to interface `{iface}`: {err}"
        ))
    })?;

    Ok(LinuxAttachment {
        ebpf,
        link_id: Some(link_id),
    })
}

#[cfg(target_os = "linux")]
fn insert_linux_maps(ebpf: &mut Ebpf, compiled: &CompiledPolicy) -> Result<()> {
    {
        let map = ebpf.map_mut(SELECTOR_AGREEMENT_MAP).ok_or_else(|| {
            LsdcError::Enforcement(format!("missing map `{SELECTOR_AGREEMENT_MAP}`"))
        })?;
        let mut session_map = BpfHashMap::<_, u32, u32>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{SELECTOR_AGREEMENT_MAP}` as hash map: {err}"
            ))
        })?;
        session_map
            .insert(compiled.selector_key, compiled.enforcement_key, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!(
                    "failed to populate `{SELECTOR_AGREEMENT_MAP}`: {err}"
                ))
            })?;
    }

    {
        let map = ebpf
            .map_mut(PACKET_LIMIT_MAP)
            .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{PACKET_LIMIT_MAP}`")))?;
        let mut limit_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{PACKET_LIMIT_MAP}` as hash map: {err}"
            ))
        })?;
        let packet_cap = compiled.max_packets.unwrap_or(u64::MAX);
        limit_map
            .insert(compiled.enforcement_key, packet_cap, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!("failed to populate `{PACKET_LIMIT_MAP}`: {err}"))
            })?;
    }

    {
        let map = ebpf
            .map_mut(BYTE_LIMIT_MAP)
            .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{BYTE_LIMIT_MAP}`")))?;
        let mut limit_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{BYTE_LIMIT_MAP}` as hash map: {err}"
            ))
        })?;
        let byte_cap = compiled.max_bytes.unwrap_or(u64::MAX);
        limit_map
            .insert(compiled.enforcement_key, byte_cap, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!("failed to populate `{BYTE_LIMIT_MAP}`: {err}"))
            })?;
    }

    initialize_counter_map(ebpf, PACKET_COUNT_MAP, compiled.enforcement_key)?;
    initialize_counter_map(ebpf, BYTE_COUNT_MAP, compiled.enforcement_key)?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn initialize_counter_map(ebpf: &mut Ebpf, map_name: &str, enforcement_key: u32) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{map_name}`")))?;
    let mut counter_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
        LsdcError::Enforcement(format!("failed to open `{map_name}` as hash map: {err}"))
    })?;
    let _ = counter_map.remove(&enforcement_key);
    counter_map.insert(enforcement_key, 0, 0).map_err(|err| {
        LsdcError::Enforcement(format!("failed to initialize `{map_name}`: {err}"))
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_linux_maps(ebpf: &mut Ebpf, enforcement_key: u32, selector_key: u32) -> Result<()> {
    remove_u32_u32_entry(ebpf, SELECTOR_AGREEMENT_MAP, selector_key)?;
    remove_u32_u64_entry(ebpf, PACKET_LIMIT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, BYTE_LIMIT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, PACKET_COUNT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, BYTE_COUNT_MAP, enforcement_key)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_u32_u32_entry(ebpf: &mut Ebpf, map_name: &str, key: u32) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{map_name}`")))?;
    let mut typed = BpfHashMap::<_, u32, u32>::try_from(map).map_err(|err| {
        LsdcError::Enforcement(format!("failed to open `{map_name}` as hash map: {err}"))
    })?;
    let _ = typed.remove(&key);
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_u32_u64_entry(ebpf: &mut Ebpf, map_name: &str, key: u32) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{map_name}`")))?;
    let mut typed = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
        LsdcError::Enforcement(format!("failed to open `{map_name}` as hash map: {err}"))
    })?;
    let _ = typed.remove(&key);
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_counters(attachment: &LinuxAttachment, enforcement_key: u32) -> Result<(u64, u64)> {
    Ok((
        read_counter(&attachment.ebpf, PACKET_COUNT_MAP, enforcement_key)?,
        read_counter(&attachment.ebpf, BYTE_COUNT_MAP, enforcement_key)?,
    ))
}

#[cfg(target_os = "linux")]
fn read_counter(ebpf: &Ebpf, map_name: &str, enforcement_key: u32) -> Result<u64> {
    let map = ebpf
        .map(map_name)
        .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{map_name}`")))?;
    let counter_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
        LsdcError::Enforcement(format!("failed to open `{map_name}` as hash map: {err}"))
    })?;
    counter_map.get(&enforcement_key, 0).map_err(|err| {
        LsdcError::Enforcement(format!(
            "failed to read counter from `{map_name}` for key `{enforcement_key}`: {err}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn detach_linux(mut attachment: LinuxAttachment) -> Result<()> {
    let Some(link_id) = attachment.link_id.take() else {
        return Ok(());
    };

    let program: &mut Xdp = attachment
        .ebpf
        .program_mut(XDP_PROGRAM_NAME)
        .ok_or_else(|| {
            LsdcError::Enforcement(format!(
                "missing XDP program `{XDP_PROGRAM_NAME}` in eBPF object"
            ))
        })?
        .try_into()
        .map_err(|err| {
            LsdcError::Enforcement(format!("failed to convert program to XDP: {err}"))
        })?;
    program
        .detach(link_id)
        .map_err(|err| LsdcError::Enforcement(format!("failed to detach XDP link: {err}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_ebpf_object() -> Result<Ebpf> {
    let path = resolve_ebpf_object_path()?;
    Ebpf::load_file(&path).map_err(|err| {
        LsdcError::Enforcement(format!(
            "failed to load eBPF object `{}`: {err}",
            path.display()
        ))
    })
}

#[cfg(target_os = "linux")]
fn resolve_ebpf_object_path() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("LSDC_EBPF_OBJECT") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Ok(path);
        }
        return Err(LsdcError::Enforcement(format!(
            "LSDC_EBPF_OBJECT points to missing file `{}`",
            path.display()
        )));
    }

    let workspace_root = workspace_root()?;
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let path = workspace_root
        .join("crates")
        .join("liquid-data-plane")
        .join("ebpf")
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("lsdc-xdp");

    if path.exists() {
        Ok(path)
    } else {
        Err(LsdcError::Enforcement(format!(
            "missing eBPF object `{}`; run `cargo xtask build-ebpf` first",
            path.display()
        )))
    }
}

#[cfg(target_os = "linux")]
fn workspace_root() -> Result<&'static Path> {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    let path = ROOT.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .unwrap_or(&manifest_dir)
            .to_path_buf()
    });

    Ok(path.as_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
    use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};
    use lsdc_common::odrl::ast::PolicyId;

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
}
