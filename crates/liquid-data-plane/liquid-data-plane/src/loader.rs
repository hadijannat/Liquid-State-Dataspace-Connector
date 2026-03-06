use crate::compiler::compile_agreement;
use crate::maps::CompiledPolicy;
use chrono::{DateTime, Utc};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{DataPlane, EnforcementHandle, EnforcementStatus};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use crate::maps::{
    BYTE_COUNT_MAP, BYTE_LIMIT_MAP, PACKET_COUNT_MAP, PACKET_LIMIT_MAP, SESSION_AGREEMENT_MAP,
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
}

#[derive(Default)]
struct State {
    tracked: HashMap<String, TrackedEnforcement>,
    interfaces: HashMap<String, InterfaceRuntime>,
}

struct InterfaceRuntime {
    active_handles: HashSet<String>,
    #[cfg(target_os = "linux")]
    attachment: LinuxAttachment,
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
    session_port: u16,
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
        }
    }
}

impl LiquidDataPlane {
    pub fn new() -> Self {
        Self::default()
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
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = deactivate_inner(&inner, &handle_id, LifecycleState::Expired).await;
        });
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
        let handle = EnforcementHandle {
            id: agreement.agreement_id.0.clone(),
            interface: iface.to_string(),
            session_port: compiled.session_port,
            active: true,
        };

        {
            let mut state = self.inner.lock().await;
            let State { tracked, interfaces } = &mut *state;

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
                    && entry.session_port == compiled.session_port
                    && entry.state == LifecycleState::Active
            }) {
                return Err(LsdcError::Enforcement(format!(
                    "session port `{}` is already active on interface `{}`",
                    compiled.session_port, handle.interface
                )));
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(runtime) = interfaces.get_mut(iface) {
                    insert_linux_maps(&mut runtime.attachment.ebpf, &compiled)?;
                } else {
                    let mut attachment = attach_linux(iface)?;
                    insert_linux_maps(&mut attachment.ebpf, &compiled)?;
                    interfaces.insert(
                        iface.to_string(),
                        InterfaceRuntime {
                            active_handles: HashSet::new(),
                            attachment,
                        },
                    );
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
                    session_port: compiled.session_port,
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
        deactivate_inner(&self.inner, &handle.id, LifecycleState::Revoked).await
    }

    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus> {
        let state = self.inner.lock().await;
        let tracked = &state.tracked;
        #[cfg(target_os = "linux")]
        let interfaces = &state.interfaces;
        let Some(entry) = tracked.get(&handle.id) else {
            return Ok(EnforcementStatus::Revoked);
        };

        match &entry.state {
            LifecycleState::Active => {
                #[cfg(target_os = "linux")]
                let (packets_processed, bytes_processed) =
                    if let Some(interface) = interfaces.get(&entry.interface) {
                        read_counters(&interface.attachment, entry.enforcement_key)?
                    } else {
                        (0, 0)
                    };

                #[cfg(not(target_os = "linux"))]
                let (packets_processed, bytes_processed) = (0, 0);

                Ok(EnforcementStatus::Active {
                    packets_processed,
                    bytes_processed,
                    session_port: entry.session_port,
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
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let mut detach: Option<LinuxAttachment> = None;

    {
        let mut state = inner.lock().await;
        let State { tracked, interfaces } = &mut *state;
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
        let session_port = entry.session_port;

        #[cfg(target_os = "linux")]
        {
            if let Some(interface) = interfaces.get_mut(&interface_name) {
                if let Err(err) =
                    remove_linux_maps(&mut interface.attachment.ebpf, enforcement_key, session_port)
                {
                    entry.state = LifecycleState::Error(err.to_string());
                    return Err(err);
                }

                interface.active_handles.remove(handle_id);
                if interface.active_handles.is_empty() {
                    detach = interfaces.remove(&interface_name).map(|runtime| runtime.attachment);
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
        let map = ebpf.map_mut(SESSION_AGREEMENT_MAP).ok_or_else(|| {
            LsdcError::Enforcement(format!("missing map `{SESSION_AGREEMENT_MAP}`"))
        })?;
        let mut session_map = BpfHashMap::<_, u16, u32>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{SESSION_AGREEMENT_MAP}` as hash map: {err}"
            ))
        })?;
        session_map
            .insert(compiled.session_port, compiled.enforcement_key, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!(
                    "failed to populate `{SESSION_AGREEMENT_MAP}`: {err}"
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
        limit_map.insert(compiled.enforcement_key, packet_cap, 0).map_err(|err| {
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
        limit_map.insert(compiled.enforcement_key, byte_cap, 0).map_err(|err| {
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
fn remove_linux_maps(ebpf: &mut Ebpf, enforcement_key: u32, session_port: u16) -> Result<()> {
    remove_u16_u32_entry(ebpf, SESSION_AGREEMENT_MAP, session_port)?;
    remove_u32_u64_entry(ebpf, PACKET_LIMIT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, BYTE_LIMIT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, PACKET_COUNT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, BYTE_COUNT_MAP, enforcement_key)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_u16_u32_entry(ebpf: &mut Ebpf, map_name: &str, key: u16) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{map_name}`")))?;
    let mut typed = BpfHashMap::<_, u16, u32>::try_from(map).map_err(|err| {
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
        .map_err(|err| LsdcError::Enforcement(format!("failed to convert program to XDP: {err}")))?;
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
        .join("liquid-data-plane-ebpf")
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
                    protocol: TransportProtocol::Udp,
                    session_port: None,
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
        let plane = LiquidDataPlane::new();
        let agreement = make_agreement("agreement-test", None);

        let handle = plane.enforce(&agreement, "lo").await.unwrap();

        assert_eq!(handle.id, agreement.agreement_id.0);
        assert_eq!(handle.interface, "lo");
        assert!(handle.session_port >= 20_000);
    }

    #[tokio::test]
    async fn test_allows_multiple_active_agreements_on_interface() {
        let plane = LiquidDataPlane::new();
        let first = make_agreement("agreement-test-1", None);
        let second = make_agreement("agreement-test-2", None);

        let first_handle = plane.enforce(&first, "lo").await.unwrap();
        let second_handle = plane.enforce(&second, "lo").await.unwrap();

        assert_ne!(first_handle.session_port, second_handle.session_port);
    }

    #[tokio::test]
    async fn test_expiry_transitions_status_to_expired() {
        let plane = LiquidDataPlane::new();
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
        let plane = LiquidDataPlane::new();
        let agreement = make_agreement("agreement-revoked", None);

        let handle = plane.enforce(&agreement, "lo").await.unwrap();
        plane.revoke(&handle).await.unwrap();

        let status = plane.status(&handle).await.unwrap();
        assert!(matches!(status, EnforcementStatus::Revoked));
    }
}
