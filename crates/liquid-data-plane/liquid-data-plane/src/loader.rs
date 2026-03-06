use crate::compiler::compile_agreement;
use crate::maps::CompiledPolicy;
use chrono::{DateTime, Utc};
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::traits::{DataPlane, EnforcementHandle, EnforcementStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use crate::maps::{ACTIVE_AGREEMENT_KEY, ACTIVE_AGREEMENT_MAP, PACKET_COUNT_MAP, RATE_LIMIT_MAP};
#[cfg(target_os = "linux")]
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{Xdp, XdpFlags, XdpLinkId},
    Ebpf,
};
#[cfg(target_os = "linux")]
use std::convert::TryInto;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
const XDP_PROGRAM_NAME: &str = "lsdc_xdp";

/// The Liquid Data Plane enforces the reduced Sprint 0 policy DSL via XDP.
///
/// Linux hosts attach a real XDP program and populate maps.
/// Other platforms keep the same lifecycle semantics in simulation mode.
pub struct LiquidDataPlane {
    inner: Arc<Inner>,
}

struct Inner {
    tracked: Mutex<HashMap<String, TrackedEnforcement>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecycleState {
    Active,
    Expired,
    Revoked,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Error(String),
}

struct TrackedEnforcement {
    interface: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    enforcement_key: u32,
    max_packets: u64,
    expires_at: Option<DateTime<Utc>>,
    state: LifecycleState,
    #[cfg(target_os = "linux")]
    platform: Option<LinuxAttachment>,
}

#[cfg(target_os = "linux")]
struct LinuxAttachment {
    ebpf: Ebpf,
    link_id: Option<XdpLinkId>,
}

impl Default for LiquidDataPlane {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                tracked: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl LiquidDataPlane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile and return the reduced enforcement plan without attaching it.
    pub fn compile(&self, agreement: &ContractAgreement) -> Result<CompiledPolicy> {
        compile_agreement(agreement)
    }

    async fn reserve_tracking(
        &self,
        handle: &EnforcementHandle,
        compiled: &CompiledPolicy,
    ) -> Result<()> {
        let mut tracked = self.inner.tracked.lock().await;
        if tracked.values().any(|entry| {
            entry.interface == handle.interface && entry.state == LifecycleState::Active
        }) {
            return Err(LsdcError::Enforcement(format!(
                "interface `{}` already has an active agreement",
                handle.interface
            )));
        }

        tracked.insert(
            handle.id.clone(),
            TrackedEnforcement {
                interface: handle.interface.clone(),
                enforcement_key: compiled.enforcement_key,
                max_packets: compiled.max_packets,
                expires_at: compiled.expires_at,
                state: LifecycleState::Active,
                #[cfg(target_os = "linux")]
                platform: None,
            },
        );

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn remove_tracking(&self, handle_id: &str) {
        self.inner.tracked.lock().await.remove(handle_id);
    }

    #[cfg(target_os = "linux")]
    async fn install_linux_attachment(
        &self,
        handle_id: &str,
        attachment: LinuxAttachment,
    ) -> Result<()> {
        let mut tracked = self.inner.tracked.lock().await;
        let entry = tracked.get_mut(handle_id).ok_or_else(|| {
            LsdcError::Enforcement(format!(
                "cannot install Linux attachment for unknown handle `{handle_id}`"
            ))
        })?;
        entry.platform = Some(attachment);
        Ok(())
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
            let _ = inner.deactivate(&handle_id, LifecycleState::Expired).await;
        });
    }
}

impl Inner {
    #[cfg(target_os = "linux")]
    async fn deactivate(&self, handle_id: &str, next_state: LifecycleState) -> Result<()> {
        let platform = {
            let mut tracked = self.tracked.lock().await;
            let Some(entry) = tracked.get_mut(handle_id) else {
                return Ok(());
            };

            if entry.state != LifecycleState::Active {
                return Ok(());
            }

            entry.state = next_state;
            entry.platform.take()
        };
        if let Some(attachment) = platform {
            if let Err(err) = detach_linux(attachment) {
                let mut tracked = self.tracked.lock().await;
                if let Some(entry) = tracked.get_mut(handle_id) {
                    entry.state = LifecycleState::Error(err.to_string());
                }
                return Err(err);
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn deactivate(&self, handle_id: &str, next_state: LifecycleState) -> Result<()> {
        let mut tracked = self.tracked.lock().await;
        if let Some(entry) = tracked.get_mut(handle_id) {
            if entry.state == LifecycleState::Active {
                entry.state = next_state;
            }
        }
        Ok(())
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
        tracing::info!(
            agreement_id = %compiled.agreement_id,
            enforcement_key = compiled.enforcement_key,
            max_packets = compiled.max_packets,
            interface = iface,
            "Enforcing Sprint 0 packet-cap policy"
        );

        let handle = EnforcementHandle {
            id: agreement.agreement_id.0.clone(),
            interface: iface.to_string(),
            active: true,
        };

        self.reserve_tracking(&handle, &compiled).await?;

        #[cfg(target_os = "linux")]
        {
            match enforce_linux(&compiled, iface).await {
                Ok(attachment) => {
                    self.install_linux_attachment(&handle.id, attachment)
                        .await?
                }
                Err(err) => {
                    self.remove_tracking(&handle.id).await;
                    return Err(err);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        tracing::warn!(
            agreement_id = %compiled.agreement_id,
            "Non-Linux platform: running in simulation mode"
        );

        self.spawn_expiry_task(handle.id.clone(), compiled.expires_at);
        Ok(handle)
    }

    async fn revoke(&self, handle: &EnforcementHandle) -> Result<()> {
        tracing::info!(handle_id = %handle.id, "Revoking enforcement");
        self.inner
            .deactivate(&handle.id, LifecycleState::Revoked)
            .await
    }

    async fn status(&self, handle: &EnforcementHandle) -> Result<EnforcementStatus> {
        let tracked = self.inner.tracked.lock().await;
        let Some(entry) = tracked.get(&handle.id) else {
            return Ok(EnforcementStatus::Revoked);
        };

        match &entry.state {
            LifecycleState::Active => {
                #[cfg(target_os = "linux")]
                let packets_processed = match entry.platform.as_ref() {
                    Some(platform) => read_packet_count(platform, entry.enforcement_key)?,
                    None => 0,
                };

                #[cfg(not(target_os = "linux"))]
                let packets_processed = 0;

                tracing::debug!(
                    handle_id = %handle.id,
                    max_packets = entry.max_packets,
                    expires_at = ?entry.expires_at,
                    packets_processed,
                    "Read enforcement status"
                );

                Ok(EnforcementStatus::Active { packets_processed })
            }
            LifecycleState::Expired => Ok(EnforcementStatus::Expired),
            LifecycleState::Revoked => Ok(EnforcementStatus::Revoked),
            LifecycleState::Error(message) => Ok(EnforcementStatus::Error(message.clone())),
        }
    }
}

#[cfg(target_os = "linux")]
async fn enforce_linux(compiled: &CompiledPolicy, iface: &str) -> Result<LinuxAttachment> {
    let mut ebpf = load_ebpf_object()?;
    populate_linux_maps(&mut ebpf, compiled)?;

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
fn populate_linux_maps(ebpf: &mut Ebpf, compiled: &CompiledPolicy) -> Result<()> {
    {
        let map = ebpf.map_mut(ACTIVE_AGREEMENT_MAP).ok_or_else(|| {
            LsdcError::Enforcement(format!("missing map `{ACTIVE_AGREEMENT_MAP}`"))
        })?;
        let mut active_map = BpfHashMap::<_, u32, u32>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{ACTIVE_AGREEMENT_MAP}` as hash map: {err}"
            ))
        })?;
        active_map
            .insert(ACTIVE_AGREEMENT_KEY, compiled.enforcement_key, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!(
                    "failed to populate `{ACTIVE_AGREEMENT_MAP}`: {err}"
                ))
            })?;
    }

    {
        let map = ebpf
            .map_mut(RATE_LIMIT_MAP)
            .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{RATE_LIMIT_MAP}`")))?;
        let mut rate_limit_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{RATE_LIMIT_MAP}` as hash map: {err}"
            ))
        })?;
        rate_limit_map
            .insert(compiled.enforcement_key, compiled.max_packets, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!("failed to populate `{RATE_LIMIT_MAP}`: {err}"))
            })?;
    }

    {
        let map = ebpf
            .map_mut(PACKET_COUNT_MAP)
            .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{PACKET_COUNT_MAP}`")))?;
        let mut packet_count_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{PACKET_COUNT_MAP}` as hash map: {err}"
            ))
        })?;
        let _ = packet_count_map.remove(&compiled.enforcement_key);
        packet_count_map
            .insert(compiled.enforcement_key, 0_u64, 0)
            .map_err(|err| {
                LsdcError::Enforcement(format!("failed to initialize `{PACKET_COUNT_MAP}`: {err}"))
            })?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn read_packet_count(platform: &LinuxAttachment, enforcement_key: u32) -> Result<u64> {
    let map = platform
        .ebpf
        .map(PACKET_COUNT_MAP)
        .ok_or_else(|| LsdcError::Enforcement(format!("missing map `{PACKET_COUNT_MAP}`")))?;
    let packet_count_map = BpfHashMap::<_, u32, u64>::try_from(map).map_err(|err| {
        LsdcError::Enforcement(format!(
            "failed to open `{PACKET_COUNT_MAP}` as hash map: {err}"
        ))
    })?;
    packet_count_map.get(&enforcement_key, 0).map_err(|err| {
        LsdcError::Enforcement(format!(
            "failed to read packet count for key `{enforcement_key}`: {err}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn detach_linux(mut attachment: LinuxAttachment) -> Result<()> {
    let Some(link_id) = attachment.link_id.take() else {
        return Ok(());
    };

    {
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
    }

    clear_linux_maps(&mut attachment.ebpf)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_linux_maps(ebpf: &mut Ebpf) -> Result<()> {
    {
        let map = ebpf.map_mut(ACTIVE_AGREEMENT_MAP).ok_or_else(|| {
            LsdcError::Enforcement(format!("missing map `{ACTIVE_AGREEMENT_MAP}`"))
        })?;
        let mut active_map = BpfHashMap::<_, u32, u32>::try_from(map).map_err(|err| {
            LsdcError::Enforcement(format!(
                "failed to open `{ACTIVE_AGREEMENT_MAP}` as hash map: {err}"
            ))
        })?;
        let _ = active_map.remove(&ACTIVE_AGREEMENT_KEY);
    }
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
    use lsdc_common::odrl::ast::{Action, Constraint, Permission, PolicyAgreement, PolicyId};

    fn make_agreement(valid_until: Option<DateTime<Utc>>) -> ContractAgreement {
        ContractAgreement {
            agreement_id: PolicyId("agreement-test".into()),
            policy: PolicyAgreement {
                id: PolicyId("policy-test".into()),
                provider: "did:web:provider".into(),
                consumer: "did:web:consumer".into(),
                target: "urn:data:test".into(),
                permissions: vec![Permission {
                    action: Action::Stream,
                    constraints: vec![Constraint::Count { max: 5 }],
                    duties: vec![],
                }],
                prohibitions: vec![],
                obligations: vec![],
                valid_from: Utc::now(),
                valid_until,
            },
        }
    }

    #[tokio::test]
    async fn test_reuses_agreement_id_for_handle_identity() {
        let plane = LiquidDataPlane::new();
        let agreement = make_agreement(None);

        let handle = plane.enforce(&agreement, "lo").await.unwrap();

        assert_eq!(handle.id, agreement.agreement_id.0);
        assert_eq!(handle.interface, "lo");
    }

    #[tokio::test]
    async fn test_rejects_second_active_agreement_on_interface() {
        let plane = LiquidDataPlane::new();
        let first = make_agreement(None);
        let second = ContractAgreement {
            agreement_id: PolicyId("agreement-test-2".into()),
            policy: first.policy.clone(),
        };

        plane.enforce(&first, "lo").await.unwrap();
        let err = plane.enforce(&second, "lo").await.unwrap_err();
        assert!(err.to_string().contains("already has an active agreement"));
    }

    #[tokio::test]
    async fn test_expiry_transitions_status_to_expired() {
        let plane = LiquidDataPlane::new();
        let agreement = make_agreement(Some(Utc::now() + Duration::milliseconds(20)));

        let handle = plane.enforce(&agreement, "lo").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let status = plane.status(&handle).await.unwrap();
        assert!(matches!(status, EnforcementStatus::Expired));
    }

    #[tokio::test]
    async fn test_revoke_transitions_status_to_revoked() {
        let plane = LiquidDataPlane::new();
        let agreement = make_agreement(None);

        let handle = plane.enforce(&agreement, "lo").await.unwrap();
        plane.revoke(&handle).await.unwrap();

        let status = plane.status(&handle).await.unwrap();
        assert!(matches!(status, EnforcementStatus::Revoked));
    }
}
