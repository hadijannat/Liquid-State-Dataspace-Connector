use crate::projection::{
    CompiledPolicy, BYTE_COUNT_MAP, BYTE_LIMIT_MAP, PACKET_COUNT_MAP, PACKET_LIMIT_MAP,
    SELECTOR_AGREEMENT_MAP,
};
use crate::runtime::LinuxAttachment;
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{xdp::XdpLinkId, Xdp, XdpFlags},
    Ebpf,
};
use lsdc_common::error::{LsdcError, Result};
use std::convert::TryInto;
use std::path::{Path, PathBuf};

const XDP_PROGRAM_NAME: &str = "lsdc_xdp";

pub(crate) fn attach_linux(iface: &str) -> Result<LinuxAttachment> {
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

pub(crate) fn insert_linux_maps(ebpf: &mut Ebpf, compiled: &CompiledPolicy) -> Result<()> {
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

pub(crate) fn remove_linux_maps(
    ebpf: &mut Ebpf,
    enforcement_key: u32,
    selector_key: u32,
) -> Result<()> {
    remove_u32_u32_entry(ebpf, SELECTOR_AGREEMENT_MAP, selector_key)?;
    remove_u32_u64_entry(ebpf, PACKET_LIMIT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, BYTE_LIMIT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, PACKET_COUNT_MAP, enforcement_key)?;
    remove_u32_u64_entry(ebpf, BYTE_COUNT_MAP, enforcement_key)?;
    Ok(())
}

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

pub(crate) fn read_counters(
    attachment: &LinuxAttachment,
    enforcement_key: u32,
) -> Result<(u64, u64)> {
    Ok((
        read_counter(&attachment.ebpf, PACKET_COUNT_MAP, enforcement_key)?,
        read_counter(&attachment.ebpf, BYTE_COUNT_MAP, enforcement_key)?,
    ))
}

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

pub(crate) fn detach_linux(mut attachment: LinuxAttachment) -> Result<()> {
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

fn load_ebpf_object() -> Result<Ebpf> {
    let path = resolve_ebpf_object_path()?;
    Ebpf::load_file(&path).map_err(|err| {
        LsdcError::Enforcement(format!(
            "failed to load eBPF object `{}`: {err}",
            path.display()
        ))
    })
}

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
