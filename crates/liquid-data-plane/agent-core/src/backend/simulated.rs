use crate::runtime::InterfaceRuntime;
use std::collections::{HashMap, HashSet};

pub(crate) fn ensure_interface_runtime(
    interfaces: &mut HashMap<String, InterfaceRuntime>,
    iface: &str,
) {
    interfaces
        .entry(iface.to_string())
        .or_insert_with(|| InterfaceRuntime {
            active_handles: HashSet::new(),
            #[cfg(target_os = "linux")]
            attachment: None,
        });
}
