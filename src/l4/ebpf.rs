//! eBPF L4 backend — scaffold. See module docs in old version for intent.

#![cfg(feature = "ebpf")]

use super::{ChildInstall, L4Config, Pending as L4Pending};
use std::io;

pub(crate) fn is_supported() -> bool {
    let disabled = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(2);
    if disabled >= 2 {
        return false;
    }
    false // conservative: never pick until the aya loader lands.
}

pub(crate) struct Pending;

pub(crate) fn prepare(_cfg: L4Config) -> io::Result<(ChildInstall, L4Pending)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ebpf backend scaffold only — tokimo-ebpf crate not yet implemented",
    ))
}

pub(crate) struct EbpfHandle;

impl super::L4Backend for EbpfHandle {}

pub(crate) fn start_parent(_p: Pending, _cfg: L4Config) -> io::Result<EbpfHandle> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "ebpf backend scaffold only"))
}
