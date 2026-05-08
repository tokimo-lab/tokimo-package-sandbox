//! macOS host-exec vsock listener (port 5556).
//!
//! Accepts inbound vsock connections from `tokimo-host-exec` running
//! inside the guest VM and dispatches each to a worker thread.

#![cfg(target_os = "macos")]

use std::sync::Arc;

use super::HostExecBridge;

pub(super) fn start(_bridge: Arc<HostExecBridge>, _port: u32) -> std::io::Result<()> {
    // TODO macOS vsock listener implementation. The macOS backend
    // exposes vsock via arcbox-vz; wiring matches the FUSE listener
    // pattern in src/vfs_host (see `FuseHost::start_vsock_server`).
    // For this revision we leave it as a no-op so non-Linux builds
    // compile.
    tracing::warn!("host-exec macOS vsock listener not yet implemented");
    Ok(())
}
