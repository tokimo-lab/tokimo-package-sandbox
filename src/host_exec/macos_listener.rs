//! macOS host-exec vsock listener (port 5556).
//!
//! Accepts inbound vsock connections from `tokimo-host-exec` running
//! inside the guest VM and dispatches each to a worker thread that calls
//! [`HostExecBridge::handle_one`].

#![cfg(target_os = "macos")]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use arcbox_vz::VirtioSocketListener;
use tokio::runtime::Runtime;

use super::HostExecBridge;

/// Spawn the host-exec vsock accept loop. Each accepted guest connection is
/// handled by a dedicated worker thread via [`HostExecBridge::handle_one`].
pub(super) fn start(
    bridge: Arc<HostExecBridge>,
    mut listener: VirtioSocketListener,
    runtime: Arc<Runtime>,
) -> std::io::Result<()> {
    let shutdown = bridge.shutdown_flag();
    runtime.spawn(async move {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept().await {
                Ok(conn) => {
                    use std::os::fd::FromRawFd;
                    let raw = conn.into_raw_fd();
                    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw) };
                    let b = bridge.clone();
                    std::thread::Builder::new()
                        .name("host-exec-worker".into())
                        .spawn(move || b.handle_one(stream))
                        .ok();
                }
                Err(e) => {
                    if !shutdown.load(Ordering::Relaxed) {
                        tracing::warn!("host-exec vsock listener accept failed: {e}");
                    }
                    break;
                }
            }
        }
    });
    Ok(())
}
