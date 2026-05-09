//! VM lifecycle interface for the Cloud Hypervisor backend.
//!
//! This module is a placeholder for the V3.0-spawn step. All public items
//! here will be fleshed out by the `v30-spawn` sub-agent.
//!
//! Planned responsibilities:
//! - Build the CH JSON VM configuration (memory, CPUs, kernel, initrd,
//!   virtio-fs shares, vsock device, network interface).
//! - Spawn the `cloud-hypervisor` child process with the correct flags.
//! - Manage the CH REST API socket (unix:///run/ch-<id>.sock) for hotplug.
//! - Implement graceful shutdown (SIGTERM → wait → SIGKILL).
//!
//! # Grep markers
//!
//! ```text
//! grep -rn 'TODO(v30-spawn)' packages/tokimo-package-sandbox/src/ch/
//! ```

// TODO(v30-spawn): add fields to ChVmmState (child PID, API socket path,
// config snapshot) and implement the functions below.

/// Placeholder for CH VM runtime state.
///
/// TODO(v30-spawn): replace with a real struct containing:
/// - `child: std::process::Child`
/// - `api_socket: PathBuf`   (unix socket for CH REST API)
/// - `config: VmConfig`      (serialisable JSON config sent to CH)
pub struct ChVmmState {
    _private: (),
}

impl ChVmmState {
    // TODO(v30-spawn): implement ChVmmState::spawn(binary, config) -> Result<Self>
    // TODO(v30-spawn): implement ChVmmState::stop(&mut self) -> Result<()>
    // TODO(v30-spawn): implement ChVmmState::is_alive(&mut self) -> bool
}
