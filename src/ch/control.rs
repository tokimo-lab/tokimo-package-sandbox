//! vsock control plane interface for the Cloud Hypervisor backend.
//!
//! This module is a placeholder for the V3.0-vsock step. All public items
//! here will be fleshed out by the `v30-vsock` sub-agent.
//!
//! Planned responsibilities:
//! - Open a host-side `AF_VSOCK` connection to the guest-agent on port 1024.
//! - Implement the JSON-RPC framing codec (length-prefixed or newline-delimited).
//! - Negotiate the session handshake: send `Hello`, receive `Ready`.
//! - Multiplex shell streams: each shell gets a separate vsock port (or a
//!   tagged channel on a shared socket — TBD in v30-vsock design).
//! - Fan-out incoming `Event` frames to all `Receiver` subscribers registered
//!   via `SandboxBackend::subscribe()`.
//!
//! # Grep markers
//!
//! ```text
//! grep -rn 'TODO(v30-vsock)' packages/tokimo-package-sandbox/src/ch/
//! ```

// TODO(v30-vsock): add ChControlState struct with:
// - `socket: tokio::net::UnixStream`  (or vsock equivalent once dep is added)
// - `shell_registry: HashMap<JobId, ShellHandle>`
// - `subscribers: Vec<mpsc::Sender<Event>>`
// - `host_exec_cb: Option<HostExecCallback>`

/// Placeholder for CH vsock control plane state.
///
/// TODO(v30-vsock): replace with a real struct containing the vsock
/// connection and session registry.
pub struct ChControlState {
    _private: (),
}

impl ChControlState {
    // TODO(v30-vsock): implement ChControlState::connect(cid: u32, port: u32) -> Result<Self>
    // TODO(v30-vsock): implement ChControlState::send_rpc(&self, method, params) -> Result<Value>
    // TODO(v30-vsock): implement ChControlState::recv_loop(self) — async fan-out task
}
