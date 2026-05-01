//! Internal trait implemented by each platform backend.

use std::path::Path;
use std::sync::mpsc::Receiver;

use crate::api::{ConfigureParams, Event, JobId, Plan9Share};
use crate::error::Result;

/// Per-platform backend driving a [`Sandbox`](crate::Sandbox).
///
/// All methods are thread-safe (the trait requires `Send + Sync`). The
/// backend owns its own state and does not require the caller to hold
/// any locks.
pub trait SandboxBackend: Send + Sync + 'static {
    fn configure(&self, params: ConfigureParams) -> Result<()>;
    fn create_vm(&self) -> Result<()>;
    fn start_vm(&self) -> Result<()>;
    fn stop_vm(&self) -> Result<()>;

    fn is_running(&self) -> Result<bool>;
    fn is_guest_connected(&self) -> Result<bool>;
    fn is_process_running(&self, id: &JobId) -> Result<bool>;

    fn shell_id(&self) -> Result<JobId>;
    /// Spawn an additional shell in the running VM, returning a fresh
    /// JobId. Each shell has independent stdin/stdout/stderr streams
    /// (events are tagged with this JobId). Errors if the VM isn't
    /// running.
    fn spawn_shell(&self) -> Result<JobId>;
    /// Terminate a shell previously returned by `shell_id()` or
    /// `spawn_shell()`. Sends SIGTERM and removes the bookkeeping.
    fn close_shell(&self, id: &JobId) -> Result<()>;
    /// Enumerate all currently-active shell JobIds in this session
    /// (the boot shell from `shell_id()` plus any `spawn_shell()` returns
    /// that haven't been closed). Order is unspecified.
    fn list_shells(&self) -> Result<Vec<JobId>>;
    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()>;
    /// Deliver a POSIX signal to a specific shell's foreground process
    /// group. The signal number is the raw Linux value
    /// (`SIGINT = 2`, `SIGTERM = 15`, …).
    fn signal_shell(&self, id: &JobId, sig: i32) -> Result<()>;

    fn subscribe(&self) -> Result<Receiver<Event>>;

    fn create_disk_image(&self, path: &Path, gib: u64) -> Result<()>;
    fn set_debug_logging(&self, enabled: bool) -> Result<()>;
    fn is_debug_logging_enabled(&self) -> Result<bool>;
    fn send_guest_response(&self, raw: serde_json::Value) -> Result<()>;
    fn passthrough(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;

    // -- Dynamic Plan9 share management ------------------------------
    fn add_plan9_share(&self, share: Plan9Share) -> Result<()>;
    fn remove_plan9_share(&self, name: &str) -> Result<()>;
}
