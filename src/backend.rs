//! Internal trait implemented by each platform backend.

use std::path::Path;
use std::sync::mpsc::Receiver;

use crate::api::{ConfigureParams, Event, JobId, Mount, SessionDetails, SessionSummary, ShellOpts};
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
    fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId>;
    /// Resize a PTY shell. Errors if the shell was spawned in pipes mode.
    fn resize_shell(&self, id: &JobId, rows: u16, cols: u16) -> Result<()>;
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

    // -- Dynamic mount management -------------------------------------
    fn add_mount(&self, mount: Mount) -> Result<()>;
    fn remove_mount(&self, name: &str) -> Result<()>;

    // -- Management / introspection -----------------------------------
    /// Enumerate sessions tracked by the backend. See
    /// [`crate::Sandbox::list_sessions`] for semantics.
    fn list_sessions(&self) -> Result<Vec<SessionSummary>>;
    /// Look up detail for one session by name; `Ok(None)` if unknown.
    fn session_info(&self, name: &str) -> Result<Option<SessionDetails>>;
    /// Force-stop a session by name, idempotent.
    fn stop_session(&self, name: &str) -> Result<()>;
}
