//! Public Sandbox API.
//!
//! Command-style RPC interface inspired by Claude `cowork-svc.exe`. Single
//! `Sandbox` handle exposes 17 commands. Backed by a per-platform
//! [`SandboxBackend`](crate::backend::SandboxBackend) implementation:
//!
//! * **Windows** — talks over a named pipe to `tokimo-sandbox-svc.exe`,
//!   which orchestrates a Hyper-V (HCS) micro-VM running Linux.
//! * **Linux**   — wraps `bwrap` + the in-sandbox `tokimo-sandbox-init`
//!   guest binary directly in-process.
//! * **macOS**   — boots a Linux VM via Apple Virtualization framework
//!   (arcbox-vz), guest-side init binary same as Linux.
//!
//! Network policies, hooks, and CA installation are TODO and currently
//! behave as `AllowAll`.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Network policy. Currently both variants behave identically (allow-all)
/// because the network-hook layer is a TODO across all backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Forward all traffic; no host-side filtering.
    AllowAll,
    /// Block all egress. Currently behaves as AllowAll (TODO).
    Blocked,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy::AllowAll
    }
}

/// Plan9 / virtiofs share — a host directory exposed to the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan9Share {
    /// Logical share name. Used as the 9p tag and the guest mount tag.
    pub name: String,
    /// Host-side directory.
    pub host_path: PathBuf,
    /// Guest mount point (absolute path inside the VM).
    pub guest_path: PathBuf,
    /// Mount the share read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// Configuration passed to [`Sandbox::configure`]. All non-Windows fields
/// are honoured on every platform; the *Path* / disk fields are Windows-only
/// and are silently ignored on Linux/macOS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigureParams {
    /// Logical session name (used for VM id, log prefixes, persistent
    /// rootfs lookup).
    pub user_data_name: String,

    /// VM memory budget (mebibytes). Default 4096.
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,

    /// Virtual CPU count. Default 4.
    #[serde(default = "default_cpu_count")]
    pub cpu_count: u32,

    /// Plan9 / virtiofs shares (host ↔ guest path bindings).
    #[serde(default)]
    pub plan9_shares: Vec<Plan9Share>,

    /// Network policy. Currently TODO, defaults to AllowAll.
    #[serde(default)]
    pub network: NetworkPolicy,

    // ---- Windows-only fields -------------------------------------------
    //
    // Linux/macOS backends ignore these.
    /// Path to the persistent rootfs VHDX (Windows). If `None`, the
    /// service auto-discovers from `<repo>/vm/rootfs.vhdx`.
    #[serde(default)]
    pub vhdx_path: Option<PathBuf>,

    /// Path to the Linux kernel image (Windows). If `None`, auto-discovered.
    #[serde(default)]
    pub kernel_path: Option<PathBuf>,

    /// Path to the Linux initrd image (Windows). If `None`, auto-discovered.
    #[serde(default)]
    pub initrd_path: Option<PathBuf>,

    /// Optional secondary scratch VHDX path (Windows).
    #[serde(default)]
    pub session_disk_path: Option<PathBuf>,

    /// Optional conda persistent VHDX path (Windows).
    #[serde(default)]
    pub conda_disk_path: Option<PathBuf>,

    /// URL the host probes to monitor guest API reachability (e.g.
    /// `http://10.0.0.1:1234/healthz`). When set, the service emits
    /// [`Event::ApiReachability`] events.
    #[serde(default)]
    pub api_probe_url: Option<String>,

    /// Session identifier (UUID).  External caller controls this.
    ///
    /// Connections that supply the same `session_id` share a single VM
    /// instance — the second `configure()` returns immediately and the
    /// caller can issue `exec` / `spawn` against the already-running VM.
    ///
    /// When empty the service generates a random UUID (effectively
    /// one-shot — no reconnect possible).
    #[serde(default)]
    pub session_id: String,
}

fn default_memory_mb() -> u64 {
    4096
}
fn default_cpu_count() -> u32 {
    4
}

/// Opaque guest-side child process identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

impl JobId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for JobId {
    fn from(s: String) -> Self {
        JobId(s)
    }
}

/// Asynchronous events delivered via [`Sandbox::subscribe`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Stdout chunk from a spawned child.
    Stdout { id: JobId, data: Vec<u8> },
    /// Stderr chunk from a spawned child.
    Stderr { id: JobId, data: Vec<u8> },
    /// Child exited.
    Exit {
        id: JobId,
        exit_code: i32,
        signal: Option<i32>,
    },
    /// Asynchronous error pertaining to a child or the session.
    Error {
        id: Option<JobId>,
        message: String,
        fatal: bool,
    },
    /// Guest reported "ready" (init connected, mounts done).
    Ready,
    /// Guest connection state changed.
    GuestConnected { connected: bool },
    /// Network status. Currently informational only — see TODOs.
    NetworkStatus { up: bool, message: String },
    /// API reachability probe result (controlled by `api_probe_url`).
    ApiReachability { reachable: bool, latency_ms: Option<u64> },
    /// Raw notification from the service for which there's no typed variant
    /// yet. `method` is the wire method name, `params` is the JSON payload.
    Raw { method: String, params: serde_json::Value },
}

// ---------------------------------------------------------------------------
// Sandbox handle
// ---------------------------------------------------------------------------

/// The single public entry point. Cheap to clone (internally `Arc`).
///
/// Lifecycle:
/// 1. [`Sandbox::connect`] — open the control plane (Windows: pipe to svc;
///    Linux/macOS: in-process state).
/// 2. [`Sandbox::configure`] — supply `ConfigureParams`.
/// 3. [`Sandbox::create_vm`] (Windows-only; no-op on Linux/macOS) +
///    [`Sandbox::start_vm`] — boot the guest. A shell is auto-started.
/// 4. [`Sandbox::shell_id`] — get the shell's [`JobId`].
/// 5. [`Sandbox::write_stdin`] — send commands/data to the shell.
///    [`Sandbox::subscribe`] — receive stdout/stderr/exit events.
/// 6. [`Sandbox::stop_vm`] — shut down.
#[derive(Clone)]
pub struct Sandbox {
    inner: Arc<dyn SandboxBackend>,
}

impl Sandbox {
    /// Construct a Sandbox with an explicit backend. Mainly used by
    /// per-platform constructors and tests.
    pub fn new(backend: Arc<dyn SandboxBackend>) -> Self {
        Self { inner: backend }
    }

    /// Connect to the platform-default sandbox control plane.
    ///
    /// * Windows — opens `\\.\pipe\tokimo-sandbox-svc` and performs `Hello`.
    /// * Linux   — constructs an in-process backend; no real connection.
    /// * macOS   — constructs an in-process backend; no real connection.
    pub fn connect() -> Result<Self> {
        let backend = crate::platform::default_backend()?;
        Ok(Self::new(backend))
    }

    // ---- Lifecycle ------------------------------------------------------

    pub fn configure(&self, params: ConfigureParams) -> Result<()> {
        validate_configure(&params)?;
        self.inner.configure(params)
    }

    /// Create the VM (on Windows: HCS compute system). On Linux/macOS this
    /// is a no-op that always succeeds — the VM/sandbox lifecycle is fully
    /// covered by [`Sandbox::start_vm`] on those platforms.
    pub fn create_vm(&self) -> Result<()> {
        self.inner.create_vm()
    }

    /// Start the VM and wait for the guest to connect.
    pub fn start_vm(&self) -> Result<()> {
        self.inner.start_vm()
    }

    /// Stop the VM and tear down all guest processes.
    pub fn stop_vm(&self) -> Result<()> {
        self.inner.stop_vm()
    }

    // ---- Status ---------------------------------------------------------

    pub fn is_running(&self) -> Result<bool> {
        self.inner.is_running()
    }

    pub fn is_guest_connected(&self) -> Result<bool> {
        self.inner.is_guest_connected()
    }

    pub fn is_process_running(&self, id: &JobId) -> Result<bool> {
        self.inner.is_process_running(id)
    }

    // ---- Process control ------------------------------------------------

    /// Return the [`JobId`] of the boot-time shell auto-started by
    /// [`Sandbox::start_vm`]. Use with [`Sandbox::write_stdin`] to send
    /// commands and [`Sandbox::subscribe`] to receive output.
    pub fn shell_id(&self) -> Result<JobId> {
        self.inner.shell_id()
    }

    /// Spawn an additional shell inside the running VM and return its
    /// [`JobId`]. Each shell has independent stdin/stdout/stderr streams
    /// (events from this shell are tagged with the returned id). Allows
    /// API-level concurrency: multiple shells can run in parallel and be
    /// individually written to / signalled / closed.
    pub fn spawn_shell(&self) -> Result<JobId> {
        self.inner.spawn_shell()
    }

    /// Terminate a shell (sends SIGTERM and drops bookkeeping). Works on
    /// the boot shell or any shell returned by [`Sandbox::spawn_shell`].
    pub fn close_shell(&self, id: &JobId) -> Result<()> {
        self.inner.close_shell(id)
    }

    /// Enumerate all currently-active shell JobIds in this session
    /// (boot shell + any live `spawn_shell` returns). Order is
    /// unspecified. Useful for UIs that need to render a session's
    /// running shells, or for graceful shutdown loops.
    pub fn list_shells(&self) -> Result<Vec<JobId>> {
        self.inner.list_shells()
    }

    /// Write bytes to the stdin of a child process (typically a shell).
    /// Send `\x03` (Ctrl+C) to interrupt, `\x04` (Ctrl+D) for EOF.
    pub fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        self.inner.write_stdin(id, data)
    }

    /// Deliver a POSIX signal to a specific shell's foreground process
    /// group. The signal value is the raw Linux number (`2` for SIGINT,
    /// `15` for SIGTERM, etc.).
    ///
    /// Sending Ctrl+C bytes to stdin via [`Sandbox::write_stdin`] does
    /// **not** raise SIGINT in pipe mode — only a PTY would, and shells
    /// are in pipe mode. Use this method instead.
    pub fn signal_shell(&self, id: &JobId, sig: i32) -> Result<()> {
        self.inner.signal_shell(id, sig)
    }

    /// Convenience wrapper for `signal_shell(id, 2)` (SIGINT).
    pub fn interrupt_shell(&self, id: &JobId) -> Result<()> {
        self.inner.signal_shell(id, 2)
    }

    // ---- Events ---------------------------------------------------------

    /// Subscribe to async events. The returned receiver is multiplexed over
    /// the existing control-plane connection — multiple subscribers are
    /// supported and each gets its own clone of the event stream.
    pub fn subscribe(&self) -> Result<std::sync::mpsc::Receiver<Event>> {
        self.inner.subscribe()
    }

    // ---- Disk / debug / passthrough -------------------------------------

    /// Create a fixed-size virtual disk image at `path` (Windows: VHDX via
    /// CreateVirtualDisk; Linux/macOS: returns NotSupported).
    pub fn create_disk_image(&self, path: &std::path::Path, gib: u64) -> Result<()> {
        self.inner.create_disk_image(path, gib)
    }

    pub fn set_debug_logging(&self, enabled: bool) -> Result<()> {
        self.inner.set_debug_logging(enabled)
    }

    pub fn is_debug_logging_enabled(&self) -> Result<bool> {
        self.inner.is_debug_logging_enabled()
    }

    /// Forward a guest-RPC response to the service's RPC server. Used by
    /// callers implementing the Claude-style "guest asks host" RPC pattern.
    /// Currently a TODO placeholder on all platforms.
    pub fn send_guest_response(&self, raw: serde_json::Value) -> Result<()> {
        self.inner.send_guest_response(raw)
    }

    /// Pass a method/params pair through to the underlying control-plane
    /// without typing. Used for methods not yet exposed by typed APIs.
    pub fn passthrough(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        self.inner.passthrough(method, params)
    }

    // ---- Dynamic Plan9 share management --------------------------------

    /// Mount a new Plan9 share into the running guest. Equivalent to a
    /// runtime version of [`ConfigureParams::plan9_shares`] — must be
    /// called only after [`Sandbox::start_vm`]. Returns an error if the
    /// VM is not running, the share name collides with an existing share,
    /// or the host path cannot be canonicalised.
    pub fn add_plan9_share(&self, share: Plan9Share) -> Result<()> {
        if share.name.is_empty() {
            return Err(Error::validation("plan9 share name must not be empty"));
        }
        self.inner.add_plan9_share(share)
    }

    /// Unmount a previously added Plan9 share by `name`. The matching
    /// share must have been added via [`Sandbox::add_plan9_share`] (the
    /// boot-time shares listed in [`ConfigureParams::plan9_shares`]
    /// cannot be removed at runtime).
    pub fn remove_plan9_share(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::validation("plan9 share name must not be empty"));
        }
        self.inner.remove_plan9_share(name)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_configure(p: &ConfigureParams) -> Result<()> {
    if p.user_data_name.is_empty() {
        return Err(Error::validation("user_data_name must not be empty"));
    }
    if p.memory_mb < 256 {
        return Err(Error::validation("memory_mb must be >= 256"));
    }
    if p.cpu_count == 0 || p.cpu_count > 64 {
        return Err(Error::validation("cpu_count must be in 1..=64"));
    }
    let mut seen_names = std::collections::HashSet::new();
    let mut seen_guest = std::collections::HashSet::new();
    for s in &p.plan9_shares {
        if s.name.is_empty() {
            return Err(Error::validation("plan9 share name must not be empty"));
        }
        if !seen_names.insert(s.name.clone()) {
            return Err(Error::validation(format!("duplicate plan9 share name: {}", s.name)));
        }
        if !seen_guest.insert(s.guest_path.clone()) {
            return Err(Error::validation(format!(
                "duplicate plan9 share guest_path: {}",
                s.guest_path.display()
            )));
        }
    }
    Ok(())
}
