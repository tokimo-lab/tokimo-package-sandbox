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

#[allow(clippy::derivable_impls)]
impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy::AllowAll
    }
}

/// A host directory exposed to the guest (Plan9 on Windows, virtiofs on
/// macOS, bind mount on Linux).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    /// Logical mount name (used as the 9p tag / virtiofs tag).
    pub name: String,
    /// Host-side directory.
    pub host_path: PathBuf,
    /// Guest mount point (absolute path inside the VM).
    pub guest_path: PathBuf,
    /// Mount read-only.
    #[serde(default)]
    pub read_only: bool,
    /// If `true` and `host_path` does not exist, [`Sandbox::add_mount`]
    /// (and the boot-time mount setup) will `create_dir_all` it before
    /// handing off to the backend. Default `false` (the strictest, and
    /// the historical behaviour).
    #[serde(default)]
    pub create_host_dir: bool,
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
    /// Pass 0 for no limit (backend-specific: HCS omits the constraint,
    /// VZ requests maximum available).
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,

    /// Virtual CPU count. Default 4.
    /// Pass 0 for no limit (backend-specific: HCS omits the constraint,
    /// VZ requests maximum available).
    #[serde(default = "default_cpu_count")]
    pub cpu_count: u32,

    /// Host directories to mount into the guest.
    #[serde(default)]
    pub mounts: Vec<Mount>,

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

/// Options for [`Sandbox::spawn_shell`]. `Default` produces a pipes-mode
/// shell with the backend's default boot-shell argv (matching the
/// behaviour of the previous zero-arg `spawn_shell()`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellOpts {
    /// `Some((rows, cols))` → allocate a PTY pair and use the slave as
    /// the child's controlling terminal. `None` → pipes mode.
    #[serde(default)]
    pub pty: Option<(u16, u16)>,
    /// Optional argv override. `None` → backend-default login shell.
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    /// Env overlay applied on top of the session-wide environment.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Optional initial cwd; backend default is `/work`.
    #[serde(default)]
    pub cwd: Option<String>,
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

/// Options for [`Sandbox::add_user`].
///
/// `home` is the only required field. Init treats it as both the user's
/// `HOME` and the default starting cwd. If the directory does not exist
/// it is created (idempotent), so callers may pre-mount a host directory
/// at the same path via [`Sandbox::add_mount`] to make whatever the user
/// writes during their session land directly on the host filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddUserOpts {
    /// Absolute guest-side HOME directory.
    pub home: PathBuf,
    /// Override starting cwd. Defaults to `home`.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Extra environment variables, applied last (highest precedence).
    /// Layered on top of the per-user defaults USER, LOGNAME, HOME, PS1,
    /// MAIL.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// If `true` (default), init runs `useradd -M -d <home> -s /bin/bash
    /// -g 1000 -N <user_id>` (idempotent) and execs the shell as that
    /// uid in shared group `tokimo-users` (gid 1000) via `runuser`. On
    /// failure init falls back to running as root with USER/LOGNAME env
    /// set. If `false`, the shell always runs as root and only the env
    /// vars distinguish the user.
    #[serde(default = "default_true")]
    pub real_user: bool,
}

impl Default for AddUserOpts {
    fn default() -> Self {
        Self {
            home: PathBuf::new(),
            cwd: None,
            env: Vec::new(),
            real_user: true,
        }
    }
}

fn default_true() -> bool {
    true
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
    pub fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId> {
        self.inner.spawn_shell(opts)
    }

    /// Resize a PTY shell's controlling terminal. Sends `TIOCSWINSZ` on
    /// the master fd inside the guest and a `SIGWINCH` to the foreground
    /// process group. Errors if `id` does not refer to a PTY-mode shell.
    pub fn resize_shell(&self, id: &JobId, rows: u16, cols: u16) -> Result<()> {
        self.inner.resize_shell(id, rows, cols)
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

    /// Mount a host directory into the running guest at runtime. Must be
    /// called after [`Sandbox::start_vm`]. The mount name must not collide
    /// with boot-time mounts listed in [`ConfigureParams::mounts`].
    pub fn add_mount(&self, mount: Mount) -> Result<()> {
        if mount.name.is_empty() {
            return Err(Error::validation("mount name must not be empty"));
        }
        if mount.create_host_dir
            && let Err(e) = std::fs::create_dir_all(&mount.host_path)
        {
            return Err(Error::other(format!(
                "create_dir_all({}): {e}",
                mount.host_path.display()
            )));
        }
        self.inner.add_mount(mount)
    }

    /// Unmount a previously added runtime mount by `name`. Boot-time
    /// mounts (listed in [`ConfigureParams::mounts`]) cannot be removed.
    pub fn remove_mount(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::validation("mount name must not be empty"));
        }
        self.inner.remove_mount(name)
    }

    // ---- User management ----------------------------------------------

    /// Register a named user inside the running guest and start a bash
    /// shell scoped to that identity. Returns the shell's [`JobId`].
    ///
    /// The guest creates `opts.home` (if missing), exports the per-user
    /// env vars (`USER`, `LOGNAME`, `HOME`, `PS1`, `MAIL`) and — when
    /// `opts.real_user` is `true` — `useradd`s the account and execs the
    /// shell with that uid via `runuser`. See [`AddUserOpts`] for the
    /// fallback behaviour.
    ///
    /// The standard recipe for "guest writes go directly to host disk":
    ///
    /// ```ignore
    /// use std::path::PathBuf;
    /// use tokimo_package_sandbox::{Sandbox, Mount, AddUserOpts};
    ///
    /// let sb = Sandbox::connect()?;
    /// // ... configure / start_vm ...
    /// sb.add_mount(Mount {
    ///     name: "alice-home".into(),
    ///     host_path: PathBuf::from("/host/data/alice"),
    ///     guest_path: PathBuf::from("/home/alice"),
    ///     read_only: false,
    ///     create_host_dir: true,
    /// })?;
    /// let shell = sb.add_user("alice", AddUserOpts {
    ///     home: PathBuf::from("/home/alice"),
    ///     ..Default::default()
    /// })?;
    /// # Ok::<_, tokimo_package_sandbox::Error>(())
    /// ```
    pub fn add_user(&self, user_id: &str, opts: AddUserOpts) -> Result<JobId> {
        validate_user_id(user_id)?;
        if opts.home.as_os_str().is_empty() {
            return Err(Error::validation("AddUserOpts.home must not be empty"));
        }
        // home is a *guest* (Linux) path. Don't use Path::is_absolute()
        // because on Windows hosts that requires a drive letter, which
        // would (incorrectly) reject `/home/alice`. Just check the
        // POSIX leading-slash convention.
        let home_str = opts.home.to_string_lossy();
        if !home_str.starts_with('/') {
            return Err(Error::validation(
                "AddUserOpts.home must be a POSIX absolute path (start with '/')",
            ));
        }
        if let Some(cwd) = &opts.cwd
            && !cwd.to_string_lossy().starts_with('/')
        {
            return Err(Error::validation(
                "AddUserOpts.cwd must be a POSIX absolute path (start with '/')",
            ));
        }
        self.inner.add_user(user_id, opts)
    }

    /// Counterpart to [`Sandbox::add_user`]: SIGKILLs every shell owned
    /// by the requesting client and (if the account was created via
    /// `real_user=true`) `userdel`s it. Best-effort; succeeds even if
    /// the user was never registered.
    pub fn remove_user(&self, user_id: &str) -> Result<()> {
        validate_user_id(user_id)?;
        self.inner.remove_user(user_id)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_configure(p: &ConfigureParams) -> Result<()> {
    if p.user_data_name.is_empty() {
        return Err(Error::validation("user_data_name must not be empty"));
    }
    if p.memory_mb != 0 && p.memory_mb < 256 {
        return Err(Error::validation("memory_mb must be 0 (no limit) or >= 256"));
    }
    if p.cpu_count > 64 {
        return Err(Error::validation("cpu_count must be 0 (no limit) or in 1..=64"));
    }
    let mut seen_names = std::collections::HashSet::new();
    let mut seen_guest = std::collections::HashSet::new();
    for m in &p.mounts {
        if m.name.is_empty() {
            return Err(Error::validation("mount name must not be empty"));
        }
        if !seen_names.insert(m.name.clone()) {
            return Err(Error::validation(format!("duplicate mount name: {}", m.name)));
        }
        if !seen_guest.insert(m.guest_path.clone()) {
            return Err(Error::validation(format!(
                "duplicate mount guest_path: {}",
                m.guest_path.display()
            )));
        }
    }
    Ok(())
}

/// Validate a `user_id` for [`Sandbox::add_user`] / [`Sandbox::remove_user`].
/// Mirrors the init-side check (`is_valid_user_id`).
fn validate_user_id(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::validation("user_id must not be empty"));
    }
    if s.len() > 32 {
        return Err(Error::validation("user_id must be <= 32 chars"));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(Error::validation("user_id must match [A-Za-z0-9_-]+"));
    }
    Ok(())
}
