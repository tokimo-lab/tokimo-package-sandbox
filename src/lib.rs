//! tokimo-package-sandbox — cross-platform native sandbox.
//!
//! Public API: a single [`Sandbox`] handle exposing 17 commands inspired
//! by Claude `cowork-svc.exe`. See the [`api`] module for details.
//!
//! ```no_run
//! use tokimo_package_sandbox::{Sandbox, ConfigureParams};
//! let sb = Sandbox::connect().unwrap();
//! sb.configure(ConfigureParams {
//!     user_data_name: "demo".into(),
//!     base_rootfs: ".vm/base".into(),
//!     vm_dir: ".vm/run".into(),
//!     session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
//!     memory_mb: 4096,
//!     cpu_count: 4,
//!     ..Default::default()
//! }).unwrap();
//! sb.create_vm().unwrap();
//! sb.start_vm().unwrap();
//! let shell = sb.shell_id().unwrap();
//! sb.write_stdin(&shell, b"echo hello\n").unwrap();
//! sb.stop_vm().unwrap();
//! ```

// ── Module tree ──────────────────────────────────────────────────────────────
pub mod api;
pub mod backends;
pub mod host_exec;
pub mod init;
pub mod net;
pub mod util;
pub mod vfs;

// ── Backward-compat shims: internal `crate::OLDNAME` paths ──────────────────
// These allow all existing `use crate::X` statements in the internal source
// files to continue compiling without modification.

// api group
pub(crate) use api::backend;
pub use api::backend_kind;
pub(crate) use api::error;
pub(crate) use api::platform;

// vfs group
pub use vfs::backend as vfs_backend;
pub use vfs::host as vfs_host;
pub use vfs::impls as vfs_impls;
pub use vfs::protocol as vfs_protocol;

// init group
pub use init::client as init_client;
pub use init::protocol;

// host_exec group
pub use host_exec::protocol as host_exec_protocol;

// backends group
#[cfg(target_os = "linux")]
pub use backends::linux;
#[cfg(target_os = "macos")]
pub(crate) use backends::macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use backends::shared as shared_backend;
pub use backends::svc_protocol;
#[cfg(target_os = "windows")]
pub(crate) use backends::windows;

// net group
pub use net::constants as net_constants;
#[cfg(target_os = "linux")]
pub use net::ifreq;
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub use net::netstack;

// util group
pub use util::affinity;
pub use util::fonts;
#[cfg(unix)]
pub use util::raw_io;
pub use util::rootfs_init;
pub use util::session_registry;
pub use util::vm_dir;
#[cfg(target_os = "linux")]
pub use util::vsock_util;

// ── Top-level re-exports from api/ ───────────────────────────────────────────
pub use api::backend::SandboxBackend;
pub use api::backend_kind::{ActiveBackend, SandboxBackendKind, detect_backend};
pub use api::error::{Error, Result};
pub use api::{
    ConfigureParams, Event, HostExecAction, HostExecCallback, HostExecCtx, JobId, Mount, NetworkPolicy,
    PortForwardSpec, Sandbox, SessionDetails, SessionSummary, ShellOpts,
};
#[cfg(target_os = "linux")]
pub use backends::linux::ch::probe::{ChProbeResult, probe_ch};
pub use util::fonts::FontDir;

#[cfg(target_os = "windows")]
pub use backends::windows::canonicalize_safe;
