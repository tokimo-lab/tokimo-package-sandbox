//! tokimo-package-sandbox — cross-platform command sandbox (Linux / macOS / Windows).
//!
//! ```no_run
//! use tokimo_package_sandbox::{SandboxConfig, NetworkPolicy};
//! let cfg = SandboxConfig::new("/tmp/work").network(NetworkPolicy::Blocked);
//! let out = tokimo_package_sandbox::run(&["rm", "-rf", "/"], &cfg).unwrap();
//! assert!(!out.success() || out.exit_code != 0);
//! ```

mod config;
mod error;
mod host;
mod session;

pub mod diagnostics;
pub mod protocol;
pub mod util;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod profile;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod workspace;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;
/// Wire protocol shared between the host library and `tokimo-sandbox-svc.exe`.
#[cfg(target_os = "windows")]
pub mod svc_protocol {
    pub use crate::windows::protocol::*;
}

/// TOCTOU-safe path canonicalisation used by the SYSTEM service. Exposed
/// for test harnesses; library callers don't normally need it.
#[cfg(target_os = "windows")]
pub use windows::safe_path::canonicalize_safe;

pub use config::{Mount, NetworkPolicy, ResourceLimits, SandboxConfig, SystemLayout};
pub use diagnostics::is_session_fatal_message;
pub use error::{Error, ExecutionResult, Result};
pub use host::net_observer::{DnsPolicy, HostPattern, Layer, NetEvent, NetEventSink, Proto, Verdict};
pub use session::{ExecOutput, JobHandle, OpenPtyFn, PtyHandle, RunOneshotFn, Session};
pub use util::safe_session_name;

#[cfg(target_os = "linux")]
pub use linux::init_client::{InitClient, SpawnInfo};
#[cfg(target_os = "linux")]
pub use linux::seccomp::generate_bpf_bytes;
#[cfg(target_os = "linux")]
pub use linux::{SpawnedInit, locate_init_binary, spawn_init};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use workspace::{UserConfig, UserHandle, Workspace, WorkspaceConfig};

/// Execute `cmd` inside the sandbox configured by `cfg`.
///
/// `cmd[0]` is the program, `cmd[1..]` are its arguments. The command is
/// looked up via `PATH` inside the sandbox (not the host's `PATH`).
pub fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    cfg.validate()?;

    // Escape hatch for debugging.
    if std::env::var("SAFEBOX_DISABLE").ok().as_deref() == Some("1") {
        return run_without_sandbox(cmd, cfg);
    }

    #[cfg(target_os = "linux")]
    {
        linux::run(cmd, cfg)
    }
    #[cfg(target_os = "macos")]
    {
        macos::run(cmd, cfg)
    }
    #[cfg(target_os = "windows")]
    {
        windows::run(cmd, cfg)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = cmd;
        let _ = cfg;
        Err(Error::validation("unsupported platform"))
    }
}

#[cfg(unix)]
fn run_without_sandbox<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    use std::process::Command;
    if cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }
    let mut c = Command::new(cmd[0].as_ref());
    for a in &cmd[1..] {
        c.arg(a.as_ref());
    }
    c.env_clear();
    for (k, v) in &cfg.env {
        c.env(k, v);
    }
    if let Some(cwd) = &cfg.cwd {
        c.current_dir(cwd);
    } else {
        c.current_dir(&cfg.work_dir);
    }
    host::common::pipe_stdio(&mut c);
    host::common::spawn_run(&mut c, cfg.stdin.as_deref(), &cfg.limits, cfg.stream_stderr)
}

#[cfg(windows)]
fn run_without_sandbox<S: AsRef<str>>(cmd: &[S], _cfg: &SandboxConfig) -> Result<ExecutionResult> {
    let _ = cmd;
    Err(Error::validation("SAFEBOX_DISABLE is not supported on Windows"))
}
