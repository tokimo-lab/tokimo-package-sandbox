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
mod net_observer;
mod result;
mod session;

pub mod init_protocol;

#[cfg(target_os = "linux")]
pub mod init_wire;

#[cfg(target_os = "linux")]
pub mod init_client;

#[cfg(unix)]
mod common;

#[cfg(target_os = "linux")]
mod bridge;
#[cfg(target_os = "linux")]
mod l4;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod workspace;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

pub use config::{Mount, NetworkPolicy, ResourceLimits, SandboxConfig, SystemLayout};
pub use error::{Error, Result};
pub use net_observer::{DnsPolicy, HostPattern, Layer, NetEvent, NetEventSink, Proto, Verdict};
pub use result::ExecutionResult;
pub use session::{ExecOutput, JobHandle, OpenPtyFn, PtyHandle, RunOneshotFn, Session};

#[cfg(target_os = "linux")]
pub use linux::{SpawnedInit, locate_init_binary, spawn_init};

#[cfg(target_os = "linux")]
pub use seccomp::generate_bpf_bytes;

#[cfg(target_os = "linux")]
pub use init_client::{InitClient, SpawnInfo};

#[cfg(target_os = "linux")]
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
        return windows::run(cmd, cfg);
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
    common::pipe_stdio(&mut c);
    common::spawn_run(&mut c, cfg.stdin.as_deref(), &cfg.limits, cfg.stream_stderr)
}

#[cfg(windows)]
fn run_without_sandbox<S: AsRef<str>>(cmd: &[S], _cfg: &SandboxConfig) -> Result<ExecutionResult> {
    let _ = cmd;
    Err(Error::validation("SAFEBOX_DISABLE is not supported on Windows"))
}
