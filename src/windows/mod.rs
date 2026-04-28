//! Windows sandbox: SYSTEM service via named pipe.
//!
//! All VM operations are delegated to `tokimo-sandbox-svc.exe`, a Windows
//! service running as `localSystem`. The library auto-installs the service
//! on first use via a one-time UAC prompt.
//!
//! ## Debugging
//!
//! Run the service in console mode for local development:
//!
//! ```text
//! cargo build --bin tokimo-sandbox-svc
//! .\target\debug\tokimo-sandbox-svc.exe --console
//! ```
//!
//! The library auto-detects a console-mode service already running and skips
//! the auto-install step.

mod svc;

use crate::{Error, ExecutionResult, Result};

use std::path::PathBuf;

const DEFAULT_MEMORY_MB: u64 = 512;
const DEFAULT_CPUS: usize = 2;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) fn run<S: AsRef<str>>(cmd: &[S], cfg: &crate::config::SandboxConfig) -> Result<ExecutionResult> {
    if cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }

    let shell_cmd = cmd
        .iter()
        .map(|s| shell_escape(s.as_ref()))
        .collect::<Vec<_>>()
        .join(" ");

    use base64::Engine;
    let cmd_b64 = base64::engine::general_purpose::STANDARD.encode(shell_cmd.as_bytes());

    let kernel = find_kernel()?;
    let initrd = find_initrd()?;
    let rootfs = find_rootfs(cfg)?;
    let memory_mb: u64 = std::env::var("TOKIMO_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MB);
    let cpu_count: usize = std::env::var("TOKIMO_CPUS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CPUS);

    svc::client::exec_vm(&kernel, &initrd, &rootfs, &cmd_b64, memory_mb, cpu_count)
}

pub(crate) fn spawn_session_shell(_cfg: &crate::config::SandboxConfig) -> Result<crate::session::ShellHandle> {
    Err(Error::validation(
        "Session not yet supported on Windows. Use run() for one-shot execution.",
    ))
}

pub(crate) fn run_without_sandbox<S: AsRef<str>>(
    _cmd: &[S],
    _cfg: &crate::config::SandboxConfig,
) -> Result<ExecutionResult> {
    Err(Error::validation("SAFEBOX_DISABLE is not supported on Windows"))
}

// ---------------------------------------------------------------------------
// Shell escaping
// ---------------------------------------------------------------------------

fn shell_escape(s: &str) -> String {
    if s.contains('\'') || s.contains('\\') || s.contains('"') || s.contains('$') || s.contains(' ') {
        let escaped = s.replace('\'', "'\\''");
        format!("'{}'", escaped)
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Path discovery (kernel, initrd, rootfs)
// ---------------------------------------------------------------------------

fn find_kernel() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_KERNEL") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(Error::exec(format!("TOKIMO_KERNEL={} not found", pb.display())));
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        let pb = PathBuf::from(&home).join(".tokimo/kernel/vmlinuz");
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in &["vmlinuz", "bzImage", "kernel"] {
                let pb = dir.join(name);
                if pb.exists() {
                    return Ok(pb);
                }
            }
        }
    }
    Err(Error::validation(
        "Linux kernel not found. Set TOKIMO_KERNEL=/path/to/vmlinuz or place it at \
         ~/.tokimo/kernel/vmlinuz. Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}

fn find_initrd() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_INITRD") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(Error::exec(format!("TOKIMO_INITRD={} not found", pb.display())));
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        let pb = PathBuf::from(&home).join(".tokimo/initrd.img");
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in &["initrd.img", "initramfs.cpio.gz", "initrd"] {
                let pb = dir.join(name);
                if pb.exists() {
                    return Ok(pb);
                }
            }
        }
    }
    Err(Error::validation(
        "Initrd not found. Set TOKIMO_INITRD=/path/to/initrd.img or place it at \
         ~/.tokimo/initrd.img. Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}

fn find_rootfs(cfg: &crate::config::SandboxConfig) -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_ROOTFS") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(Error::exec(format!("TOKIMO_ROOTFS={} not found", pb.display())));
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        let pb = PathBuf::from(&home).join(".tokimo/rootfs");
        if pb.exists() {
            return Ok(pb);
        }
    }
    if cfg.work_dir.join("usr").exists() {
        return Ok(cfg.work_dir.clone());
    }
    Err(Error::validation(
        "Rootfs not found. Set TOKIMO_ROOTFS=/path/to/rootfs or place it at \
         ~/.tokimo/rootfs/. Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}
