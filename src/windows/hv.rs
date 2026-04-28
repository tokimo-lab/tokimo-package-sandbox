//! Windows Hyper-V backend via Host Compute Service (HCS).
//!
//! Boots a lightweight Linux VM for Linux-grade isolation on Windows,
//! using the same kernel + initrd + rootfs artifacts as macOS VZ.
//!
//! ## Execution modes
//!
//! - **Serial mode (V1, `run()`)**: command passed via kernel cmdline,
//!   output collected via shared files. No tokimo-sandbox-init required.
//! - **VSOCK mode (V2, future)**: tokimo-sandbox-init as PID 1, full
//!   init protocol over Hyper-V sockets.
//!
//! ## Configuration (env vars)
//!
//! - `TOKIMO_HV_KERNEL`  — path to Linux kernel (vmlinuz)
//! - `TOKIMO_HV_INITRD`  — path to initrd
//! - `TOKIMO_HV_ROOTFS`  — path to rootfs directory (shared via Plan 9)
//! - `TOKIMO_HV_MEMORY`  — VM memory in MB (default 512)
//! - `TOKIMO_HV_CPUS`    — vCPU count (default 2)
//!
//! Falls back to reading `TOKIMO_VZ_*` vars when `TOKIMO_HV_*` are not set,
//! so a single `~/.tokimo/` install works for both macOS and Windows.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::SandboxConfig;
use crate::{Error, ExecutionResult, Result};

use super::hcs;

const DEFAULT_MEMORY_MB: u64 = 512;
const DEFAULT_CPUS: usize = 2;
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub(crate) fn is_available() -> bool {
    hcs::is_available()
}

/// One-shot command execution via HCS Linux VM.
///
/// Boots a VM, runs the command via kernel cmdline, collects output from
/// shared files. Uses the same initrd + rootfs as the macOS VZ backend.
pub(crate) fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult> {
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

    exec_vm(cfg, &cmd_b64)
}

/// Session shell — not yet implemented for HCS path.
pub(crate) fn spawn_session_shell(_cfg: &SandboxConfig) -> Result<crate::session::ShellHandle> {
    Err(Error::validation(
        "HCS Session: not yet implemented. \
         Set SAFEBOX_WSL=1 to use WSL2 backend with Session support.",
    ))
}

// ---------------------------------------------------------------------------
// Shell escaping (same as macOS VZ)
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
// HvRunner — boots VM, runs command, collects result via shared files
// ---------------------------------------------------------------------------

fn exec_vm(cfg: &SandboxConfig, cmd_b64: &str) -> Result<ExecutionResult> {
    let kernel_path = find_kernel()?;
    let initrd_path = find_initrd()?;
    let rootfs_path = find_rootfs(cfg)?;
    let memory_mb: u64 = std::env::var("TOKIMO_HV_MEMORY")
        .ok()
        .or_else(|| std::env::var("TOKIMO_VZ_MEMORY").ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MB);
    let cpu_count: usize = std::env::var("TOKIMO_HV_CPUS")
        .ok()
        .or_else(|| std::env::var("TOKIMO_VZ_CPUS").ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CPUS);

    // Clean up leftover result files from previous runs.
    let _ = std::fs::remove_file(rootfs_path.join(".vz_stdout"));
    let _ = std::fs::remove_file(rootfs_path.join(".vz_stderr"));
    let _ = std::fs::remove_file(rootfs_path.join(".vz_exit_code"));

    let vm_id = unique_vm_id();

    let config_json = hcs::build_vm_config(
        &vm_id,
        &kernel_path,
        &initrd_path,
        &rootfs_path,
        cmd_b64,
        memory_mb,
        cpu_count,
    );

    tracing::info!(
        id = %vm_id,
        kernel = %kernel_path.display(),
        initrd = %initrd_path.display(),
        rootfs = %rootfs_path.display(),
        "Booting HCS VM",
    );

    let system = hcs::HcsSystem::create(&vm_id, &config_json).map_err(|e| Error::exec(format!("HCS create: {e}")))?;

    system.start().map_err(|e| Error::exec(format!("HCS start: {e}")))?;

    let deadline = Instant::now() + EXEC_TIMEOUT + Duration::from_secs(10);

    // Poll for VM stop (initrd calls poweroff -f after command completes).
    loop {
        thread::sleep(POLL_INTERVAL);

        match poll_vm_state(&system) {
            VmState::Stopped => break,
            VmState::Error => break,
            VmState::Running => {}
        }

        if Instant::now() > deadline {
            tracing::warn!(id = %vm_id, "VM timeout, terminating");
            let _ = system.terminate();
            break;
        }
    }

    tracing::info!(id = %vm_id, "VM stopped, reading results");

    // Read results from shared files (same format as macOS VZ).
    let stdout = std::fs::read_to_string(rootfs_path.join(".vz_stdout")).unwrap_or_default();
    let stderr = std::fs::read_to_string(rootfs_path.join(".vz_stderr")).unwrap_or_default();
    let exit_code = std::fs::read_to_string(rootfs_path.join(".vz_exit_code"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);

    // Clean up temp files.
    let _ = std::fs::remove_file(rootfs_path.join(".vz_stdout"));
    let _ = std::fs::remove_file(rootfs_path.join(".vz_stderr"));
    let _ = std::fs::remove_file(rootfs_path.join(".vz_exit_code"));

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        timed_out: false,
        oom_killed: false,
    })
}

#[derive(Debug, PartialEq)]
enum VmState {
    Running,
    Stopped,
    Error,
}

fn poll_vm_state(system: &hcs::HcsSystem) -> VmState {
    match system.get_properties("{\"Property\":\"State\"}") {
        Ok(json) => {
            // Parse {"State": "Running"} or {"State": "Stopped"}
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                match v["State"].as_str() {
                    Some("Running") => VmState::Running,
                    Some("Stopped") => VmState::Stopped,
                    _ => VmState::Error,
                }
            } else {
                VmState::Error
            }
        }
        Err(_) => VmState::Error,
    }
}

// ---------------------------------------------------------------------------
// Helper: unique VM ID (PID + timestamp + counter)
// ---------------------------------------------------------------------------

use std::sync::atomic::AtomicU64;

static VM_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_vm_id() -> String {
    let pid = std::process::id() as u64;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let cnt = VM_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("tokimo-{pid:x}-{ts:x}-{cnt:x}")
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

/// Find the Linux kernel. Checks:
/// 1. `TOKIMO_HV_KERNEL` env var
/// 2. `TOKIMO_VZ_KERNEL` env var (shared config)
/// 3. `~/.tokimo/kernel/vmlinuz`
/// 4. Next to the current executable
fn find_kernel() -> Result<PathBuf> {
    for env_var in &["TOKIMO_HV_KERNEL", "TOKIMO_VZ_KERNEL"] {
        if let Ok(p) = std::env::var(env_var) {
            let pb = PathBuf::from(&p);
            if pb.exists() {
                return Ok(pb);
            }
            return Err(Error::exec(format!("{env_var}={} not found", pb.display())));
        }
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
        "HCS kernel not found. Set TOKIMO_HV_KERNEL=C:\\Users\\...\\.tokimo\\kernel\\vmlinuz\n\
         Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}

/// Find the initrd. Checks:
/// 1. `TOKIMO_HV_INITRD` env var
/// 2. `TOKIMO_VZ_INITRD` env var (shared config)
/// 3. `~/.tokimo/initrd.img`
/// 4. Next to the current executable
fn find_initrd() -> Result<PathBuf> {
    for env_var in &["TOKIMO_HV_INITRD", "TOKIMO_VZ_INITRD"] {
        if let Ok(p) = std::env::var(env_var) {
            let pb = PathBuf::from(&p);
            if pb.exists() {
                return Ok(pb);
            }
            return Err(Error::exec(format!("{env_var}={} not found", pb.display())));
        }
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
        "HCS initrd not found. Set TOKIMO_HV_INITRD=C:\\Users\\...\\.tokimo\\initrd.img\n\
         Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}

/// Find the rootfs directory. Checks:
/// 1. `TOKIMO_HV_ROOTFS` env var
/// 2. `TOKIMO_VZ_ROOTFS` env var (shared config)
/// 3. `~/.tokimo/rootfs/`
/// 4. `cfg.work_dir` (if it looks like a rootfs)
fn find_rootfs(cfg: &SandboxConfig) -> Result<PathBuf> {
    for env_var in &["TOKIMO_HV_ROOTFS", "TOKIMO_VZ_ROOTFS"] {
        if let Ok(p) = std::env::var(env_var) {
            let pb = PathBuf::from(&p);
            if pb.exists() {
                return Ok(pb);
            }
            return Err(Error::exec(format!("{env_var}={} not found", pb.display())));
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        let pb = PathBuf::from(&home).join(".tokimo/rootfs");
        if pb.exists() {
            return Ok(pb);
        }
    }
    // Fall back to cfg.work_dir if it looks like a rootfs.
    if cfg.work_dir.join("usr").exists() {
        return Ok(cfg.work_dir.clone());
    }
    Err(Error::validation(
        "HCS rootfs not found. Set TOKIMO_HV_ROOTFS=C:\\Users\\...\\.tokimo\\rootfs\n\
         Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("hello"), "hello");
        assert_eq!(shell_escape("hello world"), "'hello world'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_unique_vm_id_format() {
        let id = unique_vm_id();
        assert!(id.starts_with("tokimo-"));
        // Should be unique per call.
        let id2 = unique_vm_id();
        assert_ne!(id, id2);
    }
}
