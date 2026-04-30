//! macOS Virtualization.framework backend.
//!
//! Boots a lightweight Linux VM for Linux-grade isolation on macOS.
//!
//! ## Execution modes
//!
//! - **Serial mode (V1, `run()`)**: command passed via kernel cmdline,
//!   output collected via virtio console. No tokimo-sandbox-init required.
//! - **VSOCK mode (V2, `Session`)**: tokimo-sandbox-init as PID 1, full
//!   init protocol over virtio-vsock. Requires init binary in initrd.
//!
//! ## Configuration (env vars)
//!
//! - `TOKIMO_VZ_KERNEL`  — path to Linux kernel (vmlinuz)
//! - `TOKIMO_VZ_INITRD`  — path to initrd
//! - `TOKIMO_VZ_ROOTFS`  — path to rootfs directory (shared via virtiofs)
//! - `TOKIMO_VZ_MEMORY`  — VM memory in MB (default 512)
//! - `TOKIMO_VZ_CPUS`    — vCPU count (default 2)

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, SerialPortConfiguration, SharedDirectory,
    SingleDirectoryShare, SocketDeviceConfiguration, VirtioFileSystemDeviceConfiguration, VirtualMachineConfiguration,
    VirtualMachineState, is_supported,
};

use crate::config::SandboxConfig;
use crate::{Error, ExecutionResult, Result};

pub(crate) const DEFAULT_MEMORY_MB: u64 = 512;
pub(crate) const DEFAULT_CPUS: usize = 2;
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub(crate) fn is_available() -> bool {
    is_supported()
}

/// One-shot command execution via VZ VM.
///
/// Boots a VM, runs the command via kernel cmdline, collects output.
///
/// The command is passed as a base64-encoded shell command string. The
/// initrd runs `chroot /mnt/work /bin/bash -c "<cmd>"`. To avoid double-bash
/// quoting issues, the caller's argv is shell-escaped and joined with spaces
/// — if the caller passes `["python3", "--version"]`, the guest runs
/// `bash -c "python3 --version"`.
pub(crate) fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    if cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }

    // Shell-escape each argument and join. This turns
    //   ["python3", "--version"]  →  "python3 --version"
    //   ["/bin/sh", "-c", "echo hi"]  →  "/bin/sh -c 'echo hi'"
    let shell_cmd = cmd
        .iter()
        .map(|s| shell_escape(s.as_ref()))
        .collect::<Vec<_>>()
        .join(" ");

    let cmd_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(shell_cmd.as_bytes())
    };

    exec_vm(cfg, &cmd_b64)
}

/// Minimal shell escaping: wrap in single quotes, escaping any embedded quotes.
fn shell_escape(s: &str) -> String {
    if s.contains('\'') || s.contains('\\') || s.contains('"') || s.contains('$') || s.contains(' ') {
        // Single-quote: replace ' with '\''
        let escaped = s.replace('\'', "'\\''");
        format!("'{}'", escaped)
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// VzRunner — boots VM, runs command, collects result via virtiofs files
// ---------------------------------------------------------------------------

/// Boot a VM, pass command via kernel cmdline, read result from shared files.
fn exec_vm(cfg: &SandboxConfig, cmd_b64: &str) -> Result<ExecutionResult> {
    if !is_supported() {
        return Err(Error::validation(
            "Virtualization.framework not available (requires macOS 11+)",
        ));
    }

    let kernel_path = find_kernel()?;
    let initrd_path = find_initrd()?;
    let rootfs_path = find_rootfs(cfg)?;
    let memory_mb: u64 = std::env::var("TOKIMO_VZ_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MB);
    let cpu_count: usize = std::env::var("TOKIMO_VZ_CPUS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CPUS);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|e| Error::exec(format!("tokio runtime: {e}")))?;

    let cmd_b64 = cmd_b64.to_string();
    let rootfs_s = rootfs_path.to_string_lossy().into_owned();
    let kernel_s = kernel_path.to_string_lossy().into_owned();
    let initrd_s = initrd_path.to_string_lossy().into_owned();
    let rootfs_result = rootfs_path.clone();

    let result: Result<ExecutionResult> = rt.block_on(async {
        let mut boot_loader =
            LinuxBootLoader::new(&kernel_s).map_err(|e| Error::exec(format!("LinuxBootLoader: {e}")))?;
        boot_loader
            .set_initial_ramdisk(&initrd_s)
            .set_command_line(&format!("console=hvc0 quiet loglevel=3 run={cmd_b64}"));

        let shared_dir =
            SharedDirectory::new(&rootfs_s, false).map_err(|e| Error::exec(format!("SharedDirectory: {e}")))?;
        let single_share =
            SingleDirectoryShare::new(shared_dir).map_err(|e| Error::exec(format!("SingleDirectoryShare: {e}")))?;
        let mut fs_config = VirtioFileSystemDeviceConfiguration::new("work")
            .map_err(|e| Error::exec(format!("VirtioFileSystemDevice: {e}")))?;
        fs_config.set_share(single_share);

        let serial = SerialPortConfiguration::virtio_console().map_err(|e| Error::exec(format!("SerialPort: {e}")))?;
        let serial_fd_raw = serial.read_fd();

        let mut config = VirtualMachineConfiguration::new().map_err(|e| Error::exec(format!("VM config: {e}")))?;
        config
            .set_cpu_count(cpu_count)
            .set_memory_size(memory_mb * 1024 * 1024)
            .set_platform(GenericPlatform::new().map_err(|e| Error::exec(format!("Platform: {e}")))?)
            .set_boot_loader(boot_loader)
            .add_entropy_device(EntropyDeviceConfiguration::new().map_err(|e| Error::exec(format!("Entropy: {e}")))?)
            .add_socket_device(SocketDeviceConfiguration::new().map_err(|e| Error::exec(format!("Socket: {e}")))?)
            .add_serial_port(serial)
            .add_directory_share(fs_config);

        let vm = config.build().map_err(|e| Error::exec(format!("VM build: {e}")))?;

        tracing::info!(kernel=%kernel_s, initrd=%initrd_s, rootfs=%rootfs_s, "Booting VZ VM");

        vm.start().await.map_err(|e| Error::exec(format!("VM start: {e}")))?;

        if vm.state() != VirtualMachineState::Running {
            return Err(Error::exec(format!("VM state: {:?}", vm.state())));
        }

        // Drain serial for debugging (non-blocking poll).
        if let Some(fd) = serial_fd_raw {
            drain_serial_debug(fd);
        }

        // Wait for VM to stop (initrd calls poweroff -f after command).
        let deadline = std::time::Instant::now() + EXEC_TIMEOUT + Duration::from_secs(10);
        let vm_arc = Arc::new(vm);
        let vm_ref = vm_arc.clone();
        let mut timed_out = false;
        // Collect serial output for OOM detection.
        let mut serial_buf = Vec::new();
        loop {
            // Drain any available serial output.
            if let Some(fd) = serial_fd_raw {
                let mut buf = [0u8; 4096];
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    serial_buf.extend_from_slice(&buf[..n as usize]);
                }
            }
            let state = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm_ref.state()));
            match state {
                Ok(VirtualMachineState::Stopped) | Err(_) => break,
                Ok(_) => {}
            }
            if std::time::Instant::now() > deadline {
                timed_out = true;
                tracing::warn!("VM timeout");
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check serial output for OOM killer messages.
        let serial_str = String::from_utf8_lossy(&serial_buf);
        let oom_killed = serial_str.contains("Out of memory") || serial_str.contains("Killed process");

        tracing::info!(timed_out, oom_killed, "VM stopped, reading results...");

        // Read results from virtiofs-shared files (written by initrd).
        let stdout = std::fs::read_to_string(rootfs_result.join(".vz_stdout")).unwrap_or_default();
        let stderr = std::fs::read_to_string(rootfs_result.join(".vz_stderr")).unwrap_or_default();
        let exit_code = std::fs::read_to_string(rootfs_result.join(".vz_exit_code"))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(-1);

        // Clean up temp files.
        let _ = std::fs::remove_file(rootfs_result.join(".vz_stdout"));
        let _ = std::fs::remove_file(rootfs_result.join(".vz_stderr"));
        let _ = std::fs::remove_file(rootfs_result.join(".vz_exit_code"));

        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
            timed_out,
            oom_killed,
        })
    });

    result
}

// ---------------------------------------------------------------------------
// Serial output reader
// ---------------------------------------------------------------------------

/// Non-blocking drain of serial fd for debug logging.
fn drain_serial_debug(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    if total > 0 {
        let s = String::from_utf8_lossy(&buf[..total.min(buf.len())]);
        tracing::debug!(bytes = total, "VZ serial: {}", s);
    }
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

pub(crate) fn find_kernel() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_VZ_KERNEL") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(Error::exec(format!("TOKIMO_VZ_KERNEL={} not found", pb.display())));
    }
    if let Ok(home) = std::env::var("HOME") {
        let pb = PathBuf::from(&home).join(".tokimo/kernel/vmlinuz");
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for name in &["vmlinuz", "bzImage", "kernel"] {
            let pb = dir.join(name);
            if pb.exists() {
                return Ok(pb);
            }
        }
    }
    Err(Error::validation(
        "VZ kernel not found. Set TOKIMO_VZ_KERNEL=/path/to/vmlinuz",
    ))
}

pub(crate) fn find_initrd() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_VZ_INITRD") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(Error::exec(format!("TOKIMO_VZ_INITRD={} not found", pb.display())));
    }
    if let Ok(home) = std::env::var("HOME") {
        let pb = PathBuf::from(&home).join(".tokimo/initrd.img");
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for name in &["initrd.img", "initramfs.cpio.gz", "initrd"] {
            let pb = dir.join(name);
            if pb.exists() {
                return Ok(pb);
            }
        }
    }
    Err(Error::validation(
        "VZ initrd not found. Set TOKIMO_VZ_INITRD=/path/to/initrd.img",
    ))
}

pub(crate) fn find_rootfs(cfg: &SandboxConfig) -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_VZ_ROOTFS") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(Error::exec(format!("TOKIMO_VZ_ROOTFS={} not found", pb.display())));
    }
    if let Ok(home) = std::env::var("HOME") {
        let pb = PathBuf::from(&home).join(".tokimo/rootfs");
        if pb.exists() {
            return Ok(pb);
        }
    }
    // Fall back to cfg.work_dir — caller may have rootfs there.
    if cfg.work_dir.join("usr").exists() {
        return Ok(cfg.work_dir.clone());
    }
    Err(Error::validation(
        "VZ rootfs not found. Set TOKIMO_VZ_ROOTFS=/path/to/rootfs\n\
         Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases",
    ))
}
