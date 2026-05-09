//! VM lifecycle for the Cloud Hypervisor backend.
//!
//! Provides [`ChVmConfig`], [`ChVm`] (the running VM handle), and helpers
//! for finding kernel / initrd / project-root paths.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::process::Command;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::error::{Error, Result};

// ── CID allocator ────────────────────────────────────────────────────────────

/// Guest CIDs are allocated globally from this counter.
/// Host CID is 2; guest must be ≥ 3.
static NEXT_CID: AtomicU32 = AtomicU32::new(100);

pub fn next_cid() -> u32 {
    NEXT_CID.fetch_add(1, Ordering::Relaxed)
}

// ── ChVmConfig ───────────────────────────────────────────────────────────────

pub struct ChVmConfig {
    pub cid: u32,
    pub ch_binary: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub memory_mb: u64,
    pub cpu_count: u32,
}

// ── ChVm ─────────────────────────────────────────────────────────────────────

/// Handle to a running cloud-hypervisor VM process.
pub struct ChVm {
    pub cid: u32,
    pub child: tokio::process::Child,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
}

impl ChVm {
    /// Spawn a cloud-hypervisor VM process and wait for its API socket to
    /// appear (up to 3 seconds), indicating the hypervisor is ready.
    pub async fn spawn(config: ChVmConfig) -> Result<Self> {
        if !config.kernel.exists() {
            return Err(Error::other(format!(
                "vmlinux not found at '{}'. Run: make ch-vmlinux",
                config.kernel.display()
            )));
        }
        if !config.initrd.exists() {
            return Err(Error::other(format!(
                "initrd not found at '{}'. Run: make ch-initrd",
                config.initrd.display()
            )));
        }

        let cid = config.cid;
        let api_socket = PathBuf::from(format!("/tmp/tokimo-ch-api-{cid}.sock"));
        let vsock_socket = PathBuf::from(format!("/tmp/tokimo-ch-vsock-{cid}.sock"));

        // Remove stale sockets from a previous crashed VM.
        let _ = std::fs::remove_file(&api_socket);
        let _ = std::fs::remove_file(&vsock_socket);

        let memory_arg = format!("size={}M", config.memory_mb.max(256));
        let cpus_arg = format!("boot={}", config.cpu_count.max(1));
        let vsock_arg = format!("cid={},socket={}", cid, vsock_socket.display());

        info!(
            cid,
            binary = %config.ch_binary.display(),
            kernel = %config.kernel.display(),
            "spawning cloud-hypervisor"
        );

        let mut child = Command::new(&config.ch_binary)
            .args([
                "--kernel",
                &config.kernel.to_string_lossy(),
                "--initramfs",
                &config.initrd.to_string_lossy(),
                "--cmdline",
                "console=hvc0 reboot=k panic=1 quiet",
                "--cpus",
                &cpus_arg,
                "--memory",
                &memory_arg,
                "--vsock",
                &vsock_arg,
                "--serial",
                "off",
                "--console",
                "null",
                "--api-socket",
                &api_socket.to_string_lossy(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::other(format!("failed to spawn cloud-hypervisor: {e}")))?;

        // Poll for the API socket to appear (signals hypervisor is ready).
        let api_socket_poll = api_socket.clone();
        let appeared = timeout(Duration::from_secs(3), async move {
            loop {
                if api_socket_poll.exists() {
                    return;
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        if appeared.is_err() {
            warn!(cid, "API socket did not appear within 3s — killing child");
            let _ = child.kill().await;
            return Err(Error::other(
                "cloud-hypervisor failed to start: API socket did not appear within 3s",
            ));
        }

        info!(cid, api_socket = %api_socket.display(), "VM is ready");
        Ok(Self {
            cid,
            child,
            api_socket,
            vsock_socket,
        })
    }

    /// Gracefully shut down the VM: SIGTERM → wait(grace) → SIGKILL → cleanup.
    pub async fn shutdown(&mut self, grace: Duration) -> Result<()> {
        let cid = self.cid;
        if let Some(pid) = self.child.id() {
            #[cfg(target_os = "linux")]
            {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                info!(cid, pid, "sent SIGTERM to cloud-hypervisor");
            }
        }

        let wait_result = timeout(grace, self.child.wait()).await;
        if wait_result.is_err() {
            warn!(cid, "VM did not exit within grace period — sending SIGKILL");
            let _ = self.child.kill().await;
            let _ = self.child.wait().await;
        }

        // Clean up socket files.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_socket);
        info!(cid, "VM shutdown complete");
        Ok(())
    }

    /// Returns `true` if the child process has not yet exited.
    pub fn is_alive(&mut self) -> bool {
        self.child.try_wait().map(|s| s.is_none()).unwrap_or(false)
    }
}

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Walk up from the current executable to find the project root (the
/// directory that contains a `bin/cloud-hypervisor` subdirectory).
/// Also respects the `TOKIMO_PROJECT_ROOT` environment variable.
pub fn locate_project_root() -> Option<PathBuf> {
    if let Ok(root) = std::env::var("TOKIMO_PROJECT_ROOT") {
        return Some(PathBuf::from(root));
    }
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?.to_owned();
    for _ in 0..10 {
        if dir.join("bin").join("cloud-hypervisor").is_dir() {
            return Some(dir);
        }
        dir = match dir.parent() {
            Some(p) => p.to_owned(),
            None => return None,
        };
    }
    None
}

/// Resolve the vmlinux path: `{root}/bin/ch-vmlinux/current/bin/vmlinux`.
pub fn ch_vmlinux_path() -> Result<PathBuf> {
    let root = locate_project_root().ok_or_else(|| {
        Error::other(
            "cannot locate project root (TOKIMO_PROJECT_ROOT unset and bin/cloud-hypervisor not \
             found in ancestor directories)",
        )
    })?;
    Ok(root
        .join("bin")
        .join("ch-vmlinux")
        .join("current")
        .join("bin")
        .join("vmlinux"))
}

/// Resolve the initrd path: `{root}/bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz`.
/// Returns `Err` with a human-readable message if the file is missing.
pub fn ch_initrd_path() -> Result<PathBuf> {
    let root = locate_project_root().ok_or_else(|| {
        Error::other(
            "cannot locate project root (TOKIMO_PROJECT_ROOT unset and bin/cloud-hypervisor not \
             found in ancestor directories)",
        )
    })?;
    let path = root
        .join("bin")
        .join("ch-initrd")
        .join("dev")
        .join("linux-x86_64")
        .join("initrd.cpio.gz");
    Ok(path)
}
