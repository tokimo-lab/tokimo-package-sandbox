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

// ── Constants ────────────────────────────────────────────────────────────────

/// virtiofs tag name for the shared directory visible to the guest.
pub const SHARED_TAG: &str = "tokimoshare";

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
    pub shared_dir: Option<PathBuf>,
}

// ── ChVm ─────────────────────────────────────────────────────────────────────

/// Handle to a running cloud-hypervisor VM process.
pub struct ChVm {
    pub cid: u32,
    pub child: tokio::process::Child,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
    pub virtiofsd_child: Option<tokio::process::Child>,
    pub virtiofsd_socket: Option<PathBuf>,
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

        // ── Optional virtiofsd setup ─────────────────────────────────────────
        let mut virtiofsd_child_opt = None;
        let mut virtiofsd_socket_opt = None;
        let fs_args = if let Some(ref shared_dir) = config.shared_dir {
            let virtiofsd_socket = PathBuf::from(format!("/tmp/tokimo-ch-virtiofsd-{cid}.sock"));
            let _ = std::fs::remove_file(&virtiofsd_socket);

            let virtiofsd_bin = virtiofsd_path()?;
            if !virtiofsd_bin.exists() {
                return Err(Error::other(format!(
                    "virtiofsd not found at '{}'. Run: make virtiofsd",
                    virtiofsd_bin.display()
                )));
            }

            info!(cid, "spawning virtiofsd for shared_dir {:?}", shared_dir);
            // Use chroot sandbox; virtiofsd's default namespace sandbox relies on pivot_root which Docker seccomp blocks
            let mut vfsd_child = Command::new(&virtiofsd_bin)
                .args([
                    "--socket-path",
                    &virtiofsd_socket.to_string_lossy(),
                    "--shared-dir",
                    &shared_dir.to_string_lossy(),
                    "--cache=auto",
                    "--sandbox=chroot",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| Error::other(format!("failed to spawn virtiofsd: {e}")))?;

            // Stream stderr to warnings
            if let Some(stderr) = vfsd_child.stderr.take() {
                tokio::spawn(async move {
                    use tokio::io::{AsyncBufReadExt, BufReader};
                    let mut reader = BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        warn!("virtiofsd: {}", line);
                    }
                });
            }

            // Wait for virtiofsd socket to appear (up to 5 seconds)
            let sock_poll = virtiofsd_socket.clone();
            let appeared = timeout(Duration::from_secs(5), async move {
                loop {
                    if sock_poll.exists() {
                        return;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            })
            .await;

            if appeared.is_err() {
                warn!(cid, "virtiofsd socket did not appear within 5s — killing child");
                let _ = vfsd_child.kill().await;
                return Err(Error::other(
                    "virtiofsd failed to start: socket did not appear within 5s",
                ));
            }

            let fs_arg = format!(
                "tag={},socket={},num_queues=1,queue_size=512",
                SHARED_TAG,
                virtiofsd_socket.display()
            );
            virtiofsd_child_opt = Some(vfsd_child);
            virtiofsd_socket_opt = Some(virtiofsd_socket);
            vec!["--fs".to_string(), fs_arg]
        } else {
            Vec::new()
        };

        // ── Build cloud-hypervisor arguments ─────────────────────────────────
        let memory_arg = if config.shared_dir.is_some() {
            format!("size={}M,shared=on", config.memory_mb.max(256))
        } else {
            format!("size={}M", config.memory_mb.max(256))
        };
        let cpus_arg = format!("boot={}", config.cpu_count.max(1));
        let vsock_arg = format!("cid={},socket={}", cid, vsock_socket.display());

        info!(
            cid,
            binary = %config.ch_binary.display(),
            kernel = %config.kernel.display(),
            "spawning cloud-hypervisor"
        );

        let mut ch_args = vec![
            "--kernel".to_string(),
            config.kernel.to_string_lossy().into_owned(),
            "--initramfs".to_string(),
            config.initrd.to_string_lossy().into_owned(),
            "--cmdline".to_string(),
            "console=hvc0 reboot=k panic=1 quiet".to_string(),
            "--cpus".to_string(),
            cpus_arg,
            "--memory".to_string(),
            memory_arg,
            "--vsock".to_string(),
            vsock_arg,
            "--serial".to_string(),
            "off".to_string(),
            "--console".to_string(),
            "null".to_string(),
            "--api-socket".to_string(),
            api_socket.to_string_lossy().into_owned(),
        ];
        ch_args.extend(fs_args);

        let mut child = match Command::new(&config.ch_binary)
            .args(&ch_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                // Clean up virtiofsd if CH spawn fails
                if let Some(mut vfsd) = virtiofsd_child_opt {
                    let _ = vfsd.start_kill();
                }
                return Err(Error::other(format!("failed to spawn cloud-hypervisor: {e}")));
            }
        };

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
            // Try to read stderr for a diagnostic message.
            let stderr_snippet = if let Some(mut stderr) = child.stderr.take() {
                let mut buf = Vec::new();
                use tokio::io::AsyncReadExt;
                let _ = tokio::time::timeout(Duration::from_millis(200), stderr.read_to_end(&mut buf)).await;
                let txt = String::from_utf8_lossy(&buf);
                let last_line = txt.lines().last().unwrap_or("").trim().to_owned();
                if last_line.is_empty() {
                    String::new()
                } else {
                    format!(": {last_line}")
                }
            } else {
                String::new()
            };
            let _ = child.kill().await;
            // Clean up virtiofsd too
            if let Some(mut vfsd) = virtiofsd_child_opt {
                let _ = vfsd.kill().await;
            }
            return Err(Error::other(format!(
                "cloud-hypervisor failed to start: API socket did not appear within 3s{stderr_snippet}"
            )));
        }

        info!(cid, api_socket = %api_socket.display(), "VM is ready");
        Ok(Self {
            cid,
            child,
            api_socket,
            vsock_socket,
            virtiofsd_child: virtiofsd_child_opt,
            virtiofsd_socket: virtiofsd_socket_opt,
        })
    }

    /// Gracefully shut down the VM: SIGTERM → wait(grace) → SIGKILL → cleanup.
    pub async fn shutdown(&mut self, grace: Duration) -> Result<()> {
        let cid = self.cid;

        // Shutdown cloud-hypervisor
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

        // Shutdown virtiofsd if it was spawned
        if let Some(ref mut vfsd) = self.virtiofsd_child {
            if let Some(pid) = vfsd.id() {
                #[cfg(target_os = "linux")]
                {
                    use nix::sys::signal::{Signal, kill};
                    use nix::unistd::Pid;
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                    info!(cid, pid, "sent SIGTERM to virtiofsd");
                }
            }

            let wait_result = timeout(grace, vfsd.wait()).await;
            if wait_result.is_err() {
                warn!(cid, "virtiofsd did not exit within grace period — sending SIGKILL");
                let _ = vfsd.kill().await;
                let _ = vfsd.wait().await;
            }
        }

        // Clean up socket files.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_socket);
        if let Some(ref sock) = self.virtiofsd_socket {
            let _ = std::fs::remove_file(sock);
        }
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

/// Resolve the virtiofsd path: `{root}/bin/virtiofsd/current/virtiofsd`.
pub fn virtiofsd_path() -> Result<PathBuf> {
    let root = locate_project_root().ok_or_else(|| {
        Error::other(
            "cannot locate project root (TOKIMO_PROJECT_ROOT unset and bin/cloud-hypervisor not \
             found in ancestor directories)",
        )
    })?;
    Ok(root.join("bin").join("virtiofsd").join("current").join("virtiofsd"))
}
