//! VM lifecycle for the Cloud Hypervisor backend.
//!
//! Provides [`ChVmConfig`], [`ChVm`] (the running VM handle), and helpers
//! for finding kernel / initrd / project-root paths.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};

use crate::error::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// virtiofs tag name for the shared directory visible to the guest.
pub const SHARED_TAG: &str = "tokimoshare";

/// Default guest MAC address used when networking is enabled without an override.
pub const DEFAULT_MAC_ADDR: &str = "9a:55:9a:55:9a:55";

const PROCESS_LOG_CAPTURE_LINES: usize = 20;

// ── CID allocator ────────────────────────────────────────────────────────────

/// Guest CIDs are allocated globally from this counter.
/// Host CID is 2; guest must be ≥ 3.
static NEXT_CID: AtomicU32 = AtomicU32::new(100);

pub fn next_cid() -> u32 {
    NEXT_CID.fetch_add(1, Ordering::Relaxed)
}

// ── ChVmConfig ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct PortForward {
    pub proto: PortProto,
    pub host_port: u16,
    pub guest_port: u16,
    pub host_addr: Option<String>,
}

pub struct NetworkConfig {
    pub passt_binary: PathBuf,
    pub mac_addr: Option<String>,
    pub port_forwards: Vec<PortForward>,
}

pub struct ChVmConfig {
    pub cid: u32,
    pub ch_binary: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub memory_mb: u64,
    pub cpu_count: u32,
    pub shared_dir: Option<PathBuf>,
    pub network: Option<NetworkConfig>,
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
    pub passt_child: Option<std::process::Child>,
    pub passt_socket: Option<PathBuf>,
    ch_log_tasks: Vec<JoinHandle<()>>,
    virtiofsd_log_tasks: Vec<JoinHandle<()>>,
    passt_log_threads: Vec<std::thread::JoinHandle<()>>,
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

        let memory_shared = config.shared_dir.is_some() || config.network.is_some();

        // ── Optional virtiofsd setup ─────────────────────────────────────────
        let mut virtiofsd_child_opt = None;
        let mut virtiofsd_socket_opt = None;
        let mut virtiofsd_log_tasks = Vec::new();
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
            let mut vfsd_child = TokioCommand::new(&virtiofsd_bin)
                .args([
                    "--socket-path",
                    &virtiofsd_socket.to_string_lossy(),
                    "--shared-dir",
                    &shared_dir.to_string_lossy(),
                    "--cache=auto",
                    "--sandbox=chroot",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| Error::other(format!("failed to spawn virtiofsd: {e}")))?;

            if let Some(stdout) = vfsd_child.stdout.take() {
                virtiofsd_log_tasks.push(spawn_tokio_log_task(cid, "virtiofsd", "stdout", stdout, None));
            }

            let virtiofsd_stderr = Arc::new(Mutex::new(VecDeque::with_capacity(PROCESS_LOG_CAPTURE_LINES)));
            if let Some(stderr) = vfsd_child.stderr.take() {
                virtiofsd_log_tasks.push(spawn_tokio_log_task(
                    cid,
                    "virtiofsd",
                    "stderr",
                    stderr,
                    Some(Arc::clone(&virtiofsd_stderr)),
                ));
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
                let virtiofsd_stderr_snippet = captured_log_snippet("virtiofsd", "stderr", &virtiofsd_stderr);
                warn!(cid, "virtiofsd socket did not appear within 5s — killing child");
                let _ = vfsd_child.kill().await;
                let _ = vfsd_child.wait().await;
                abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
                return Err(Error::other(format!(
                    "virtiofsd failed to start: socket did not appear within 5s{virtiofsd_stderr_snippet}"
                )));
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

        // ── Optional passt setup ─────────────────────────────────────────────
        let mut passt_child_opt: Option<std::process::Child> = None;
        let mut passt_socket_opt = None;
        let mut passt_stderr_opt: Option<Arc<Mutex<VecDeque<String>>>> = None;
        let mut passt_log_threads = Vec::new();
        let net_args = if let Some(ref network) = config.network {
            let passt_socket = PathBuf::from(format!("/tmp/tokimo-ch-passt-{cid}.sock"));
            let _ = std::fs::remove_file(&passt_socket);

            if !network.passt_binary.exists() {
                if let Some(mut vfsd) = virtiofsd_child_opt {
                    let _ = vfsd.kill().await;
                    let _ = vfsd.wait().await;
                }
                abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
                return Err(Error::other(format!(
                    "passt not found at '{}'",
                    network.passt_binary.display()
                )));
            }

            let mut tcp_ports = std::collections::HashSet::new();
            let mut udp_ports = std::collections::HashSet::new();
            for pf in &network.port_forwards {
                let ports = match &pf.proto {
                    PortProto::Tcp => &mut tcp_ports,
                    PortProto::Udp => &mut udp_ports,
                };
                if !ports.insert(pf.host_port) {
                    if let Some(mut vfsd) = virtiofsd_child_opt.take() {
                        let _ = vfsd.kill().await;
                        let _ = vfsd.wait().await;
                    }
                    abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
                    return Err(Error::validation(format!(
                        "duplicate host_port {} for {:?} in port_forwards",
                        pf.host_port, pf.proto
                    )));
                }
            }

            let mut passt_pf_args: Vec<String> = Vec::new();
            let make_spec = |fwds: &[&PortForward]| {
                fwds.iter()
                    .map(|pf| {
                        if let Some(addr) = &pf.host_addr {
                            format!("{}/{}:{}", addr, pf.host_port, pf.guest_port)
                        } else {
                            format!("{}:{}", pf.host_port, pf.guest_port)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            };

            let tcp_fwds: Vec<&PortForward> = network
                .port_forwards
                .iter()
                .filter(|pf| pf.proto == PortProto::Tcp)
                .collect();
            let udp_fwds: Vec<&PortForward> = network
                .port_forwards
                .iter()
                .filter(|pf| pf.proto == PortProto::Udp)
                .collect();

            if !tcp_fwds.is_empty() {
                passt_pf_args.push("-t".to_string());
                passt_pf_args.push(make_spec(&tcp_fwds));
            }
            if !udp_fwds.is_empty() {
                passt_pf_args.push("-u".to_string());
                passt_pf_args.push(make_spec(&udp_fwds));
            }

            info!(cid, "spawning passt for vhost-user networking");
            let passt_socket_arg = passt_socket.to_string_lossy().into_owned();
            let mut passt_child = match std::process::Command::new(&network.passt_binary)
                .args(["--vhost-user", "--socket", &passt_socket_arg, "-f", "--no-map-gw"])
                .args(&passt_pf_args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(e) => {
                    if let Some(mut vfsd) = virtiofsd_child_opt {
                        if let Err(err) = vfsd.kill().await {
                            warn!(cid, error = %err, "failed to kill virtiofsd after passt spawn failure");
                        }
                        let _ = vfsd.wait().await;
                    }
                    abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
                    let _ = std::fs::remove_file(&passt_socket);
                    return Err(Error::other(format!("failed to spawn passt: {e}")));
                }
            };

            if let Some(stdout) = passt_child.stdout.take() {
                passt_log_threads.push(spawn_std_log_thread(cid, "passt", "stdout", stdout, None));
            }

            let passt_stderr = Arc::new(Mutex::new(VecDeque::with_capacity(PROCESS_LOG_CAPTURE_LINES)));
            if let Some(stderr) = passt_child.stderr.take() {
                passt_log_threads.push(spawn_std_log_thread(
                    cid,
                    "passt",
                    "stderr",
                    stderr,
                    Some(Arc::clone(&passt_stderr)),
                ));
            }

            let sock_poll = passt_socket.clone();
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
                let passt_stderr_snippet = captured_log_snippet("passt", "stderr", &passt_stderr);
                warn!(cid, "passt socket did not appear within 5s — killing child");
                if let Err(e) = passt_child.kill() {
                    warn!(cid, error = %e, "failed to kill passt after socket timeout");
                }
                if let Err(e) = passt_child.wait() {
                    warn!(cid, error = %e, "failed to wait for passt after socket timeout");
                }
                join_std_log_threads(&mut passt_log_threads);
                let _ = std::fs::remove_file(&passt_socket);
                if let Some(mut vfsd) = virtiofsd_child_opt {
                    let _ = vfsd.kill().await;
                    let _ = vfsd.wait().await;
                }
                abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
                return Err(Error::other(format!(
                    "passt failed to start: socket did not appear within 5s{passt_stderr_snippet}"
                )));
            }

            let mac_addr = network.mac_addr.as_deref().unwrap_or(DEFAULT_MAC_ADDR);
            let net_arg = format!(
                "mac={},vhost_user=true,socket={},vhost_mode=client",
                mac_addr,
                passt_socket.display()
            );
            passt_child_opt = Some(passt_child);
            passt_socket_opt = Some(passt_socket);
            passt_stderr_opt = Some(passt_stderr);
            vec!["--net".to_string(), net_arg]
        } else {
            Vec::new()
        };

        // ── Build cloud-hypervisor arguments ─────────────────────────────────
        let memory_arg = if memory_shared {
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
        ch_args.extend(net_args);

        let mut child = match TokioCommand::new(&config.ch_binary)
            .args(&ch_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let passt_stderr_snippet = if let Some(ref passt_stderr) = passt_stderr_opt {
                    captured_log_snippet("passt", "stderr", passt_stderr)
                } else {
                    String::new()
                };
                if let Some(mut vfsd) = virtiofsd_child_opt {
                    if let Err(err) = vfsd.kill().await {
                        warn!(cid, error = %err, "failed to kill virtiofsd after CH spawn failure");
                    }
                    let _ = vfsd.wait().await;
                }
                abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
                if let Some(mut passt) = passt_child_opt {
                    if let Err(err) = passt.kill() {
                        warn!(cid, error = %err, "failed to kill passt after CH spawn failure");
                    }
                    if let Err(err) = passt.wait() {
                        warn!(cid, error = %err, "failed to wait for passt after CH spawn failure");
                    }
                    join_std_log_threads(&mut passt_log_threads);
                }
                if let Some(ref sock) = passt_socket_opt {
                    let _ = std::fs::remove_file(sock);
                }
                return Err(Error::other(format!(
                    "failed to spawn cloud-hypervisor: {e}{passt_stderr_snippet}"
                )));
            }
        };

        let mut ch_log_tasks = Vec::new();
        let ch_stderr = Arc::new(Mutex::new(VecDeque::with_capacity(PROCESS_LOG_CAPTURE_LINES)));
        if let Some(stdout) = child.stdout.take() {
            ch_log_tasks.push(spawn_tokio_log_task(cid, "cloud-hypervisor", "stdout", stdout, None));
        }
        if let Some(stderr) = child.stderr.take() {
            ch_log_tasks.push(spawn_tokio_log_task(
                cid,
                "cloud-hypervisor",
                "stderr",
                stderr,
                Some(Arc::clone(&ch_stderr)),
            ));
        }

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
            let stderr_snippet = captured_log_snippet("cloud-hypervisor", "stderr", &ch_stderr);
            let passt_stderr_snippet = if let Some(ref passt_stderr) = passt_stderr_opt {
                captured_log_snippet("passt", "stderr", passt_stderr)
            } else {
                String::new()
            };
            let _ = child.kill().await;
            let _ = child.wait().await;
            abort_tokio_log_tasks(&mut ch_log_tasks);
            if let Some(mut vfsd) = virtiofsd_child_opt {
                let _ = vfsd.kill().await;
                let _ = vfsd.wait().await;
            }
            abort_tokio_log_tasks(&mut virtiofsd_log_tasks);
            if let Some(mut passt) = passt_child_opt {
                if let Err(e) = passt.kill() {
                    warn!(cid, error = %e, "failed to kill passt after CH API timeout");
                }
                if let Err(e) = passt.wait() {
                    warn!(cid, error = %e, "failed to wait for passt after CH API timeout");
                }
                join_std_log_threads(&mut passt_log_threads);
            }
            if let Some(ref sock) = passt_socket_opt {
                let _ = std::fs::remove_file(sock);
            }
            return Err(Error::other(format!(
                "cloud-hypervisor failed to start: API socket did not appear within 3s{stderr_snippet}{passt_stderr_snippet}"
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
            passt_child: passt_child_opt,
            passt_socket: passt_socket_opt,
            ch_log_tasks,
            virtiofsd_log_tasks,
            passt_log_threads,
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
        drain_tokio_log_tasks(&mut self.ch_log_tasks).await;

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
            drain_tokio_log_tasks(&mut self.virtiofsd_log_tasks).await;
        }

        // Shutdown passt if it was spawned
        if let Some(mut passt) = self.passt_child.take() {
            match passt.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    #[cfg(target_os = "linux")]
                    {
                        use nix::sys::signal::{Signal, kill};
                        use nix::unistd::Pid;
                        let pid = passt.id();
                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                        info!(cid, pid, "sent SIGTERM to passt");
                    }
                    let grace_start = std::time::Instant::now();
                    loop {
                        match passt.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) if grace_start.elapsed() >= grace => {
                                warn!(cid, "passt did not exit within grace period — sending SIGKILL");
                                let _ = passt.kill();
                                let _ = passt.wait();
                                break;
                            }
                            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                            Err(e) => {
                                warn!(cid, error = %e, "error waiting for passt during shutdown");
                                break;
                            }
                        }
                    }
                }
                Err(e) => warn!(cid, error = %e, "error checking passt status during shutdown"),
            }
        }

        join_std_log_threads(&mut self.passt_log_threads);

        // Clean up socket files.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_socket);
        if let Some(ref sock) = self.virtiofsd_socket {
            let _ = std::fs::remove_file(sock);
        }
        if let Some(ref sock) = self.passt_socket {
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

impl Drop for ChVm {
    fn drop(&mut self) {
        abort_tokio_log_tasks(&mut self.ch_log_tasks);
        abort_tokio_log_tasks(&mut self.virtiofsd_log_tasks);
        kill_wait_passt_child(self.cid, &mut self.passt_child);
        join_std_log_threads(&mut self.passt_log_threads);
        if let Some(ref sock) = self.passt_socket {
            let _ = std::fs::remove_file(sock);
        }
    }
}

fn captured_log_snippet(component: &str, stream: &str, lines: &Arc<Mutex<VecDeque<String>>>) -> String {
    let lines = lines.lock().unwrap();
    if lines.is_empty() {
        return String::new();
    }
    format!(
        "; {component} {stream}: {}",
        lines.iter().cloned().collect::<Vec<_>>().join(" | ")
    )
}

fn push_captured_line(capture: &Option<Arc<Mutex<VecDeque<String>>>>, line: &str) {
    if let Some(cap) = capture {
        let mut guard = cap.lock().unwrap();
        if guard.len() == PROCESS_LOG_CAPTURE_LINES {
            guard.pop_front();
        }
        guard.push_back(line.to_owned());
    }
}

fn log_process_line(cid: u32, component: &str, stream: &str, line: &str) {
    let lower = line.to_ascii_lowercase();
    if ["error", "failed", "panic", "fatal"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        error!("ch[{cid}]: {component} {stream}: {line}");
    } else if ["denied", "refused"].iter().any(|needle| lower.contains(needle)) {
        warn!("ch[{cid}]: {component} {stream}: {line}");
    } else {
        info!("ch[{cid}]: {component} {stream}: {line}");
    }
}

fn spawn_tokio_log_task<R>(
    cid: u32,
    component: &'static str,
    stream: &'static str,
    reader: R,
    capture: Option<Arc<Mutex<VecDeque<String>>>>,
) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    log_process_line(cid, component, stream, &line);
                    push_captured_line(&capture, &line);
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("ch[{cid}]: {component} {stream}: failed to read stream: {e}");
                    break;
                }
            }
        }
    })
}

/// Spawn a background std thread to read a process stdout/stderr pipe line by
/// line, logging via tracing and optionally capturing into a bounded buffer.
fn spawn_std_log_thread<R>(
    cid: u32,
    component: &'static str,
    stream: &'static str,
    reader: R,
    capture: Option<Arc<Mutex<VecDeque<String>>>>,
) -> std::thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    log_process_line(cid, component, stream, &line);
                    push_captured_line(&capture, &line);
                }
                Err(e) => {
                    warn!("ch[{cid}]: {component} {stream}: failed to read stream: {e}");
                    break;
                }
            }
        }
    })
}

async fn drain_tokio_log_tasks(tasks: &mut Vec<JoinHandle<()>>) {
    for mut task in tasks.drain(..) {
        tokio::select! {
            _ = &mut task => {}
            _ = sleep(Duration::from_secs(1)) => {
                warn!("timed out waiting for VM log task to finish");
                task.abort();
            }
        }
    }
}

fn abort_tokio_log_tasks(tasks: &mut Vec<JoinHandle<()>>) {
    for task in tasks.drain(..) {
        task.abort();
    }
}

fn join_std_log_threads(threads: &mut Vec<std::thread::JoinHandle<()>>) {
    for thread in threads.drain(..) {
        if thread.join().is_err() {
            warn!("VM log thread panicked while joining");
        }
    }
}

/// Synchronously kill and wait for a running passt `std::process::Child`.
fn kill_wait_passt_child(cid: u32, child: &mut Option<std::process::Child>) {
    if let Some(mut passt) = child.take() {
        match passt.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(e) = passt.kill() {
                    warn!(cid, error = %e, "failed to kill passt");
                }
                if let Err(e) = passt.wait() {
                    warn!(cid, error = %e, "failed to wait for passt");
                }
            }
            Err(e) => warn!(cid, error = %e, "failed to check passt status"),
        }
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

/// Resolve the initrd path, preferring the released dependency under
/// `{root}/bin/ch-initrd/current/initrd.cpio.gz` and falling back to the local
/// development build under `{root}/bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz`.
pub fn ch_initrd_path() -> Result<PathBuf> {
    let root = locate_project_root().ok_or_else(|| {
        Error::other(
            "cannot locate project root (TOKIMO_PROJECT_ROOT unset and bin/cloud-hypervisor not \
             found in ancestor directories)",
        )
    })?;
    let released = root
        .join("bin")
        .join("ch-initrd")
        .join("current")
        .join("initrd.cpio.gz");
    if released.exists() {
        return Ok(released);
    }

    Ok(root
        .join("bin")
        .join("ch-initrd")
        .join("dev")
        .join("linux-x86_64")
        .join("initrd.cpio.gz"))
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

/// Resolve the passt path: `{root}/bin/passt/current/bin/passt`.
pub fn passt_path() -> Result<PathBuf> {
    let root = locate_project_root().ok_or_else(|| {
        Error::other(
            "cannot locate project root (TOKIMO_PROJECT_ROOT unset and bin/cloud-hypervisor not \
             found in ancestor directories)",
        )
    })?;
    Ok(root.join("bin").join("passt").join("current").join("bin").join("passt"))
}
