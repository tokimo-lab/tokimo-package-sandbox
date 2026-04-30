//! Persistent VZ session — long-lived Linux VM with tokimo-sandbox-init.
//!
//! On macOS, a `Session` is implemented by booting a persistent Linux VM whose
//! PID 1 is `tokimo-sandbox-init`. The host communicates with init over
//! virtio-vsock (port 1) using the length-prefixed stream framing in
//! [`init_wire`]. A bash shell is opened inside the VM, and its stdio is
//! bridged to the host via the init protocol's pipe events.
//!
//! ## Architecture
//!
//! ```text
//! Host pump thread                     Guest (Linux VM)
//! ────────────────                     ────────────────
//! VsockInitClient::wait_for_event()    tokimo-sandbox-init
//!   → drain_stdout/stderr              → bash (OpenShell child)
//!   → write to host pipes                 → stdout/stderr events
//!   ← stdin via Op::Write                 ← stdin via Op::Write
//! ```

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, NetworkDeviceConfiguration, SerialPortConfiguration,
    SharedDirectory, SingleDirectoryShare, SocketDeviceConfiguration, VirtioFileSystemDeviceConfiguration,
    VirtualMachineConfiguration, VirtualMachineState, is_supported,
};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use super::vz::{DEFAULT_CPUS, DEFAULT_MEMORY_MB, find_initrd, find_kernel, find_rootfs};
use crate::config::{Mount, NetworkPolicy, SandboxConfig};
use crate::host::net_observer::{self, ProxyConfig, ProxyHandle};
use crate::protocol::types::MountEntry;
use crate::session::ShellHandle;
use crate::{Error, Result};

use super::vz_vsock::{ChildHandle, VsockInitClient, VsockTransport};

const VSOCK_CONTROL_PORT: u32 = 1;
/// Extra deadline beyond the VM boot for VSOCK connection.
const VSOCK_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// VzSessionRunner — manages the VM lifecycle
// ---------------------------------------------------------------------------

/// Holds a running VM and its VSOCK control connection.
pub(crate) struct VzSessionRunner {
    /// Must be kept alive so the VM doesn't dealloc.
    #[allow(dead_code)]
    vm: arcbox_vz::VirtualMachine,
    /// Host-side VSOCK init client connected to guest port 1.
    client: Arc<VsockInitClient>,
    /// Keep the tokio runtime alive.
    #[allow(dead_code)]
    rt: Arc<tokio::runtime::Runtime>,
    /// Tear-down: first send shutdown, then drop this (which stops the VM).
    #[allow(dead_code)]
    keepalive: VzSessionKeepalive,
}

impl VzSessionRunner {
    /// Borrow the init client for Workspace / multi-user use.
    pub(crate) fn client(&self) -> &Arc<VsockInitClient> {
        &self.client
    }
}

struct VzSessionKeepalive {
    _rootfs: PathBuf, // keep path alive for virtiofs
}

/// Boot a persistent VM with `tokimo-sandbox-init` as PID 1.
pub(crate) fn boot_session_vm(cfg: &SandboxConfig) -> Result<VzSessionRunner> {
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

    let kernel_s = kernel_path.to_string_lossy().into_owned();
    let initrd_s = initrd_path.to_string_lossy().into_owned();
    let rootfs_s = rootfs_path.to_string_lossy().into_owned();
    let rootfs_keep = rootfs_path.clone();

    // Snapshot extra_mounts: moved into the async block, also kept on the
    // host side for sending the post-Hello MountManifest.
    let mount_specs: Vec<Mount> = cfg.extra_mounts.clone();
    let manifest_entries: Vec<MountEntry> = mount_specs
        .iter()
        .enumerate()
        .map(|(idx, m)| MountEntry::Virtiofs {
            source: format!("s{idx}"),
            target: m.guest.as_ref().unwrap_or(&m.host).to_string_lossy().into_owned(),
            read_only: m.read_only,
        })
        .collect();

    // Boot VM and establish VSOCK connection.
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .map_err(|e| Error::exec(format!("tokio runtime: {e}")))?,
    );

    let (vm, client) = rt.block_on(async {
        let mut boot_loader =
            LinuxBootLoader::new(&kernel_s).map_err(|e| Error::exec(format!("LinuxBootLoader: {e}")))?;
        boot_loader
            .set_initial_ramdisk(&initrd_s)
            .set_command_line("console=hvc0 quiet loglevel=3 TOKIMO_SANDBOX_VSOCK_PORT=1");

        let shared_dir =
            SharedDirectory::new(&rootfs_s, false).map_err(|e| Error::exec(format!("SharedDirectory: {e}")))?;
        let single_share =
            SingleDirectoryShare::new(shared_dir).map_err(|e| Error::exec(format!("SingleDirectoryShare: {e}")))?;
        let mut fs_config = VirtioFileSystemDeviceConfiguration::new("work")
            .map_err(|e| Error::exec(format!("VirtioFileSystemDevice: {e}")))?;
        fs_config.set_share(single_share);

        // Build per-mount virtiofs devices. Tag = "s{idx}" (0..N). The
        // matching `MountManifest` is sent post-Hello so init mounts each at
        // its requested guest path. We canonicalize each mount.host up front
        // so the SharedDirectory pin is the resolved path.
        let mut extra_share_configs = Vec::with_capacity(mount_specs.len());
        for (idx, m) in mount_specs.iter().enumerate() {
            let host = m
                .host
                .canonicalize()
                .map_err(|e| Error::exec(format!("canonicalize {}: {e}", m.host.display())))?;
            let host_s = host.to_string_lossy().into_owned();
            let tag = format!("s{idx}");
            let dir = SharedDirectory::new(&host_s, m.read_only)
                .map_err(|e| Error::exec(format!("SharedDirectory({host_s}): {e}")))?;
            let single =
                SingleDirectoryShare::new(dir).map_err(|e| Error::exec(format!("SingleDirectoryShare({tag}): {e}")))?;
            let mut cfg_dev = VirtioFileSystemDeviceConfiguration::new(&tag)
                .map_err(|e| Error::exec(format!("VirtioFileSystemDevice({tag}): {e}")))?;
            cfg_dev.set_share(single);
            extra_share_configs.push(cfg_dev);
        }

        let serial = SerialPortConfiguration::virtio_console().map_err(|e| Error::exec(format!("SerialPort: {e}")))?;
        let serial_read_fd = serial.read_fd(); // capture before move

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
        for dev in extra_share_configs {
            config.add_directory_share(dev);
        }

        // Network: only add virtio-net when not fully blocked.
        match cfg.network {
            NetworkPolicy::Blocked => {}
            _ => {
                let net_dev =
                    NetworkDeviceConfiguration::nat().map_err(|e| Error::exec(format!("NetworkDevice NAT: {e}")))?;
                config.add_network_device(net_dev);
            }
        }

        let vm = config.build().map_err(|e| Error::exec(format!("VM build: {e}")))?;

        tracing::info!(kernel = %kernel_s, initrd = %initrd_s, rootfs = %rootfs_s, "Booting VZ session VM");
        vm.start().await.map_err(|e| Error::exec(format!("VM start: {e}")))?;

        if vm.state() != VirtualMachineState::Running {
            return Err(Error::exec(format!("VM not running: {:?}", vm.state())));
        }
        // Connect VSOCK control channel. Read serial console while waiting
        // to capture init error messages.
        tracing::info!("VSOCK connecting to guest port {VSOCK_CONTROL_PORT}...");
        let socket_devices = vm.socket_devices();
        let socket_dev = socket_devices
            .first()
            .ok_or_else(|| Error::exec("no virtio-socket device"))?;

        let deadline = Instant::now() + VSOCK_CONNECT_TIMEOUT;
        let mut vsock_conn = None;
        let mut console_output = String::new();
        while Instant::now() < deadline {
            match socket_dev.connect(VSOCK_CONTROL_PORT).await {
                Ok(conn) => {
                    vsock_conn = Some(conn);
                    break;
                }
                Err(_) => {
                    // Drain serial for diagnostics.
                    if let Some(fd) = serial_read_fd {
                        let mut buf = [0u8; 4096];
                        unsafe {
                            let flags = libc::fcntl(fd, libc::F_GETFL);
                            if flags >= 0 {
                                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                            }
                            loop {
                                let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
                                if n <= 0 {
                                    break;
                                }
                                console_output.push_str(&String::from_utf8_lossy(&buf[..n as usize]));
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        let conn = vsock_conn.ok_or_else(|| {
            Error::exec(format!(
                "VSOCK connect timed out after {VSOCK_CONNECT_TIMEOUT:?}. Console:\n{console_output}"
            ))
        })?;

        let transport = VsockTransport::from_raw_fd(conn.into_raw_fd())?;
        let client = Arc::new(VsockInitClient::new(transport)?);
        let init_pid = client.hello()?;
        tracing::info!(init_pid, "VSOCK handshake complete");

        Ok::<_, Error>((vm, client))
    })?;

    // Apply the host-built mount manifest (no-op when there are no
    // extra_mounts). Each entry corresponds to a virtiofs device added
    // above with tag `s{idx}`. Sent after the async block so we don't
    // have to make the async closure `move`.
    if !manifest_entries.is_empty() {
        tracing::info!(count = manifest_entries.len(), "sending MountManifest");
        client.mount_manifest(manifest_entries)?;
    }

    Ok(VzSessionRunner {
        vm,
        client,
        rt,
        keepalive: VzSessionKeepalive { _rootfs: rootfs_keep },
    })
}

// ---------------------------------------------------------------------------
// Session shell — bridges init ↔ sentinel protocol
// ---------------------------------------------------------------------------

/// Inner state for the init-bridge pump thread (mirrors Linux `InitLifecycle`).
struct SessionLifecycle {
    exit_code: Mutex<Option<i32>>,
    cv: Condvar,
}

/// stdin implementation that sends Op::Write frames over VSOCK.
struct VsockStdin {
    client: Arc<VsockInitClient>,
    child_id: String,
    closed: bool,
}

impl Write for VsockStdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdin closed"));
        }
        self.client
            .write(&self.child_id, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for VsockStdin {
    fn drop(&mut self) {
        let _ = self.client.close_child(&self.child_id);
        self.closed = true;
    }
}

/// Spawn a bash shell inside the persistent VM and return a [`ShellHandle`]
/// with the sentinel-protocol bridge set up.
pub(crate) fn spawn_session_shell(cfg: &SandboxConfig) -> Result<ShellHandle> {
    let runner = boot_session_vm(cfg)?;
    let client = runner.client.clone();

    // Set up L7 proxy for Observed/Gated network policies.
    let (_proxy, proxy_env) = match &cfg.network {
        NetworkPolicy::Observed { sink } | NetworkPolicy::Gated { sink, .. } => {
            let proxy_cfg = ProxyConfig {
                sink: Arc::clone(sink),
                allow_hosts: Vec::new(),
                enforce_allow: matches!(cfg.network, NetworkPolicy::Gated { .. }),
            };
            let proxy =
                net_observer::start_proxy(proxy_cfg).map_err(|e| Error::exec(format!("start L7 proxy: {e}")))?;
            let addr = proxy.addr();
            let env = vec![
                ("HTTP_PROXY".to_string(), format!("http://{addr}")),
                ("HTTPS_PROXY".to_string(), format!("http://{addr}")),
                ("http_proxy".to_string(), format!("http://{addr}")),
                ("https_proxy".to_string(), format!("http://{addr}")),
            ];
            (Some(proxy), env)
        }
        _ => (None, Vec::new()),
    };

    // Shell env overlay includes proxy settings + caller's env.
    let mut shell_env: Vec<(String, String)> = proxy_env;
    for (k, v) in &cfg.env {
        shell_env.push((k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()));
    }

    // Open bash shell inside the VM.
    let info = client.open_shell(&["/bin/bash", "--noprofile", "--norc"], &shell_env, None)?;
    let child_id = info.child_id;
    tracing::info!(child_id, "VZ session shell opened");

    // Bridge pipes: pump thread reads init events → writes to pipes;
    // sentinel reader threads consume the read ends (same pattern as Linux).
    let (out_r, out_w) = pipe_pair()?;
    let (err_r, err_w) = pipe_pair()?;

    let lifecycle = Arc::new(SessionLifecycle {
        exit_code: Mutex::new(None),
        cv: Condvar::new(),
    });
    let stop = Arc::new(AtomicBool::new(false));

    // Pump thread.
    let pump_client = client.clone();
    let pump_child_id = child_id.clone();
    let pump_lifecycle = lifecycle.clone();
    let pump_stop = stop.clone();
    let pump = thread::Builder::new()
        .name("tps-vz-pump".into())
        .spawn(move || {
            let mut out_w = unsafe { std::fs::File::from_raw_fd(out_w.into_raw_fd()) };
            let mut err_w = unsafe { std::fs::File::from_raw_fd(err_w.into_raw_fd()) };
            loop {
                if pump_stop.load(Ordering::Relaxed) {
                    break;
                }
                let dead = pump_client.is_dead();
                let deadline = Instant::now() + Duration::from_millis(200);
                let _ = pump_client.wait_for_event(&pump_child_id, deadline);
                for chunk in pump_client.drain_stdout(&pump_child_id) {
                    if out_w.write_all(&chunk).is_err() {
                        break;
                    }
                }
                for chunk in pump_client.drain_stderr(&pump_child_id) {
                    if err_w.write_all(&chunk).is_err() {
                        break;
                    }
                }
                if let Some((code, _sig)) = pump_client.take_exit(&pump_child_id) {
                    let mut g = pump_lifecycle.exit_code.lock().expect("lifecycle");
                    *g = Some(code);
                    pump_lifecycle.cv.notify_all();
                    break;
                }
                if dead {
                    let mut g = pump_lifecycle.exit_code.lock().expect("lifecycle");
                    if g.is_none() {
                        *g = Some(-1);
                    }
                    pump_lifecycle.cv.notify_all();
                    break;
                }
            }
        })
        .map_err(|e| Error::exec(format!("spawn tps-vz-pump thread: {e}")))?;

    // stdin via VSOCK Write op.
    let stdin: Box<dyn std::io::Write + Send> = Box::new(VsockStdin {
        client: client.clone(),
        child_id: child_id.clone(),
        closed: false,
    });
    // stdout/stderr read ends from the bridge pipes.
    let stdout: Box<dyn std::io::Read + Send> = Box::new(unsafe { std::fs::File::from_raw_fd(out_r.into_raw_fd()) });
    let stderr: Box<dyn std::io::Read + Send> = Box::new(unsafe { std::fs::File::from_raw_fd(err_r.into_raw_fd()) });

    // try_wait: returns true when bash has exited.
    let try_wait_lifecycle = lifecycle.clone();
    let try_wait =
        Box::new(move || -> bool { try_wait_lifecycle.exit_code.lock().map(|g| g.is_some()).unwrap_or(true) });

    // shell_exit_code: returns the exit code when bash has exited.
    let exit_lifecycle = lifecycle.clone();
    let shell_exit_code: Box<dyn FnMut() -> Option<i32> + Send> =
        Box::new(move || -> Option<i32> { exit_lifecycle.exit_code.lock().ok().and_then(|g| *g) });

    // kill: best-effort SIGKILL the bash pgrp.
    let kill_client = client.clone();
    let kill_child_id = child_id.clone();
    let kill_lifecycle = lifecycle.clone();
    let kill = Box::new(move || {
        let _ = kill_client.signal(&kill_child_id, libc::SIGKILL, true);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut g = match kill_lifecycle.exit_code.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        while g.is_none() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (g2, _) = match kill_lifecycle.cv.wait_timeout(g, deadline - now) {
                Ok(x) => x,
                Err(_) => return,
            };
            g = g2;
        }
    });

    // Keepalive: must outlive the ShellHandle.
    let stop_for_keepalive = stop.clone();
    let keepalive: Box<dyn std::any::Any + Send> = Box::new(VzKeepalive {
        _runner: runner,
        _proxy,
        _pump: pump,
        _pump_stop: stop_for_keepalive,
    });

    // Factory closures — created here so they can capture the Arc<VsockInitClient>.

    // open_pty: spawn a PTY child inside the VM, bridge I/O via init protocol
    // (no SCM_RIGHTS on VSOCK — PTY master ↔ host I/O goes through Op::Write
    // + Stdout/Stderr events).
    let pty_client = client.clone();
    let open_pty: crate::session::OpenPtyFn = Box::new(
        move |rows: u16, cols: u16, argv: &[String], env: &[(String, String)], cwd: Option<&str>| {
            open_pty_via_init(Arc::clone(&pty_client), rows, cols, argv, env, cwd)
        },
    );

    // run_oneshot: independent pipes-mode child of init.
    let oneshot_client = client.clone();
    let run_oneshot: crate::session::RunOneshotFn = Box::new(move |cmd: &str, timeout: Duration| {
        let (stdout, stderr, code) = oneshot_client.run_oneshot(&["/bin/bash", "-c", cmd], &[], None, timeout)?;
        Ok(crate::session::ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
        })
    });

    // spawn_async: spawn a background job via pipe-mode, with env/cwd
    // inheritance from the shell.
    let spawn_client = client.clone();
    let spawn_shell_cid = child_id.clone();
    let job_map: Arc<Mutex<HashMap<u64, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let spawn_job_map = job_map.clone();
    let spawn_async: crate::session::SpawnAsyncFn = Box::new(move |job_id: u64, cmd: &str| {
        let handle =
            spawn_client.spawn_pipes_inherit_async(&["/bin/bash", "-c", cmd], &[], None, Some(&spawn_shell_cid))?;
        let cid = handle.child_id().to_string();
        spawn_job_map
            .lock()
            .map_err(|_| Error::exec("job map poisoned"))?
            .insert(job_id, cid);
        Ok(Box::new(VsockJobOutput {
            handle,
            _client: spawn_client.clone(),
        }))
    });

    // kill_spawn: look up child_id by job_id and SIGKILL.
    let kill_client = client.clone();
    let kill_job_map = job_map;
    let kill_spawn: crate::session::KillSpawnFn = Box::new(move |job_id: u64| {
        let child_id = {
            let map = kill_job_map.lock().map_err(|_| Error::exec("job map poisoned"))?;
            map.get(&job_id).cloned()
        };
        if let Some(cid) = child_id {
            // Best-effort: send SIGKILL, ignore result (child may already be dead).
            let _ = kill_client.signal(&cid, libc::SIGKILL, true);
        }
        // Always return Ok — caller uses wait_with_timeout to confirm death.
        Ok(())
    });

    Ok(ShellHandle {
        stdin,
        stdout,
        stderr,
        try_wait,
        kill,
        keepalive,
        open_pty: Some(Arc::new(open_pty)),
        run_oneshot: Some(Arc::new(run_oneshot)),
        spawn_async: Some(Arc::new(spawn_async)),
        kill_spawn: Some(Arc::new(kill_spawn)),
        shell_exit_code,
    })
}

// ---------------------------------------------------------------------------
// PTY support — production-quality implementation
// ---------------------------------------------------------------------------

/// Open a PTY child inside the VM.
///
/// Architecture (mirrors Firecracker / Kata Containers):
/// ```text
///   Host PTY master (posix_openpt, raw mode)
///     ↕ mio event loop on dedicated thread
///   Init protocol bridge (Op::Write / Stdout events / Op::Resize)
///     ↕
///   Guest PTY (real controlling terminal for child process)
/// ```
///
/// The host PTY is in raw mode: all bytes including ^C, ^\, ^Z pass through
/// transparently. Signal generation happens on the guest PTY where the child
/// has a real terminal. Resize is handled on both sides (host TIOCSWINSZ +
/// guest Op::Resize). Backpressure via Op::Write Ack.
fn open_pty_via_init(
    client: Arc<VsockInitClient>,
    rows: u16,
    cols: u16,
    argv: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
) -> Result<crate::session::PtyHandle> {
    // Open host-side PTY master. The slave side is unused — the real PTY
    // is inside the guest. We use the host master as a poll-able I/O endpoint.
    let host_master = crate::host::pty::open_pty_master().map_err(|e| Error::exec(format!("open host PTY: {e}")))?;
    crate::host::pty::set_winsize(host_master.as_fd().as_raw_fd(), rows, cols)
        .map_err(|e| Error::exec(format!("set winsize: {e}")))?;

    // Spawn child in Pty mode inside the guest. The init server allocates a
    // real PTY for the child and bridges I/O through the protocol.
    let argv_strs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let (info, _no_fd) = client.spawn_pty(&argv_strs, env, cwd, rows, cols)?;
    let child_id = info.child_id;

    // Bridge pump: host PTY master ↔ init protocol.
    let bridge_client = client.clone();
    let bridge_cid = child_id.clone();
    let host_master_raw = host_master.as_fd().as_raw_fd();
    let bridge_master_raw = host_master_raw;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_pump = stop.clone();

    // Set raw mode: bytes (including ^C, ^\, ^Z) pass through transparently.
    // Signal generation happens on the guest PTY where the child has a real terminal.
    crate::host::pty::set_raw_mode(host_master_raw).map_err(|e| Error::exec(format!("set raw mode: {e}")))?;

    let pump = thread::Builder::new()
        .name("tps-vz-pty".into())
        .spawn(move || {
            let mut poll = match Poll::new() {
                Ok(p) => p,
                Err(_) => return,
            };
            let mut events = Events::with_capacity(4);
            const TOK_MASTER: Token = Token(0);
            if poll
                .registry()
                .register(&mut SourceFd(&bridge_master_raw), TOK_MASTER, Interest::READABLE)
                .is_err()
            {
                return;
            }
            let mut buf = [0u8; 8192];
            loop {
                if stop_pump.load(Ordering::Relaxed) {
                    break;
                }
                // Poll PTY master with 50ms cap. Guest output drained every iteration.
                let _ = poll.poll(&mut events, Some(Duration::from_millis(50)));

                // Host → Guest: forward user input via Op::Write.
                for _ev in events.iter() {
                    loop {
                        let n = unsafe { libc::read(bridge_master_raw, buf.as_mut_ptr().cast(), buf.len()) };
                        if n > 0 {
                            let _ = bridge_client.write(&bridge_cid, &buf[..n as usize]);
                        } else {
                            break;
                        }
                    }
                }
                // Guest → Host: drain Stdout events, write to PTY master.
                for chunk in bridge_client.drain_stdout(&bridge_cid) {
                    unsafe {
                        let _ = libc::write(bridge_master_raw, chunk.as_ptr().cast(), chunk.len());
                    }
                }
                if bridge_client.take_exit(&bridge_cid).is_some() || bridge_client.is_dead() {
                    break;
                }
            }
        })
        .map_err(|e| Error::exec(format!("spawn PTY pump: {e}")))?;

    let resize_client = client.clone();
    let resize_cid = child_id.clone();
    let resize_fn: Box<dyn Fn(u16, u16) -> Result<()> + Send + Sync> = Box::new(move |r: u16, c: u16| {
        // Resize host PTY master.
        let _ = crate::host::pty::set_winsize(host_master_raw, r, c);
        // Resize guest PTY master.
        resize_client.resize(&resize_cid, r, c)
    });

    let kill_client = client.clone();
    let kill_cid = child_id.clone();
    let stop_kill = stop.clone();
    let kill_fn: Box<dyn Fn() + Send + Sync> = Box::new(move || {
        stop_kill.store(true, Ordering::Relaxed);
        let _ = kill_client.signal(&kill_cid, libc::SIGKILL, true);
    });

    let wait_client = client.clone();
    let wait_cid = child_id.clone();
    let wait_fn: Box<dyn Fn(Duration) -> Option<i32> + Send + Sync> = Box::new(move |timeout: Duration| {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some((code, _sig)) = wait_client.take_exit(&wait_cid) {
                return Some(code);
            }
            if wait_client.is_dead() {
                return Some(-1);
            }
            wait_client.wait_for_event(&wait_cid, deadline);
        }
        None
    });

    let keepalive: Box<dyn std::any::Any + Send + Sync> = Box::new((client.clone(), pump, stop));

    Ok(crate::session::PtyHandle::new(
        #[cfg(unix)]
        host_master,
        child_id,
        resize_fn,
        kill_fn,
        wait_fn,
        keepalive,
    ))
}

// Helper to create pipe pairs.
fn pipe_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(Error::exec(format!("pipe: {}", std::io::Error::last_os_error())));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

// ---------------------------------------------------------------------------
// Keepalive + JobOutput
// ---------------------------------------------------------------------------

struct VzKeepalive {
    _runner: VzSessionRunner,
    _proxy: Option<ProxyHandle>,
    _pump: JoinHandle<()>,
    _pump_stop: Arc<AtomicBool>,
}

/// [`JobOutput`] implementation backed by a VSOCK pipe-mode child.
struct VsockJobOutput {
    handle: ChildHandle,
    _client: Arc<VsockInitClient>,
}

impl crate::session::JobOutput for VsockJobOutput {
    fn wait_with_timeout(&self, timeout: Duration) -> Result<crate::session::ExecOutput> {
        let (stdout, stderr, code) = self.handle.wait_with_timeout(timeout)?;
        Ok(crate::session::ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
        })
    }
}
