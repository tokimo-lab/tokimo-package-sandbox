//! Cloud Hypervisor backend implementing `SandboxBackend` via the bundled
//! `cloud-hypervisor` + `virtiofsd` and the vsock init protocol.
//!
//! This is a straight port of `src/macos/sandbox.rs`. The only material
//! differences are:
//!
//! * the hypervisor is cloud-hypervisor (out-of-process child) instead of
//!   Apple's Virtualization.framework (in-process via `arcbox-vz`);
//! * all four host listeners are plain `UnixListener`s on
//!   `<vsock_uds>_<port>` sidecar paths rather than VZ
//!   `VirtioSocketListener`s, because CH uses firecracker-style
//!   hybrid-vsock;
//! * `tokimo.guest_listens=0` (all four channels are guest-initiated).
//!
//! Everything else — the init protocol, the FuseHost, the netstack, the
//! host-exec bridge, the boot-shell + event-pump pattern — is identical.

use std::collections::HashSet;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tokio::runtime::Runtime;

use crate::api::{ConfigureParams, Event, JobId, Mount, NetworkPolicy, ShellOpts};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

use super::vmm::{BootedChVm, ChVm, ChVmConfig, FUSE_VSOCK_PORT, boot_ch_vm};

use crate::init_client::InitClient;
use crate::init_client::vsock::VsockSend;
use crate::vfs_host::FuseHost;
use crate::vfs_impls::LocalDirVfs;

type ChInitClient = InitClient<VsockSend>;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Cloud Hypervisor backend: boots a Linux VM with `tokimo-sandbox-init`,
/// communicates over hybrid-vsock UDS sidecar sockets.
pub struct ChBackend {
    state: Mutex<State>,
    event_senders: Arc<Mutex<Vec<Sender<Event>>>>,
    debug_logging: Mutex<bool>,
    pending_host_exec_cb: Mutex<Option<crate::api::HostExecCallback>>,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Empty,
    Configured { params: ConfigureParams },
    Running(Box<RunningState>),
    Stopped,
}

struct RunningState {
    /// Owns the cloud-hypervisor + virtiofsd children. Dropping reaps them.
    vm: ChVm,
    init: Arc<ChInitClient>,
    fuse_host: Arc<FuseHost>,
    shell_id: String,
    shells: HashSet<String>,
    runtime: Arc<Runtime>,
    boot_share_names: HashSet<String>,
    fuse_mount_names: HashSet<String>,
    netstack_shutdown: Arc<std::sync::atomic::AtomicBool>,
    host_exec_bridge: Option<Arc<crate::host_exec::HostExecBridge>>,
    host_exec_commands: HashSet<String>,
    params: ConfigureParams,
    started_at_unix_ms: u64,
}

impl ChBackend {
    /// Construct an empty backend. Probes for the bundled
    /// cloud-hypervisor / virtiofsd / kernel binaries and fails fast if
    /// any of them are missing — this lets `SharedBackend` fall back to
    /// bwrap on a developer machine that hasn't fetched the VM artifacts.
    pub fn new() -> Result<Self> {
        let _ = super::vmm::cloud_hypervisor_binary()?;
        let _ = super::vmm::virtiofsd_binary()?;
        Ok(Self {
            state: Mutex::new(State::Empty),
            event_senders: Arc::new(Mutex::new(Vec::new())),
            debug_logging: Mutex::new(false),
            pending_host_exec_cb: Mutex::new(None),
        })
    }

    fn emit_event(&self, event: Event) {
        let mut senders = self.event_senders.lock().unwrap();
        senders.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

impl SandboxBackend for ChBackend {
    fn active_backend(&self) -> crate::backend_kind::ActiveBackend {
        crate::backend_kind::ActiveBackend::Ch
    }

    fn configure(&self, params: ConfigureParams) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            State::Empty | State::Configured { .. } | State::Stopped => {
                *state = State::Configured { params };
                Ok(())
            }
            State::Running(_) => Err(Error::VmAlreadyRunning),
        }
    }

    fn create_vm(&self) -> Result<()> {
        Ok(())
    }

    fn start_vm(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let params = match &*state {
            State::Configured { params } => params.clone(),
            State::Empty => return Err(Error::NotConfigured),
            State::Running(_) => return Err(Error::VmAlreadyRunning),
            State::Stopped => return Err(Error::other("backend is stopped, please reconfigure")),
        };

        let _session_counter = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // ---- Boot VM ---------------------------------------------------
        let vm_config = ChVmConfig {
            memory_mb: params.memory_mb,
            cpu_count: params.cpu_count,
            network: params.network,
            base_rootfs: params.base_rootfs.clone(),
            vm_dir: params.vm_dir.clone(),
        };

        let BootedChVm {
            vm,
            init_listener,
            netstack_listener,
            fuse_listener,
            host_exec_listener,
        } = boot_ch_vm(&vm_config)?;

        // Tokio runtime drives FuseHost::serve tasks and async accept.
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| Error::other(format!("tokio runtime: {e}")))?,
        );

        // ---- Accept the guest's init connection ------------------------
        // tokimo-sandbox-init is started after the rootfs chroot in init.sh
        // and connects out to host CID 2 on port INIT_VSOCK_PORT.
        let vsock_fd = match accept_with_timeout(&init_listener, Duration::from_secs(60)) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(Error::other(format!(
                    "init handshake: accept on init sidecar failed: {e}"
                )));
            }
        };

        let init = match InitClient::<VsockSend>::connect(vsock_fd) {
            Ok(c) => Arc::new(c),
            Err(e) => return Err(e),
        };

        if let Err(e) = init.hello() {
            let _ = init.shutdown();
            drop(init);
            drop(vm);
            return Err(e);
        }

        // ---- FUSE host -------------------------------------------------
        let fuse_host: Arc<FuseHost> = Arc::new(FuseHost::new());
        spawn_fuse_accept_loop(fuse_listener, fuse_host.clone(), runtime.clone());

        // ---- Host-Exec Bridge -----------------------------------------
        let host_exec_cb: crate::api::HostExecCallback = self
            .pending_host_exec_cb
            .lock()
            .ok()
            .and_then(|mut g| g.take())
            .unwrap_or_else(|| {
                Arc::new(|ctx: crate::api::HostExecCtx| crate::api::HostExecAction::RunOnHost {
                    argv: ctx.argv,
                    env: ctx.env,
                    cwd: ctx.cwd,
                })
            });
        let host_exec_bridge = Arc::new(crate::host_exec::HostExecBridge::new(host_exec_cb));
        spawn_host_exec_accept_loop(host_exec_listener, host_exec_bridge.clone());

        // ---- Netstack: accept the guest's tun-pump connection ---------
        let egress = match params.network {
            NetworkPolicy::AllowAll => crate::netstack::EgressPolicy::AllowAll,
            NetworkPolicy::Blocked => crate::netstack::EgressPolicy::Blocked,
        };
        let local_services: Vec<crate::netstack::LocalService> = Vec::new();

        let netstack_shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        match accept_with_timeout(&netstack_listener, Duration::from_secs(30)) {
            Ok(fd) => {
                use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
                let dup_raw = unsafe { libc::dup(fd.as_raw_fd()) };
                if dup_raw < 0 {
                    tracing::warn!("netstack dup fd failed; netstack disabled this session");
                } else {
                    let write_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
                    let read_file = std::fs::File::from(fd);
                    let write_file = std::fs::File::from(write_fd);
                    let _ = crate::netstack::spawn(
                        Box::new(read_file),
                        Box::new(write_file),
                        Arc::clone(&netstack_shutdown),
                        egress,
                        local_services,
                    );
                }
            }
            Err(e) => tracing::warn!("netstack accept: {e}"),
        }

        // ---- Mount each boot-time share via FUSE ----------------------
        let mut boot_share_names = HashSet::new();
        let mut fuse_mount_names = HashSet::new();
        for share in &params.mounts {
            if share.create_host_dir
                && !share.host_path.exists()
                && let Err(e) = std::fs::create_dir_all(&share.host_path)
            {
                let _ = init.shutdown();
                return Err(Error::other(format!(
                    "create_host_dir {}: {e}",
                    share.host_path.display()
                )));
            }
            let backend = LocalDirVfs::arc(share.host_path.clone());
            fuse_host.register_mount(share.name.clone(), backend, share.read_only);
            let guest = share.guest_path.to_string_lossy().into_owned();
            if let Err(e) = init.mount_fuse(&share.name, FUSE_VSOCK_PORT, &guest, share.read_only) {
                let _ = init.shutdown();
                return Err(e);
            }
            boot_share_names.insert(share.name.clone());
            fuse_mount_names.insert(share.name.clone());
        }

        // ---- Open long-lived shell ------------------------------------
        let shell_argv = vec!["/bin/sh".to_string()];
        let shell_info = match init.open_shell(&shell_argv, &[], None) {
            Ok(i) => i,
            Err(e) => {
                let _ = init.shutdown();
                return Err(e);
            }
        };
        let shell_id = shell_info.child_id.clone();
        let mut shells = HashSet::new();
        shells.insert(shell_id.clone());

        self.emit_event(Event::Ready);
        self.emit_event(Event::GuestConnected { connected: true });

        // ---- Event pump thread ----------------------------------------
        let init_for_pump = init.clone();
        let event_senders = self.event_senders.clone();
        thread::Builder::new()
            .name("tokimo-ch-event-pump".into())
            .spawn(move || event_pump_loop(init_for_pump, event_senders))
            .map_err(|e| Error::other(format!("spawn event pump thread: {e}")))?;

        *state = State::Running(Box::new(RunningState {
            vm,
            init,
            fuse_host,
            shell_id,
            shells,
            runtime,
            boot_share_names,
            fuse_mount_names,
            netstack_shutdown,
            host_exec_bridge: Some(host_exec_bridge),
            host_exec_commands: HashSet::new(),
            params: params.clone(),
            started_at_unix_ms: now_unix_ms(),
        }));

        Ok(())
    }

    fn stop_vm(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let prev = std::mem::replace(&mut *state, State::Stopped);
        match prev {
            State::Running(rs) => {
                let RunningState {
                    init,
                    vm,
                    runtime,
                    fuse_host,
                    netstack_shutdown,
                    host_exec_bridge,
                    ..
                } = *rs;
                netstack_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
                if let Some(b) = host_exec_bridge {
                    b.shutdown();
                }
                let _ = init.shutdown();
                drop(init);
                drop(fuse_host);
                // Dropping `vm` SIGTERMs cloud-hypervisor + virtiofsd and
                // reaps both, then removes the UDS files.
                drop(vm);
                drop(runtime);
                self.emit_event(Event::GuestConnected { connected: false });
                Ok(())
            }
            State::Empty | State::Configured { .. } => {
                *state = prev;
                Err(Error::VmNotRunning)
            }
            State::Stopped => {
                *state = State::Stopped;
                Ok(())
            }
        }
    }

    fn is_running(&self) -> Result<bool> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running(rs) => Ok(!rs.init.is_dead()),
            _ => Ok(false),
        }
    }

    fn is_guest_connected(&self) -> Result<bool> {
        self.is_running()
    }

    fn is_process_running(&self, id: &JobId) -> Result<bool> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running(rs) => Ok(rs.init.take_exit(id.as_str()).is_none()),
            _ => Err(Error::VmNotRunning),
        }
    }

    fn shell_id(&self) -> Result<JobId> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running(rs) => Ok(JobId(rs.shell_id.clone())),
            _ => Err(Error::VmNotRunning),
        }
    }

    fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId> {
        let mut state = self.state.lock().unwrap();
        let rs = match &mut *state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };
        let argv = opts.argv.clone().unwrap_or_else(|| vec!["/bin/sh".to_string()]);
        let shell_info = match opts.pty {
            None => rs
                .init
                .open_shell(&argv, &opts.env, opts.cwd.as_deref())
                .map_err(|e| Error::other(format!("open_shell: {e}")))?,
            Some((rows, cols)) => {
                let (shell_info, _) = rs
                    .init
                    .spawn_pty(&argv, &opts.env, opts.cwd.as_deref(), rows, cols)
                    .map_err(|e| Error::other(format!("spawn_pty: {e}")))?;
                shell_info
            }
        };
        rs.shells.insert(shell_info.child_id.clone());
        Ok(JobId(shell_info.child_id))
    }

    fn close_shell(&self, id: &JobId) -> Result<()> {
        let init = {
            let mut state = self.state.lock().unwrap();
            let rs = match &mut *state {
                State::Running(rs) => rs,
                _ => return Err(Error::VmNotRunning),
            };
            rs.shells.remove(id.as_str());
            rs.init.clone()
        };
        init.signal(id.as_str(), 15, true)
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running(rs) => Ok(rs.shells.iter().cloned().map(JobId).collect()),
            _ => Err(Error::VmNotRunning),
        }
    }

    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        let init = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => rs.init.clone(),
                _ => return Err(Error::VmNotRunning),
            }
        };
        init.write(id.as_str(), data)
    }

    fn signal_shell(&self, id: &JobId, sig: i32) -> Result<()> {
        let init = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => rs.init.clone(),
                _ => return Err(Error::VmNotRunning),
            }
        };
        init.signal(id.as_str(), sig, true)
    }

    fn resize_shell(&self, id: &JobId, rows: u16, cols: u16) -> Result<()> {
        let init = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => rs.init.clone(),
                _ => return Err(Error::VmNotRunning),
            }
        };
        init.resize(id.as_str(), rows, cols)
    }

    fn subscribe(&self) -> Result<Receiver<Event>> {
        let (tx, rx) = channel();
        let mut senders = self.event_senders.lock().unwrap();
        senders.push(tx);
        Ok(rx)
    }

    fn create_disk_image(&self, _path: &Path, _gib: u64) -> Result<()> {
        Err(Error::not_supported("create_disk_image on ch"))
    }

    fn set_debug_logging(&self, enabled: bool) -> Result<()> {
        let mut debug = self.debug_logging.lock().unwrap();
        *debug = enabled;
        Ok(())
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        let debug = self.debug_logging.lock().unwrap();
        Ok(*debug)
    }

    fn send_guest_response(&self, _raw: serde_json::Value) -> Result<()> {
        Err(Error::not_implemented("send_guest_response on ch"))
    }

    fn passthrough(&self, _method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
        Err(Error::not_implemented("passthrough on ch"))
    }

    fn on_host_exec(&self, cb: crate::api::HostExecCallback) -> Result<()> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running(rs) => {
                if let Some(bridge) = &rs.host_exec_bridge {
                    bridge.set_callback(cb);
                    Ok(())
                } else {
                    Err(Error::other("host-exec bridge not initialised"))
                }
            }
            _ => {
                drop(state);
                *self.pending_host_exec_cb.lock().unwrap() = Some(cb);
                Ok(())
            }
        }
    }

    fn add_host_command(&self, name: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let rs = match &mut *state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };
        if rs.host_exec_commands.contains(name) {
            return Ok(());
        }
        rs.init
            .add_host_command(name)
            .map_err(|e| Error::other(format!("add_host_command: {e}")))?;
        rs.host_exec_commands.insert(name.to_string());
        Ok(())
    }

    fn remove_host_command(&self, name: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let rs = match &mut *state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };
        if !rs.host_exec_commands.remove(name) {
            return Ok(());
        }
        rs.init
            .remove_host_command(name)
            .map_err(|e| Error::other(format!("remove_host_command: {e}")))
    }

    fn set_host_commands(&self, names: &[String]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let rs = match &mut *state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };
        rs.init
            .set_host_commands(names)
            .map_err(|e| Error::other(format!("set_host_commands: {e}")))?;
        rs.host_exec_commands = names.iter().cloned().collect();
        Ok(())
    }

    fn list_host_commands(&self) -> Result<Vec<String>> {
        let state = self.state.lock().unwrap();
        let rs = match &*state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };
        let mut v: Vec<String> = rs.host_exec_commands.iter().cloned().collect();
        v.sort();
        Ok(v)
    }

    fn add_mount(&self, share: Mount) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let rs = match &mut *state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };

        if rs.boot_share_names.contains(&share.name) {
            return Err(Error::validation(format!(
                "share name '{}' is reserved by a boot-time share",
                share.name
            )));
        }
        if rs.fuse_mount_names.contains(&share.name) {
            return Err(Error::validation(format!("share '{}' is already mounted", share.name)));
        }
        if share.name == "work" || share.name.is_empty() || share.name.contains('/') {
            return Err(Error::validation(format!("invalid share name: '{}'", share.name)));
        }
        if share.create_host_dir && !share.host_path.exists() {
            std::fs::create_dir_all(&share.host_path)
                .map_err(|e| Error::other(format!("create_host_dir {}: {e}", share.host_path.display())))?;
        }
        if !share.host_path.exists() {
            return Err(Error::validation(format!(
                "host_path does not exist: {}",
                share.host_path.display()
            )));
        }

        let backend = LocalDirVfs::arc(share.host_path.clone());
        let mount_id = rs
            .fuse_host
            .register_mount(share.name.clone(), backend, share.read_only);

        let guest = share.guest_path.to_string_lossy().into_owned();
        if let Err(e) = rs
            .init
            .mount_fuse(&share.name, FUSE_VSOCK_PORT, &guest, share.read_only)
        {
            let _ = rs.fuse_host.remove_mount(mount_id);
            return Err(e);
        }

        rs.fuse_mount_names.insert(share.name.clone());
        Ok(())
    }

    fn remove_mount(&self, name: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let rs = match &mut *state {
            State::Running(rs) => rs,
            _ => return Err(Error::VmNotRunning),
        };

        if rs.boot_share_names.contains(name) {
            return Err(Error::validation(format!(
                "share '{name}' was declared at boot time and cannot be removed at runtime"
            )));
        }
        if !rs.fuse_mount_names.remove(name) {
            return Err(Error::validation(format!("no such share '{name}'")));
        }

        let unmount_err = rs.init.unmount_fuse(name).err();
        if let Some(mount_id) = rs.fuse_host.mount_id_by_name(name) {
            let _ = rs.fuse_host.remove_mount(mount_id);
        }
        if let Some(e) = unmount_err {
            return Err(e);
        }
        Ok(())
    }

    fn list_sessions(&self) -> Result<Vec<crate::SessionSummary>> {
        let state = self.state.lock().unwrap();
        Ok(match &*state {
            State::Empty | State::Stopped => Vec::new(),
            State::Configured { params } => vec![crate::SessionSummary {
                name: session_name(params),
                user_data_name: params.user_data_name.clone(),
                running: false,
                guest_connected: false,
                memory_mb: params.memory_mb,
                started_at_unix_ms: None,
            }],
            State::Running(rs) => vec![crate::SessionSummary {
                name: session_name(&rs.params),
                user_data_name: rs.params.user_data_name.clone(),
                running: true,
                guest_connected: !rs.init.is_dead(),
                memory_mb: rs.params.memory_mb,
                started_at_unix_ms: Some(rs.started_at_unix_ms),
            }],
        })
    }

    fn session_info(&self, name: &str) -> Result<Option<crate::SessionDetails>> {
        let state = self.state.lock().unwrap();
        Ok(match &*state {
            State::Empty | State::Stopped => None,
            State::Configured { params } if session_name(params) == name => Some(crate::SessionDetails {
                summary: crate::SessionSummary {
                    name: session_name(params),
                    user_data_name: params.user_data_name.clone(),
                    running: false,
                    guest_connected: false,
                    memory_mb: params.memory_mb,
                    started_at_unix_ms: None,
                },
                owner_pid: None,
                shell_count: 0,
                mount_count: 0,
            }),
            State::Configured { .. } => None,
            State::Running(rs) if session_name(&rs.params) == name => Some(crate::SessionDetails {
                summary: crate::SessionSummary {
                    name: session_name(&rs.params),
                    user_data_name: rs.params.user_data_name.clone(),
                    running: true,
                    guest_connected: !rs.init.is_dead(),
                    memory_mb: rs.params.memory_mb,
                    started_at_unix_ms: Some(rs.started_at_unix_ms),
                },
                owner_pid: None,
                shell_count: rs.shells.len(),
                mount_count: rs.fuse_mount_names.len(),
            }),
            State::Running(_) => None,
        })
    }

    fn stop_session(&self, name: &str) -> Result<()> {
        let matches = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => session_name(&rs.params) == name,
                _ => false,
            }
        };
        if matches { self.stop_vm() } else { Ok(()) }
    }
}

fn session_name(params: &ConfigureParams) -> String {
    if !params.session_id.is_empty() {
        params.session_id.clone()
    } else {
        params.user_data_name.clone()
    }
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Block-accept one connection on a std `UnixListener` within `timeout`.
/// Returns the accepted stream as an `OwnedFd` (caller owns).
fn accept_with_timeout(listener: &StdUnixListener, timeout: Duration) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Switch the *connection* back to blocking. (The listener's
                // non-blocking flag does not propagate to accepted sockets,
                // but be explicit.)
                let fd = stream.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL);
                    if flags >= 0 {
                        let _ = libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                    }
                }
                return Ok(unsafe { OwnedFd::from_raw_fd(stream.into_raw_fd()) });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("accept timed out after {timeout:?}"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Event pump: drains stdout/stderr and exit notifications for **every**
/// child the guest tells us about (identical to macOS).
fn event_pump_loop(init: Arc<ChInitClient>, event_senders: Arc<Mutex<Vec<Sender<Event>>>>) {
    let mut seen_exit: HashSet<String> = HashSet::new();

    loop {
        let ids = init.child_ids();
        for child_id in ids {
            for chunk in init.drain_stdout(&child_id) {
                let event = Event::Stdout {
                    id: JobId(child_id.clone()),
                    data: chunk,
                };
                let mut senders = event_senders.lock().unwrap();
                senders.retain(|tx| tx.send(event.clone()).is_ok());
            }
            for chunk in init.drain_stderr(&child_id) {
                let event = Event::Stderr {
                    id: JobId(child_id.clone()),
                    data: chunk,
                };
                let mut senders = event_senders.lock().unwrap();
                senders.retain(|tx| tx.send(event.clone()).is_ok());
            }
            if !seen_exit.contains(&child_id)
                && let Some((code, sig)) = init.take_exit(&child_id)
            {
                let event = Event::Exit {
                    id: JobId(child_id.clone()),
                    exit_code: code,
                    signal: sig,
                };
                let mut senders = event_senders.lock().unwrap();
                senders.retain(|tx| tx.send(event.clone()).is_ok());
                seen_exit.insert(child_id);
            }
        }

        if init.is_dead() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let event = Event::GuestConnected { connected: false };
    let mut senders = event_senders.lock().unwrap();
    senders.retain(|tx| tx.send(event.clone()).is_ok());
}

/// Spawn a tokio task on `runtime` that accepts FUSE connections from the
/// sidecar UDS listener and hands each one to `FuseHost::serve`.
fn spawn_fuse_accept_loop(listener: StdUnixListener, fuse_host: Arc<FuseHost>, runtime: Arc<Runtime>) {
    let _ = listener.set_nonblocking(true);
    let tokio_listener = match runtime.block_on(async { tokio::net::UnixListener::from_std(listener) }) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("fuse listener tokio adapt failed: {e}");
            return;
        }
    };
    runtime.spawn(async move {
        loop {
            match tokio_listener.accept().await {
                Ok((stream, _)) => {
                    let host = fuse_host.clone();
                    tokio::spawn(async move {
                        if let Err(e) = host.serve(stream).await {
                            tracing::warn!("fuse_host serve: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("fuse listener accept failed: {e}");
                    break;
                }
            }
        }
    });
}

/// Spawn a dedicated thread that accepts host-exec connections from the
/// sidecar UDS listener and runs `HostExecBridge::handle_one` per
/// connection on a per-connection worker thread.
fn spawn_host_exec_accept_loop(listener: StdUnixListener, bridge: Arc<crate::host_exec::HostExecBridge>) {
    thread::Builder::new()
        .name("tokimo-ch-host-exec-accept".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let b = bridge.clone();
                        thread::Builder::new()
                            .name("tokimo-ch-host-exec-conn".into())
                            .spawn(move || {
                                b.handle_one(stream);
                            })
                            .ok();
                    }
                    Err(e) => {
                        tracing::warn!("host-exec accept failed: {e}");
                        break;
                    }
                }
            }
        })
        .ok();
}
