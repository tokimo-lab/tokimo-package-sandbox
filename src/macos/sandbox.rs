//! macOS backend implementing `SandboxBackend` via `arcbox-vz` + the
//! VSOCK init protocol.
//!
//! Lifecycle:
//!  * `configure` stores params (allowed Empty → Configured, Configured →
//!     Configured, Stopped → Configured).
//!  * `start_vm` boots the VM, runs the init Hello handshake, starts the
//!     in-process NFSv3 server (see `src/macos/nfs.rs`), registers each
//!     `ConfigureParams.mounts` entry with it, asks the guest to
//!     `mount(2) -t nfs` each one, and opens the long-lived shell.
//!  * `stop_vm` shuts down the VM and the NFS server.
//!  * `add_mount` / `remove_mount` register / tombstone mounts in the
//!     in-process NFS server and drive the guest `MountNfs` / `UnmountNfs`
//!     ops to mount / unmount via the smoltcp gateway.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use arcbox_vz::VirtualMachine;
use tokio::runtime::Runtime;

use crate::api::{AddUserOpts, ConfigureParams, Event, JobId, Mount, NetworkPolicy, ShellOpts};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

use super::nfs::NfsServer;
use super::vm::{BootedVm, VmConfig, boot_vm};
use super::vsock_init_client::VsockInitClient;

/// Guest-visible TCP port the in-process NFS server is dialed at via the
/// smoltcp gateway IP (`HOST_IP = 192.168.127.1`). The host-side listener
/// is on an ephemeral `127.0.0.1:N`; the gateway splices the two via a
/// `LocalService`.
const NFS_GUEST_PORT: u16 = 2049;
/// Gateway IP (matches `crate::netstack::HOST_IP`).
const NFS_GUEST_IP: &str = "192.168.127.1";

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// macOS backend: boots a Linux VM with `tokimo-sandbox-init`, communicates
/// over virtio-vsock.
pub struct MacosBackend {
    state: Mutex<State>,
    event_senders: Arc<Mutex<Vec<Sender<Event>>>>,
    debug_logging: Mutex<bool>,
}

enum State {
    Empty,
    Configured { params: ConfigureParams },
    Running(Box<RunningState>),
    Stopped,
}

struct RunningState {
    vm: VirtualMachine,
    init: Arc<VsockInitClient>,
    /// In-process NFSv3 server backing all user mounts. Dropped before
    /// `vm` so any in-flight client connections through the netstack
    /// gateway tear down cleanly first.
    nfs: Option<NfsServer>,
    /// Long-lived boot-time shell child id.
    shell_id: String,
    /// All shells active in this session: the boot shell + any returned
    /// from `spawn_shell`. `close_shell` removes from the set.
    shells: HashSet<String>,
    /// Tokio runtime that drove `vm.start()`, the VSOCK connect, and the
    /// NFS server. **must** outlive the VM, otherwise the underlying
    /// Objective-C completion handlers and dispatch queues are released
    /// and the VSOCK fd dies.
    runtime: Arc<Runtime>,
    /// Names of shares declared at boot time (cannot be removed at runtime).
    boot_share_names: HashSet<String>,
    /// All NFS-backed mounts currently registered (boot + runtime).
    nfs_mount_names: HashSet<String>,
    /// Shutdown flag for the netstack thread. Setting true causes the
    /// reader/writer threads to exit at their next iteration.
    netstack_shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl MacosBackend {
    /// Construct an empty backend. Call `configure()` then `start_vm()` to boot.
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Mutex::new(State::Empty),
            event_senders: Arc::new(Mutex::new(Vec::new())),
            debug_logging: Mutex::new(false),
        })
    }

    fn emit_event(&self, event: Event) {
        let mut senders = self.event_senders.lock().unwrap();
        senders.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

impl SandboxBackend for MacosBackend {
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
        // No-op on macOS: VM lifecycle is fully covered by start_vm.
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

        // Used for debug logs / future per-session diagnostics. The dynamic
        // mount pool used to live under `~/.tokimo/sessions/<sid>/` but
        // host directories are now exposed directly through the NFS server.
        let _session_counter = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // ---- Boot VM ---------------------------------------------------
        let vm_config = VmConfig {
            memory_mb: params.memory_mb,
            cpu_count: params.cpu_count,
            network: params.network,
        };

        let BootedVm {
            vm,
            vsock,
            netstack_listener: mut listener,
            runtime,
        } = boot_vm(&vm_config)?;

        let init = Arc::new(VsockInitClient::new(vsock)?);

        // Hello handshake.
        if let Err(e) = init.hello() {
            let _ = init.shutdown();
            let _ = runtime.block_on(vm.stop());
            return Err(e);
        }

        // ---- NFS server ------------------------------------------------
        // Spawn the per-session NFSv3 server BEFORE the netstack so we
        // know the local port to register as a `LocalService`.
        let nfs = match NfsServer::start(runtime.clone()) {
            Ok(s) => s,
            Err(e) => {
                let _ = init.shutdown();
                let _ = runtime.block_on(vm.stop());
                return Err(e);
            }
        };

        // ---- Network: always-on userspace netstack ---------------------
        // The smoltcp gateway runs regardless of `NetworkPolicy`. The
        // policy becomes an `EgressPolicy` filter inside the gateway:
        // `Blocked` only routes registered `LocalService` flows (the NFS
        // server). `AllowAll` additionally splices arbitrary upstream
        // connect attempts.
        let egress = match params.network {
            NetworkPolicy::AllowAll => crate::netstack::EgressPolicy::AllowAll,
            NetworkPolicy::Blocked => crate::netstack::EgressPolicy::Blocked,
        };
        let local_services = vec![crate::netstack::LocalService {
            host_port: NFS_GUEST_PORT,
            local_addr: format!("127.0.0.1:{}", nfs.local_port).parse().unwrap(),
        }];

        let accept = runtime.block_on(async { tokio::time::timeout(Duration::from_secs(30), listener.accept()).await });
        let netstack_shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        match accept {
            Ok(Ok(conn)) => {
                use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
                let read_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(conn.into_raw_fd()) };
                let dup_raw = unsafe { libc::dup(read_fd.as_raw_fd()) };
                if dup_raw < 0 {
                    tracing::warn!("netstack dup fd failed; netstack disabled this session");
                } else {
                    let write_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
                    let read_file = std::fs::File::from(read_fd);
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
            Ok(Err(e)) => tracing::warn!("netstack accept error: {e}"),
            Err(_) => tracing::warn!("netstack accept timeout"),
        }

        // ---- Mount each boot-time share via NFS ------------------------
        let mut boot_share_names = HashSet::new();
        let mut nfs_mount_names = HashSet::new();
        for share in &params.mounts {
            // `create_host_dir` is honoured here because virtio-fs used to
            // require the host directory to exist; NFS doesn't strictly,
            // but downstream code (and tests) rely on it.
            if share.create_host_dir && !share.host_path.exists() {
                if let Err(e) = std::fs::create_dir_all(&share.host_path) {
                    let _ = init.shutdown();
                    let _ = runtime.block_on(vm.stop());
                    return Err(Error::other(format!(
                        "create_host_dir {}: {e}",
                        share.host_path.display()
                    )));
                }
            }
            if let Err(e) = nfs.add_mount(&share.name, share.host_path.clone(), share.read_only) {
                let _ = init.shutdown();
                let _ = runtime.block_on(vm.stop());
                return Err(e);
            }
            let guest = share.guest_path.to_string_lossy().into_owned();
            let export = format!("/{}", share.name);
            if let Err(e) = init.mount_nfs(
                &share.name,
                NFS_GUEST_IP,
                NFS_GUEST_PORT,
                &export,
                &guest,
                share.read_only,
            ) {
                let _ = init.shutdown();
                let _ = runtime.block_on(vm.stop());
                return Err(e);
            }
            boot_share_names.insert(share.name.clone());
            nfs_mount_names.insert(share.name.clone());
        }

        // ---- Open long-lived shell --------------------------------------
        let shell_argv = vec!["/bin/sh".to_string()];
        let shell_info = match init.open_shell(&shell_argv, &[], None) {
            Ok(i) => i,
            Err(e) => {
                let _ = init.shutdown();
                let _ = runtime.block_on(vm.stop());
                return Err(e);
            }
        };
        let shell_id = shell_info.child_id.clone();
        let mut shells = HashSet::new();
        shells.insert(shell_id.clone());

        self.emit_event(Event::Ready);
        self.emit_event(Event::GuestConnected { connected: true });

        // ---- Event pump thread ------------------------------------------
        let init_for_pump = init.clone();
        let event_senders = self.event_senders.clone();
        thread::Builder::new()
            .name("tokimo-macos-event-pump".into())
            .spawn(move || event_pump_loop(init_for_pump, event_senders))
            .map_err(|e| Error::other(format!("spawn event pump thread: {e}")))?;

        *state = State::Running(Box::new(RunningState {
            vm,
            init,
            nfs: Some(nfs),
            shell_id,
            shells,
            runtime,
            boot_share_names,
            nfs_mount_names,
            netstack_shutdown,
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
                    nfs,
                    netstack_shutdown,
                    ..
                } = *rs;
                netstack_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = init.shutdown();
                drop(init);
                drop(nfs); // tear down NFS server task before dropping the runtime
                // Apple's VZVirtualMachine.stop() asserts when invoked off
                // its dispatch queue. Use request_stop (fire-and-forget),
                // wait briefly, then let Drop tear down the rest.
                let _ = runtime.block_on(async {
                    let _ = vm.request_stop();
                    tokio::time::sleep(Duration::from_millis(300)).await;
                });
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
            Some((rows, cols)) => rs
                .init
                .spawn_pty(&argv, &opts.env, opts.cwd.as_deref(), rows, cols)
                .map_err(|e| Error::other(format!("spawn_pty: {e}")))?,
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
        // SIGTERM the shell's process group; the event pump emits Exit.
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
        Err(Error::not_supported("create_disk_image on macOS"))
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
        Err(Error::not_implemented("send_guest_response on macOS"))
    }

    fn passthrough(&self, _method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
        Err(Error::not_implemented("passthrough on macOS"))
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
        if rs.nfs_mount_names.contains(&share.name) {
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

        // 1. Register with the in-process NFS server.
        let nfs = rs.nfs.as_ref().ok_or_else(|| Error::other("nfs server not running"))?;
        nfs.add_mount(&share.name, share.host_path.clone(), share.read_only)?;

        // 2. Ask the guest to `mount(2) -t nfs` it through the gateway.
        let guest = share.guest_path.to_string_lossy().into_owned();
        let export = format!("/{}", share.name);
        if let Err(e) = rs.init.mount_nfs(
            &share.name,
            NFS_GUEST_IP,
            NFS_GUEST_PORT,
            &export,
            &guest,
            share.read_only,
        ) {
            // Roll back the host-side registration so a retry can succeed.
            let _ = nfs.remove_mount(&share.name);
            return Err(e);
        }

        rs.nfs_mount_names.insert(share.name.clone());
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
        if !rs.nfs_mount_names.remove(name) {
            return Err(Error::validation(format!("no such share '{name}'")));
        }

        // Unmount in the guest first; if that fails we still tombstone
        // the host registration so a re-add of the same name succeeds.
        let unmount_err = rs.init.unmount_nfs(name).err();
        if let Some(nfs) = rs.nfs.as_ref() {
            let _ = nfs.remove_mount(name);
        }
        if let Some(e) = unmount_err {
            return Err(e);
        }
        Ok(())
    }

    fn add_user(&self, user_id: &str, opts: AddUserOpts) -> Result<JobId> {
        let init = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => rs.init.clone(),
                _ => return Err(Error::VmNotRunning),
            }
        };
        let home = opts
            .home
            .to_str()
            .ok_or_else(|| Error::other(format!("non-UTF-8 home: {:?}", opts.home)))?
            .to_string();
        let cwd = opts
            .cwd
            .as_ref()
            .map(|p| {
                p.to_str()
                    .ok_or_else(|| Error::other(format!("non-UTF-8 cwd: {p:?}")))
                    .map(str::to_string)
            })
            .transpose()?;
        let info = init
            .add_user(user_id, &home, cwd.as_deref(), &opts.env, opts.real_user)
            .map_err(|e| Error::other(format!("add_user: {e}")))?;
        let mut state = self.state.lock().unwrap();
        if let State::Running(rs) = &mut *state {
            rs.shells.insert(info.child_id.clone());
        }
        Ok(JobId(info.child_id))
    }

    fn remove_user(&self, user_id: &str) -> Result<()> {
        let init = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => rs.init.clone(),
                _ => return Err(Error::VmNotRunning),
            }
        };
        init.remove_user(user_id)
            .map_err(|e| Error::other(format!("remove_user: {e}")))
    }
}

/// Event pump: drains stdout/stderr and exit notifications for **every**
/// child the guest tells us about. We don't pre-register children; the
/// reader thread populates the per-child entry the first time it sees an
/// event, so we just iterate over the keys present in the shared map.
fn event_pump_loop(init: Arc<VsockInitClient>, event_senders: Arc<Mutex<Vec<Sender<Event>>>>) {
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
            if !seen_exit.contains(&child_id) {
                if let Some((code, sig)) = init.take_exit(&child_id) {
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
