//! macOS backend implementing `SandboxBackend` via `arcbox-vz` + the
//! VSOCK init protocol.
//!
//! Lifecycle:
//!  * `configure` stores params (allowed Empty → Configured, Configured →
//!    Configured, Stopped → Configured).
//!  * `start_vm` boots the VM, runs the init Hello handshake, starts the
//!    cross-platform `FuseHost` (see `src/vfs_host/`), registers each
//!    `ConfigureParams.mounts` entry with it, asks the guest to mount
//!    each one over FUSE-over-vsock, and opens the long-lived shell.
//!  * `stop_vm` shuts down the VM and the FuseHost.
//!  * `add_mount` / `remove_mount` register / tombstone mounts in the
//!    `FuseHost` and drive the guest `MountFuse` / `UnmountFuse` ops to
//!    mount / unmount via the dedicated FUSE vsock listener.

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

use super::vm::{BootedVm, FUSE_VSOCK_PORT, VmConfig, boot_vm};
use super::vsock_init_client::VsockInitClient;

use crate::vfs_host::FuseHost;
use crate::vfs_impls::LocalDirVfs;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// macOS backend: boots a Linux VM with `tokimo-sandbox-init`, communicates
/// over virtio-vsock.
pub struct MacosBackend {
    state: Mutex<State>,
    event_senders: Arc<Mutex<Vec<Sender<Event>>>>,
    debug_logging: Mutex<bool>,
}

#[allow(clippy::large_enum_variant)] // RunningState already boxed; ConfigureParams is the next biggest variant and is short-lived
enum State {
    Empty,
    Configured { params: ConfigureParams },
    Running(Box<RunningState>),
    Stopped,
}

struct RunningState {
    vm: VirtualMachine,
    init: Arc<VsockInitClient>,
    /// FUSE-over-vsock host. One per session; serves all dynamic mounts.
    /// Each `Mount` is registered as a [`LocalDirVfs`] backend.
    fuse_host: Arc<FuseHost>,
    /// Long-lived boot-time shell child id.
    shell_id: String,
    /// All shells active in this session: the boot shell + any returned
    /// from `spawn_shell`. `close_shell` removes from the set.
    shells: HashSet<String>,
    /// Tokio runtime that drove `vm.start()`, the VSOCK connect, and the
    /// FuseHost. **must** outlive the VM, otherwise the underlying
    /// Objective-C completion handlers and dispatch queues are released
    /// and the VSOCK fd dies.
    runtime: Arc<Runtime>,
    /// Names of shares declared at boot time (cannot be removed at runtime).
    boot_share_names: HashSet<String>,
    /// All FUSE-backed mounts currently registered (boot + runtime).
    fuse_mount_names: HashSet<String>,
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
        // host directories are now exposed directly through the FuseHost.
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
            fuse_listener,
            runtime,
        } = boot_vm(&vm_config)?;

        let init = Arc::new(VsockInitClient::new(vsock)?);

        // Hello handshake.
        if let Err(e) = init.hello() {
            let _ = init.shutdown();
            let _ = vm.request_stop();
            return Err(e);
        }

        // ---- FUSE host -----------------------------------------------
        // The FuseHost serves all dynamic mounts in this session over a
        // single vsock listener. Each `tokimo-sandbox-fuse` child in the
        // guest opens one connection per mount and binds to it via
        // `Hello.mount_name`.
        let fuse_host: Arc<FuseHost> = Arc::new(FuseHost::new());
        spawn_fuse_accept_loop(fuse_listener, fuse_host.clone(), runtime.clone());

        // ---- Network: always-on userspace netstack -------------------
        // FUSE no longer requires a `LocalService` (it talks vsock
        // directly to host CID 2), so the gateway only carries upstream
        // egress now: `AllowAll` splices anywhere, `Blocked` drops.
        let egress = match params.network {
            NetworkPolicy::AllowAll => crate::netstack::EgressPolicy::AllowAll,
            NetworkPolicy::Blocked => crate::netstack::EgressPolicy::Blocked,
        };
        let local_services: Vec<crate::netstack::LocalService> = Vec::new();

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

        // ---- Mount each boot-time share via FUSE ---------------------
        let mut boot_share_names = HashSet::new();
        let mut fuse_mount_names = HashSet::new();
        for share in &params.mounts {
            if share.create_host_dir
                && !share.host_path.exists()
                && let Err(e) = std::fs::create_dir_all(&share.host_path)
            {
                let _ = init.shutdown();
                let _ = vm.request_stop();
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
                let _ = vm.request_stop();
                return Err(e);
            }
            boot_share_names.insert(share.name.clone());
            fuse_mount_names.insert(share.name.clone());
        }

        // ---- Open long-lived shell --------------------------------------
        let shell_argv = vec!["/bin/sh".to_string()];
        let shell_info = match init.open_shell(&shell_argv, &[], None) {
            Ok(i) => i,
            Err(e) => {
                let _ = init.shutdown();
                let _ = vm.request_stop();
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
            fuse_host,
            shell_id,
            shells,
            runtime,
            boot_share_names,
            fuse_mount_names,
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
                    fuse_host,
                    netstack_shutdown,
                    ..
                } = *rs;
                netstack_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = init.shutdown();
                drop(init);
                drop(fuse_host); // tear down FuseHost; in-flight serve tasks see EOF
                // Apple's VZVirtualMachine.stop() asserts when invoked off
                // its dispatch queue. Use request_stop (fire-and-forget),
                // wait briefly, then let Drop tear down the rest.
                runtime.block_on(async {
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

        // 1. Register the FUSE backend.
        let backend = LocalDirVfs::arc(share.host_path.clone());
        let mount_id = rs
            .fuse_host
            .register_mount(share.name.clone(), backend, share.read_only);

        // 2. Ask the guest to spawn a tokimo-sandbox-fuse child for it.
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

    fn rename_user(&self, old: &str, new: &str) -> Result<()> {
        let init = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => rs.init.clone(),
                _ => return Err(Error::VmNotRunning),
            }
        };
        init.rename_user(old, new)
            .map_err(|e| Error::other(format!("rename_user: {e}")))
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

/// Spawn the FUSE accept loop on the runtime: each accepted connection
/// from a `tokimo-sandbox-fuse` child goes to `FuseHost::serve`. Runs
/// until the listener returns an error (typically VM shutdown).
fn spawn_fuse_accept_loop(
    mut listener: arcbox_vz::VirtioSocketListener,
    fuse_host: Arc<crate::vfs_host::FuseHost>,
    runtime: Arc<Runtime>,
) {
    runtime.spawn(async move {
        use std::os::fd::IntoRawFd;
        loop {
            match listener.accept().await {
                Ok(conn) => {
                    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
                    let raw = conn.into_raw_fd();
                    // Wrap in OwnedFd; tokio AsyncFd over a unix stream
                    // requires a non-blocking fd. Use tokio's UnixStream
                    // adapter from the std fd.
                    let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };
                    let fd = owned.as_raw_fd();
                    // Set non-blocking.
                    unsafe {
                        let flags = libc::fcntl(fd, libc::F_GETFL);
                        if flags >= 0 {
                            let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                        }
                    }
                    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(owned.into_raw_fd()) };
                    match tokio::net::UnixStream::from_std(std_stream) {
                        Ok(stream) => {
                            let host = fuse_host.clone();
                            tokio::spawn(async move {
                                if let Err(e) = host.serve(stream).await {
                                    tracing::warn!("fuse_host serve: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("fuse listener: from_std: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("fuse listener accept failed: {e}");
                    break;
                }
            }
        }
    });
}
