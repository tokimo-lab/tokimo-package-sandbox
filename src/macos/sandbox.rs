//! macOS backend implementing `SandboxBackend` via `arcbox-vz` + the
//! VSOCK init protocol.
//!
//! Lifecycle:
//!  * `configure` stores params (allowed Empty → Configured, Configured →
//!     Configured, Stopped → Configured).
//!  * `start_vm` boots the VM (one virtiofs share per pre-declared
//!     Mount, plus a per-session "dynamic share" pool used for runtime
//!     `add_mount`), runs the init Hello handshake, asks the guest to
//!     mount each share, and opens the long-lived shell.
//!  * `stop_vm` shuts down the VM and tears down the per-session host dir.
//!  * `add_mount` / `remove_mount` materialise dynamic shares
//!     by APFS-cloning into the dynamic-share pool and bind-mounting on the
//!     guest (Apple's VZ does not support virtio-fs hot-plug).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use arcbox_vz::VirtualMachine;
use tokio::runtime::Runtime;

use crate::api::{AddUserOpts, ConfigureParams, Event, JobId, Mount, ShellOpts};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

use super::vm::{BootedVm, DYN_SHARE_GUEST_PATH, DYN_SHARE_TAG, VmConfig, boot_vm};
use super::vsock_init_client::VsockInitClient;

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
    /// Long-lived boot-time shell child id.
    shell_id: String,
    /// All shells active in this session: the boot shell + any returned
    /// from `spawn_shell`. `close_shell` removes from the set.
    shells: HashSet<String>,
    /// Tokio runtime that drove `vm.start()` and the VSOCK connect; **must**
    /// outlive the VM, otherwise the underlying Objective-C completion
    /// handlers and dispatch queues are released and the VSOCK fd dies.
    runtime: Arc<Runtime>,
    /// Per-session host directory that backs the dynamic-share pool.
    session_dir: PathBuf,
    /// Names of shares declared at boot time (cannot be removed at runtime).
    boot_share_names: HashSet<String>,
    /// Currently active runtime-added Plan9 shares (name → share).
    dyn_shares: HashMap<String, Mount>,
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

fn session_root() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".tokimo").join("sessions")
}

/// `cp -c -R src dst` (APFS clone), falling back to `cp -R` if cloning is
/// unsupported (e.g. cross-volume).
fn apfs_clone(src: &Path, dst: &Path) -> Result<()> {
    let cloned = Command::new("cp").arg("-c").arg("-R").arg(src).arg(dst).status();
    if matches!(&cloned, Ok(s) if s.success()) {
        return Ok(());
    }

    let status = Command::new("cp")
        .arg("-R")
        .arg(src)
        .arg(dst)
        .status()
        .map_err(|e| Error::other(format!("cp -R: {e}")))?;
    if !status.success() {
        return Err(Error::other(format!(
            "cp -R failed (status {status}) copying {} → {}",
            src.display(),
            dst.display()
        )));
    }
    Ok(())
}

/// Run a one-shot shell command in the guest and return an error if it
/// exits non-zero.
fn guest_sh(init: &VsockInitClient, script: &str) -> Result<()> {
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
    let (stdout, stderr, code) = init.run_oneshot(&argv, &[], None, Duration::from_secs(30))?;
    if code != 0 {
        return Err(Error::other(format!(
            "guest sh failed (exit {code}): {script}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        )));
    }
    Ok(())
}

/// Mount a virtiofs share inside the guest at `guest_path`. Init is
/// already chrooted to the rootfs share so we just call mount(8) directly.
fn guest_mount_virtiofs(init: &VsockInitClient, tag: &str, guest_path: &str, read_only: bool) -> Result<()> {
    let opts = if read_only { ",ro" } else { "" };
    let script = format!(
        "set -e; mkdir -p '{p}'; mount -t virtiofs -o defaults{opts} '{tag}' '{p}'",
        p = guest_path,
    );
    guest_sh(init, &script)
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

        // ---- Per-session host directory --------------------------------
        // session_dir must be unique per Sandbox handle even within the
        // same process: tests run multiple `Sandbox::connect()` instances
        // simultaneously with the same `user_data_name`, so we mix in the
        // caller-supplied `session_id` and a monotonic counter as a fallback.
        let sanitize = |s: &str| -> String {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(32)
                .collect()
        };
        let label = sanitize(&params.user_data_name);
        let sid = sanitize(&params.session_id);
        let counter = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session_id = if sid.is_empty() {
            format!("{label}-{}-{counter}", std::process::id())
        } else {
            format!("{label}-{sid}-{}-{counter}", std::process::id())
        };
        let session_dir = session_root().join(&session_id);
        let dyn_root = session_dir.join("dyn-root");
        std::fs::create_dir_all(&dyn_root)
            .map_err(|e| Error::other(format!("create session dir {}: {e}", dyn_root.display())))?;

        // ---- Boot VM ---------------------------------------------------
        let vm_config = VmConfig {
            memory_mb: params.memory_mb,
            cpu_count: params.cpu_count,
            mounts: params.mounts.clone(),
            network: params.network,
            dyn_root: dyn_root.clone(),
        };

        let BootedVm {
            vm,
            vsock,
            netstack_listener,
            runtime,
        } = match boot_vm(&vm_config) {
            Ok(b) => b,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&session_dir);
                return Err(e);
            }
        };

        let init = Arc::new(VsockInitClient::new(vsock)?);

        // Hello handshake.
        if let Err(e) = init.hello() {
            let _ = init.shutdown();
            let _ = runtime.block_on(vm.stop());
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(e);
        }

        // ---- Network: userspace netstack (AllowAll) ---------------------
        // The guest's `tokimo-tun-pump` (started by init.sh) connects to
        // our vsock listener. We hand the connection to `netstack::spawn`
        // which runs smoltcp on the host side. NetworkPolicy::Blocked has
        // no listener and no NIC at all.
        let _netstack_shutdown: Option<Arc<std::sync::atomic::AtomicBool>> =
            if let Some(mut listener) = netstack_listener {
                let accept =
                    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(30), listener.accept()).await });
                match accept {
                    Ok(Ok(conn)) => {
                        // Take ownership of the raw fd, then duplicate for
                        // the writer half so netstack can hold separate
                        // Read/Write trait objects.
                        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
                        let read_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(conn.into_raw_fd()) };
                        let dup_raw = unsafe { libc::dup(read_fd.as_raw_fd()) };
                        if dup_raw < 0 {
                            tracing::warn!("netstack dup fd failed; skipping");
                            None
                        } else {
                            let write_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
                            let read_file = std::fs::File::from(read_fd);
                            let write_file = std::fs::File::from(write_fd);
                            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
                            let _ = crate::netstack::spawn(
                                Box::new(read_file),
                                Box::new(write_file),
                                Arc::clone(&shutdown),
                                crate::netstack::EgressPolicy::AllowAll,
                                Vec::new(),
                            );
                            Some(shutdown)
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("netstack accept error: {e}");
                        None
                    }
                    Err(_) => {
                        tracing::warn!("netstack accept timeout");
                        None
                    }
                }
            } else {
                None
            };

        // ---- Mount the dynamic-share pool -------------------------------
        if let Err(e) = guest_mount_virtiofs(&init, DYN_SHARE_TAG, DYN_SHARE_GUEST_PATH, false) {
            let _ = init.shutdown();
            let _ = runtime.block_on(vm.stop());
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(e);
        }

        // ---- Mount each boot-time Plan9 share ---------------------------
        let mut boot_share_names = HashSet::new();
        for share in &params.mounts {
            let guest = share.guest_path.to_string_lossy().into_owned();
            if let Err(e) = guest_mount_virtiofs(&init, &share.name, &guest, share.read_only) {
                let _ = init.shutdown();
                let _ = runtime.block_on(vm.stop());
                let _ = std::fs::remove_dir_all(&session_dir);
                return Err(e);
            }
            boot_share_names.insert(share.name.clone());
        }

        // ---- Open long-lived shell --------------------------------------
        let shell_argv = vec!["/bin/sh".to_string()];
        let shell_info = match init.open_shell(&shell_argv, &[], None) {
            Ok(i) => i,
            Err(e) => {
                let _ = init.shutdown();
                let _ = runtime.block_on(vm.stop());
                let _ = std::fs::remove_dir_all(&session_dir);
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
            shell_id,
            shells,
            runtime,
            session_dir,
            boot_share_names,
            dyn_shares: HashMap::new(),
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
                    session_dir,
                    ..
                } = *rs;
                let _ = init.shutdown();
                drop(init);
                // Apple's VZVirtualMachine.stop() asserts when invoked off
                // its dispatch queue (we're on the main test thread, not the
                // queue arcbox-vz built the VM on). Use request_stop (which
                // is fire-and-forget / dispatches internally), wait briefly,
                // and let Drop tear down the rest.
                let _ = runtime.block_on(async {
                    let _ = vm.request_stop();
                    tokio::time::sleep(Duration::from_millis(300)).await;
                });
                drop(vm);
                drop(runtime);
                let _ = std::fs::remove_dir_all(&session_dir);
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
        if rs.dyn_shares.contains_key(&share.name) {
            return Err(Error::validation(format!("share '{}' is already mounted", share.name)));
        }
        if share.name == "work" || share.name == DYN_SHARE_TAG || share.name.is_empty() || share.name.contains('/') {
            return Err(Error::validation(format!("invalid share name: '{}'", share.name)));
        }
        if !share.host_path.exists() {
            return Err(Error::validation(format!(
                "host_path does not exist: {}",
                share.host_path.display()
            )));
        }

        // 1. APFS-clone host_path into the dynamic-share pool.
        let host_dst = rs.session_dir.join("dyn-root").join(&share.name);
        if host_dst.exists() {
            std::fs::remove_dir_all(&host_dst).ok();
        }
        if let Some(parent) = host_dst.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::other(format!("create dyn-root: {e}")))?;
        }
        apfs_clone(&share.host_path, &host_dst)?;

        // 2. Bind-mount inside the guest.
        let guest = share.guest_path.to_string_lossy().into_owned();
        let ro_remount = if share.read_only {
            format!("; mount -o remount,bind,ro '{guest}'")
        } else {
            String::new()
        };
        let script = format!(
            "set -e; mkdir -p '{guest}'; mount --bind '{src}' '{guest}'{ro}",
            src = format!("{DYN_SHARE_GUEST_PATH}/{}", share.name),
            ro = ro_remount,
        );
        if let Err(e) = guest_sh(&rs.init, &script) {
            let _ = std::fs::remove_dir_all(&host_dst);
            return Err(e);
        }

        rs.dyn_shares.insert(share.name.clone(), share);
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
        let share = rs
            .dyn_shares
            .remove(name)
            .ok_or_else(|| Error::validation(format!("no such share '{name}'")))?;

        let guest = share.guest_path.to_string_lossy().into_owned();
        let script = format!("umount '{guest}' 2>/dev/null || true; rmdir '{guest}' 2>/dev/null || true");
        let _ = guest_sh(&rs.init, &script);

        let host_dst = rs.session_dir.join("dyn-root").join(&share.name);
        let _ = std::fs::remove_dir_all(&host_dst);
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
