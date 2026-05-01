//! macOS backend implementing `SandboxBackend` via `arcbox-vz` + the
//! VSOCK init protocol.
//!
//! Lifecycle:
//!  * `configure` stores params (allowed Empty → Configured, Configured →
//!     Configured, Stopped → Configured).
//!  * `start_vm` boots the VM (one virtiofs share per pre-declared
//!     Plan9Share, plus a per-session "dynamic share" pool used for runtime
//!     `add_plan9_share`), runs the init Hello handshake, asks the guest to
//!     mount each share, and opens the long-lived shell.
//!  * `stop_vm` shuts down the VM and tears down the per-session host dir.
//!  * `add_plan9_share` / `remove_plan9_share` materialise dynamic shares
//!     by APFS-cloning into the dynamic-share pool and bind-mounting on the
//!     guest (Apple's VZ does not support virtio-fs hot-plug).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use arcbox_vz::VirtualMachine;
use tokio::runtime::Runtime;

use crate::api::{ConfigureParams, Event, JobId, NetworkPolicy, Plan9Share};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

use super::vm::{BootedVm, DYN_SHARE_GUEST_PATH, DYN_SHARE_TAG, VmConfig, boot_vm};
use super::vsock_init_client::VsockInitClient;

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
    params: ConfigureParams,
    vm: VirtualMachine,
    init: Arc<VsockInitClient>,
    /// Long-lived shell child id (mirrors Windows backend).
    #[allow(dead_code)]
    shell_id: String,
    /// Tokio runtime that drove `vm.start()` and the VSOCK connect; **must**
    /// outlive the VM, otherwise the underlying Objective-C completion
    /// handlers and dispatch queues are released and the VSOCK fd dies.
    runtime: Arc<Runtime>,
    /// Per-session host directory that backs the dynamic-share pool.
    session_dir: PathBuf,
    /// Names of shares declared at boot time (cannot be removed at runtime).
    boot_share_names: HashSet<String>,
    /// Currently active runtime-added Plan9 shares (name → share).
    dyn_shares: HashMap<String, Plan9Share>,
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
        let session_id = format!(
            "{}-{}",
            params
                .user_data_name
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(32)
                .collect::<String>(),
            std::process::id()
        );
        let session_dir = session_root().join(&session_id);
        let dyn_root = session_dir.join("dyn-root");
        std::fs::create_dir_all(&dyn_root)
            .map_err(|e| Error::other(format!("create session dir {}: {e}", dyn_root.display())))?;

        // ---- Boot VM ---------------------------------------------------
        let vm_config = VmConfig {
            memory_mb: params.memory_mb,
            cpu_count: params.cpu_count,
            plan9_shares: params.plan9_shares.clone(),
            network: params.network,
            dyn_root: dyn_root.clone(),
        };

        let BootedVm { vm, vsock, runtime } = match boot_vm(&vm_config) {
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

        // Empty MountManifest — we do not use 9p-over-vsock on macOS.
        let _ = init.mount_manifest(&[]);

        // ---- Mount the dynamic-share pool -------------------------------
        if let Err(e) = guest_mount_virtiofs(&init, DYN_SHARE_TAG, DYN_SHARE_GUEST_PATH, false) {
            let _ = init.shutdown();
            let _ = runtime.block_on(vm.stop());
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(e);
        }

        // ---- Mount each boot-time Plan9 share ---------------------------
        let mut boot_share_names = HashSet::new();
        for share in &params.plan9_shares {
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

        self.emit_event(Event::Ready);
        self.emit_event(Event::GuestConnected { connected: true });

        // ---- Event pump thread ------------------------------------------
        let init_for_pump = init.clone();
        let event_senders = self.event_senders.clone();
        let shell_id_for_pump = shell_id.clone();
        thread::Builder::new()
            .name("tokimo-macos-event-pump".into())
            .spawn(move || event_pump_loop(init_for_pump, event_senders, shell_id_for_pump))
            .map_err(|e| Error::other(format!("spawn event pump thread: {e}")))?;

        *state = State::Running(Box::new(RunningState {
            params,
            vm,
            init,
            shell_id,
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

    fn signal_shell(&self, sig: i32) -> Result<()> {
        let (init, child_id) = {
            let state = self.state.lock().unwrap();
            match &*state {
                State::Running(rs) => (rs.init.clone(), rs.shell_id.clone()),
                _ => return Err(Error::VmNotRunning),
            }
        };
        init.signal(&child_id, sig, true)
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

    fn add_plan9_share(&self, share: Plan9Share) -> Result<()> {
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

    fn remove_plan9_share(&self, name: &str) -> Result<()> {
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
}

/// Event pump: drains stdout/stderr and exit notifications for **every**
/// child the guest tells us about. We don't pre-register children; the
/// reader thread populates the per-child entry the first time it sees an
/// event, so we just iterate over the keys present in the shared map.
fn event_pump_loop(init: Arc<VsockInitClient>, event_senders: Arc<Mutex<Vec<Sender<Event>>>>, _shell_id: String) {
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
