//! `ChBackend` — Cloud Hypervisor implementation of [`SandboxBackend`].
//!
//! Implements the VM lifecycle methods (`configure`, `create_vm`, `start_vm`,
//! `stop_vm`, `is_running`). All vsock IO / RPC methods retain their
//! `unimplemented!` stubs marked `TODO(v30-vsock)`.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;

use crate::api::{ConfigureParams, Event, JobId, Mount, SessionDetails, SessionSummary, ShellOpts};
use crate::backend::SandboxBackend;
use crate::ch::vmm::{ChVm, ChVmConfig, ch_initrd_path, ch_vmlinux_path, next_cid};
use crate::ch_probe::ChProbeResult;
use crate::error::{Error, Result};

/// Cloud Hypervisor backend.
///
/// Construct via [`ChBackend::new`]; the caller is responsible for checking
/// [`ChProbeResult::is_ready`] before invoking any trait methods (the
/// constructor enforces this).
pub struct ChBackend {
    /// Absolute path to the `cloud-hypervisor` binary resolved at probe time.
    pub(crate) ch_binary: PathBuf,

    /// `/dev/vhost-vsock` presence confirmed at probe time.
    pub(crate) _vhost_vsock_available: bool,

    /// Tokio runtime for bridging async VM operations into sync trait methods.
    runtime: Arc<Runtime>,

    /// Configuration supplied via `configure()`.
    config: Mutex<Option<ConfigureParams>>,

    /// The live VM process handle (present between create_vm and stop_vm).
    vm: Mutex<Option<ChVm>>,
}

impl ChBackend {
    /// Construct a new `ChBackend` from a successful probe.
    ///
    /// Returns `Err` if `probe.is_ready()` is `false`.
    pub fn new(probe: ChProbeResult) -> Result<Self> {
        if !probe.is_ready() {
            return Err(Error::not_supported(format!(
                "Cloud Hypervisor backend is not ready on this host.\n{}",
                probe.report()
            )));
        }

        let ch_binary = probe.ch_binary.expect("is_ready() guarantees Some");

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| Error::other(format!("failed to build tokio runtime: {e}")))?;

        Ok(Self {
            ch_binary,
            _vhost_vsock_available: probe.vhost_vsock_dev,
            runtime: Arc::new(runtime),
            config: Mutex::new(None),
            vm: Mutex::new(None),
        })
    }
}

// ── SandboxBackend impl ──────────────────────────────────────────────────────

impl SandboxBackend for ChBackend {
    // -- Configuration --------------------------------------------------------

    fn configure(&self, params: ConfigureParams) -> Result<()> {
        let memory_mb = params.memory_mb;
        let cpu_count = params.cpu_count;
        if memory_mb > 0 && memory_mb < 256 {
            return Err(Error::validation("memory_mb must be at least 256 for cloud-hypervisor"));
        }
        if cpu_count > 256 {
            return Err(Error::validation("cpu_count must be ≤ 256"));
        }
        *self.config.lock().unwrap() = Some(params);
        Ok(())
    }

    // -- VM lifecycle ---------------------------------------------------------

    fn create_vm(&self) -> Result<()> {
        let (memory_mb, cpu_count) = {
            let guard = self.config.lock().unwrap();
            let cfg = guard.as_ref().ok_or(Error::NotConfigured)?;
            (cfg.memory_mb, cfg.cpu_count)
        };

        {
            let guard = self.vm.lock().unwrap();
            if guard.is_some() {
                return Err(Error::VmAlreadyRunning);
            }
        }

        let cid = next_cid();
        let vm_config = ChVmConfig {
            cid,
            ch_binary: self.ch_binary.clone(),
            kernel: ch_vmlinux_path()?,
            initrd: ch_initrd_path()?,
            memory_mb: memory_mb.max(256),
            cpu_count: cpu_count.max(1),
        };

        let vm = self.runtime.block_on(ChVm::spawn(vm_config))?;
        *self.vm.lock().unwrap() = Some(vm);
        Ok(())
    }

    fn start_vm(&self) -> Result<()> {
        // cloud-hypervisor boots the VM as part of process startup.
        // By the time create_vm() returns, the hypervisor is already running
        // (API socket appeared). This method is a no-op for ChBackend.
        let guard = self.vm.lock().unwrap();
        if guard.is_none() {
            return Err(Error::VmNotRunning);
        }
        Ok(())
    }

    fn stop_vm(&self) -> Result<()> {
        let vm = self.vm.lock().unwrap().take();
        if let Some(mut vm) = vm {
            self.runtime.block_on(vm.shutdown(Duration::from_secs(2)))?;
        }
        Ok(())
    }

    // -- State queries --------------------------------------------------------

    fn is_running(&self) -> Result<bool> {
        let mut guard = self.vm.lock().unwrap();
        Ok(guard.as_mut().map(|vm| vm.is_alive()).unwrap_or(false))
    }

    fn is_guest_connected(&self) -> Result<bool> {
        // TODO(v30-vsock): ping the guest-agent over the vsock control socket.
        unimplemented!("V3.0-vsock: is_guest_connected() — ping guest-agent over vsock")
    }

    fn is_process_running(&self, _id: &JobId) -> Result<bool> {
        // TODO(v30-vsock): send {"method":"proc_status","id": <id>} RPC.
        unimplemented!("V3.0-vsock: is_process_running() — query proc status via RPC")
    }

    // -- Shell management -----------------------------------------------------

    fn shell_id(&self) -> Result<JobId> {
        // TODO(v30-vsock): return the boot shell JobId from control state.
        unimplemented!("V3.0-vsock: shell_id() — return boot-shell JobId from control state")
    }

    fn spawn_shell(&self, _opts: ShellOpts) -> Result<JobId> {
        // TODO(v30-vsock): send open_shell RPC to guest-agent.
        unimplemented!("V3.0-vsock: spawn_shell() — open_shell RPC to guest-agent")
    }

    fn resize_shell(&self, _id: &JobId, _rows: u16, _cols: u16) -> Result<()> {
        // TODO(v30-vsock): send resize_pty RPC to guest-agent.
        unimplemented!("V3.0-vsock: resize_shell() — resize_pty RPC to guest-agent")
    }

    fn close_shell(&self, _id: &JobId) -> Result<()> {
        // TODO(v30-vsock): send close_shell RPC to guest-agent.
        unimplemented!("V3.0-vsock: close_shell() — close_shell RPC to guest-agent")
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        // TODO(v30-vsock): return shell registry snapshot from control state.
        unimplemented!("V3.0-vsock: list_shells() — snapshot shell registry")
    }

    fn write_stdin(&self, _id: &JobId, _data: &[u8]) -> Result<()> {
        // TODO(v30-vsock): write framed stdin bytes over vsock data channel.
        unimplemented!("V3.0-vsock: write_stdin() — framed stdin write to vsock data channel")
    }

    fn signal_shell(&self, _id: &JobId, _sig: i32) -> Result<()> {
        // TODO(v30-vsock): send signal RPC to guest-agent.
        unimplemented!("V3.0-vsock: signal_shell() — signal RPC to guest-agent")
    }

    // -- Event subscription ---------------------------------------------------

    fn subscribe(&self) -> Result<Receiver<Event>> {
        // TODO(v30-vsock): register mpsc Sender in event fan-out.
        unimplemented!("V3.0-vsock: subscribe() — register mpsc Sender in event fan-out")
    }

    // -- Disk / debug ---------------------------------------------------------

    fn create_disk_image(&self, _path: &Path, _gib: u64) -> Result<()> {
        // TODO(v30-spawn): fallocate + optional mkfs.
        unimplemented!("V3.0-spawn: create_disk_image() — fallocate + optional mkfs")
    }

    fn set_debug_logging(&self, _enabled: bool) -> Result<()> {
        // TODO(v30-spawn): toggle CH log verbosity.
        unimplemented!("V3.0-spawn: set_debug_logging() — toggle CH log verbosity")
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        // TODO(v30-spawn): return debug logging flag.
        unimplemented!("V3.0-spawn: is_debug_logging_enabled() — return debug log flag")
    }

    fn send_guest_response(&self, _raw: serde_json::Value) -> Result<()> {
        // TODO(v30-vsock): send JSON reply over vsock.
        unimplemented!("V3.0-vsock: send_guest_response() — send JSON reply over vsock")
    }

    fn passthrough(&self, _method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
        // TODO(v30-vsock): forward arbitrary RPC to CH REST API socket.
        unimplemented!("V3.0-vsock: passthrough() — forward RPC to CH REST API socket")
    }

    // -- Dynamic mounts -------------------------------------------------------

    fn add_mount(&self, _mount: Mount) -> Result<()> {
        // TODO(v30-spawn): CH hotplug virtio-fs add-device.
        unimplemented!("V3.0-spawn: add_mount() — CH hotplug virtio-fs add-device")
    }

    fn remove_mount(&self, _name: &str) -> Result<()> {
        // TODO(v30-spawn): CH hotplug virtio-fs remove-device.
        unimplemented!("V3.0-spawn: remove_mount() — CH hotplug virtio-fs remove-device")
    }

    // -- Session management ---------------------------------------------------

    fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        // TODO(v30-vsock): query session registry in control state.
        unimplemented!("V3.0-vsock: list_sessions() — query session registry")
    }

    fn session_info(&self, _name: &str) -> Result<Option<SessionDetails>> {
        // TODO(v30-vsock): look up session by name in control state registry.
        unimplemented!("V3.0-vsock: session_info() — lookup session in control registry")
    }

    fn stop_session(&self, _name: &str) -> Result<()> {
        // TODO(v30-vsock): close all shells for session.
        unimplemented!("V3.0-vsock: stop_session() — close all shells for session")
    }

    // -- Host-Exec bridge -----------------------------------------------------
    // Default impls from the trait return Error::other("not implemented").
    // TODO(v30-vsock): override with vsock relay.
}
