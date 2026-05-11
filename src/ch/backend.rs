//! `ChBackend` — Cloud Hypervisor implementation of [`SandboxBackend`].
//!
//! V3.0-spawn: VM lifecycle (create / start / stop / is_running).
//! V3.0-vsock: guest-agent RPC over hybrid vsock — ping + spawn_command.
//!             Implements `shell_id`, `spawn_shell`, `subscribe`, `is_guest_connected`.
//!             `write_stdin` is a TODO (one-shot model; interactive stdin needs v3.x).

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;
use tracing::warn;

use crate::api::{ConfigureParams, Event, JobId, Mount, SessionDetails, SessionSummary, ShellOpts};
use crate::backend::SandboxBackend;
use crate::ch::rpc::{GuestRpc, Response};
use crate::ch::vmm::{
    ChVm, ChVmConfig, NetworkConfig, PortForward, PortProto, ch_initrd_path, ch_vmlinux_path, next_cid, passt_path,
};
use crate::ch_probe::ChProbeResult;
use crate::error::{Error, Result};

/// vsock port the guest-agent listens on (matches TOKIMO_GUEST_VSOCK_PORT default).
const GUEST_AGENT_PORT: u32 = 1024;

/// Timeout for guest-agent to come up after VM spawn.
const GUEST_READY_TIMEOUT: Duration = Duration::from_secs(30);
const GUEST_PING_INTERVAL: Duration = Duration::from_millis(200);

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

    /// Event subscribers registered via `subscribe()`.
    ///
    /// Each `SyncSender` is a bounded channel; dead receivers are pruned on
    /// each publish. Shared with spawned tokio tasks via `Arc`.
    subscribers: Arc<Mutex<Vec<std::sync::mpsc::SyncSender<Event>>>>,
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
            subscribers: Arc::new(Mutex::new(Vec::new())),
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
        let (memory_mb, cpu_count, port_forward_specs, shared_dir) = {
            let guard = self.config.lock().unwrap();
            let cfg = guard.as_ref().ok_or(Error::NotConfigured)?;
            (
                cfg.memory_mb,
                cfg.cpu_count,
                cfg.port_forwards.clone(),
                cfg.mounts
                    .iter()
                    .find(|mount| mount.name == "agent-data")
                    .or_else(|| cfg.mounts.iter().find(|mount| !mount.read_only))
                    .map(|mount| mount.host_path.clone()),
            )
        };

        {
            let guard = self.vm.lock().unwrap();
            if guard.is_some() {
                return Err(Error::VmAlreadyRunning);
            }
        }

        let cid = next_cid();

        // Build network config if port forwards are configured.
        let network = if port_forward_specs.is_empty() {
            None
        } else {
            match passt_path() {
                Ok(passt_binary) => {
                    let forwards: Vec<PortForward> = port_forward_specs
                        .into_iter()
                        .filter_map(|pf| {
                            let proto = match pf.proto.to_lowercase().as_str() {
                                "tcp" => PortProto::Tcp,
                                "udp" => PortProto::Udp,
                                other => {
                                    tracing::warn!(proto = other, "skipping port forward with unknown proto");
                                    return None;
                                }
                            };
                            Some(PortForward {
                                proto,
                                host_port: pf.host_port,
                                guest_port: pf.guest_port,
                                host_addr: None,
                            })
                        })
                        .collect();
                    if forwards.is_empty() {
                        None
                    } else {
                        Some(NetworkConfig {
                            passt_binary,
                            mac_addr: None,
                            port_forwards: forwards,
                        })
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "passt_path() failed; skipping port forward network config");
                    None
                }
            }
        };

        let vm_config = ChVmConfig {
            cid,
            ch_binary: self.ch_binary.clone(),
            kernel: ch_vmlinux_path()?,
            initrd: ch_initrd_path()?,
            memory_mb: memory_mb.max(256),
            cpu_count: cpu_count.max(1),
            shared_dir,
            network,
        };

        let vm = self.runtime.block_on(ChVm::spawn(vm_config))?;
        let vsock_socket = vm.vsock_socket.clone();
        *self.vm.lock().unwrap() = Some(vm);

        // Poll guest-agent ping until it responds or 30 s elapses.
        self.runtime.block_on(async move {
            let rpc = GuestRpc::new(vsock_socket, GUEST_AGENT_PORT);
            let start = std::time::Instant::now();
            loop {
                match rpc.ping().await {
                    Ok(()) => {
                        tracing::info!("guest-agent responded to ping — VM ready");
                        return Ok(());
                    }
                    Err(e) => {
                        if start.elapsed() >= GUEST_READY_TIMEOUT {
                            return Err(Error::other(format!(
                                "guest-agent did not respond within {:.0}s: {e}",
                                GUEST_READY_TIMEOUT.as_secs_f32()
                            )));
                        }
                        tokio::time::sleep(GUEST_PING_INTERVAL).await;
                    }
                }
            }
        })
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
        let vsock_socket = {
            let guard = self.vm.lock().unwrap();
            guard.as_ref().map(|vm| vm.vsock_socket.clone())
        };
        let Some(sock) = vsock_socket else {
            return Ok(false);
        };
        let rpc = GuestRpc::new(sock, GUEST_AGENT_PORT);
        Ok(self.runtime.block_on(rpc.ping()).is_ok())
    }

    fn is_process_running(&self, _id: &JobId) -> Result<bool> {
        // TODO(v3x-interactive-shell): track running jobs by JobId.
        Err(Error::not_implemented("is_process_running — track jobs by id (v3.x)"))
    }

    // -- Shell management -----------------------------------------------------

    fn shell_id(&self) -> Result<JobId> {
        // The guest-agent uses a one-shot-per-connection model; there is no
        // persistent "boot shell" session. Return a fixed sentinel ID so
        // callers that just need *a* shell JobId can proceed. Actual command
        // execution goes through spawn_shell().
        // TODO(v3x-interactive-shell): implement a persistent PTY shell channel.
        if self.vm.lock().unwrap().is_none() {
            return Err(Error::VmNotRunning);
        }
        Ok(JobId("boot".into()))
    }

    fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId> {
        let vsock_socket = {
            let guard = self.vm.lock().unwrap();
            guard
                .as_ref()
                .map(|vm| vm.vsock_socket.clone())
                .ok_or(Error::VmNotRunning)?
        };

        let ShellOpts { pty: _, argv, env, cwd } = opts;
        let argv = argv.unwrap_or_else(|| vec!["/bin/sh".into()]);
        let shell_id = JobId(uuid::Uuid::new_v4().to_string());
        let id = shell_id.clone();
        let subs = Arc::clone(&self.subscribers);

        self.runtime.spawn(async move {
            let rpc = GuestRpc::new(vsock_socket, GUEST_AGENT_PORT);
            let frames = match rpc.spawn_command_with_options(&argv, &env, cwd.as_deref()).await {
                Ok(f) => f,
                Err(e) => {
                    publish_event(
                        &subs,
                        Event::Error {
                            id: Some(id.clone()),
                            message: e.to_string(),
                            fatal: false,
                        },
                    );
                    return;
                }
            };
            for frame in frames {
                let ev = match frame {
                    Response::Stdout { data } => Event::Stdout {
                        id: id.clone(),
                        data: data.into_bytes(),
                    },
                    Response::Stderr { data } => Event::Stderr {
                        id: id.clone(),
                        data: data.into_bytes(),
                    },
                    Response::Exit { code } => Event::Exit {
                        id: id.clone(),
                        exit_code: code,
                        signal: None,
                    },
                    Response::Error { msg } => Event::Error {
                        id: Some(id.clone()),
                        message: msg,
                        fatal: false,
                    },
                    Response::Pong | Response::MountStatus { .. } => continue,
                };
                publish_event(&subs, ev);
            }
        });

        Ok(shell_id)
    }

    fn resize_shell(&self, _id: &JobId, _rows: u16, _cols: u16) -> Result<()> {
        // TODO(v3x-interactive-shell): resize_pty RPC when PTY shells are supported.
        Err(Error::not_implemented("resize_shell (v3.x PTY channel)"))
    }

    fn close_shell(&self, _id: &JobId) -> Result<()> {
        // TODO(v3x-interactive-shell): close_shell RPC.
        Err(Error::not_implemented("close_shell (v3.x PTY channel)"))
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        // TODO(v3x-interactive-shell): shell registry.
        Err(Error::not_implemented("list_shells (v3.x shell registry)"))
    }

    fn write_stdin(&self, _id: &JobId, _data: &[u8]) -> Result<()> {
        // The guest-agent one-shot model does not support interactive stdin.
        // TODO(v3x-interactive-shell): route data over a persistent PTY channel.
        Err(Error::not_implemented(
            "write_stdin — interactive stdin not supported in one-shot model (v3.x)",
        ))
    }

    fn signal_shell(&self, _id: &JobId, _sig: i32) -> Result<()> {
        // TODO(v3x-interactive-shell): signal RPC.
        Err(Error::not_implemented("signal_shell (v3.x)"))
    }

    // -- Event subscription ---------------------------------------------------

    fn subscribe(&self) -> Result<Receiver<Event>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        self.subscribers.lock().unwrap().push(tx);
        Ok(rx)
    }

    // -- Disk / debug ---------------------------------------------------------

    fn create_disk_image(&self, _path: &Path, _gib: u64) -> Result<()> {
        Err(Error::not_implemented("create_disk_image (v3.x)"))
    }

    fn set_debug_logging(&self, _enabled: bool) -> Result<()> {
        Err(Error::not_implemented("set_debug_logging (v3.x)"))
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        Err(Error::not_implemented("is_debug_logging_enabled (v3.x)"))
    }

    fn send_guest_response(&self, _raw: serde_json::Value) -> Result<()> {
        Err(Error::not_implemented("send_guest_response (v3.x)"))
    }

    fn passthrough(&self, _method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
        Err(Error::not_implemented("passthrough (v3.x)"))
    }

    fn add_mount(&self, _mount: Mount) -> Result<()> {
        // TODO(v3x-mounts): CH hotplug virtio-fs.
        Err(Error::not_implemented("add_mount (v3.x)"))
    }

    fn remove_mount(&self, _name: &str) -> Result<()> {
        // TODO(v3x-mounts): CH hotplug virtio-fs remove.
        Err(Error::not_implemented("remove_mount (v3.x)"))
    }

    fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        // TODO(v3x-sessions): session registry.
        Err(Error::not_implemented("list_sessions (v3.x)"))
    }

    fn session_info(&self, _name: &str) -> Result<Option<SessionDetails>> {
        // TODO(v3x-sessions): session lookup.
        Err(Error::not_implemented("session_info (v3.x)"))
    }

    fn stop_session(&self, _name: &str) -> Result<()> {
        // TODO(v3x-sessions): stop session.
        Err(Error::not_implemented("stop_session (v3.x)"))
    }

    // -- Host-Exec bridge -----------------------------------------------------
    // Default impls from the trait return Error::other("not implemented").
    // TODO(v3x-host-exec): override with vsock relay.
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Publish `ev` to all live subscribers, pruning disconnected ones.
fn publish_event(subs: &Arc<Mutex<Vec<std::sync::mpsc::SyncSender<Event>>>>, ev: Event) {
    let mut guard = subs.lock().unwrap();
    guard.retain(|tx| match tx.try_send(ev.clone()) {
        Ok(()) => true,
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            warn!("subscriber channel full — dropping event");
            true
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
    });
}
