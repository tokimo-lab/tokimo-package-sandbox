//! `ChBackend` — Cloud Hypervisor implementation of [`SandboxBackend`].
//!
//! All trait methods are currently `unimplemented!` stubs. Each stub carries
//! a `TODO(v30-<step>)` marker so downstream agents can grep for their work:
//!
//! | marker          | step that fills it in       |
//! |-----------------|-----------------------------|
//! | `v30-spawn`     | spawn + VM lifecycle        |
//! | `v30-vsock`     | vsock RPC plumbing          |
//! | `v30-test`      | end-to-end round-trip test  |

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

use crate::api::{ConfigureParams, Event, JobId, Mount, SessionDetails, SessionSummary, ShellOpts};
use crate::backend::SandboxBackend;
use crate::ch_probe::ChProbeResult;
use crate::error::{Error, Result};

/// Cloud Hypervisor backend.
///
/// Construct via [`ChBackend::new`]; the caller is responsible for checking
/// [`ChProbeResult::is_ready`] before invoking any trait methods (the
/// constructor enforces this).
// Fields are unused until v30-spawn / v30-vsock sub-agents fill the stubs.
#[allow(dead_code)]
pub struct ChBackend {
    /// Absolute path to the `cloud-hypervisor` binary resolved at probe time.
    ///
    /// TODO(v30-spawn): pass to `vmm::ChVmmState::spawn()`.
    pub(crate) ch_binary: PathBuf,

    /// `/dev/kvm` file-descriptor handle placeholder.
    ///
    /// TODO(v30-spawn): open O_RDWR at construction and store the real
    /// `OwnedFd` here. The current `()` is a zero-cost stand-in that
    /// compiles without a `nix` dep at this stage.
    pub(crate) _kvm_fd_placeholder: (),

    /// `/dev/vhost-vsock` presence confirmed at probe time.
    ///
    /// TODO(v30-vsock): open `/dev/vhost-vsock` for the VSOCK_CID ioctl.
    pub(crate) _vhost_vsock_available: bool,
}

impl ChBackend {
    /// Construct a new `ChBackend` from a successful probe.
    ///
    /// Returns `Err` if `probe.is_ready()` is `false` — meaning one of the
    /// three minimum requirements (KVM, vsock device, binary) is missing.
    /// Upper layers (e.g. `platform::default_backend`) decide whether to fall
    /// back or propagate the error.
    pub fn new(probe: ChProbeResult) -> Result<Self> {
        if !probe.is_ready() {
            return Err(Error::not_supported(format!(
                "Cloud Hypervisor backend is not ready on this host.\n{}",
                probe.report()
            )));
        }

        // SAFETY: is_ready() guarantees ch_binary is Some.
        let ch_binary = probe.ch_binary.expect("is_ready() guarantees Some");

        Ok(Self {
            ch_binary,
            _kvm_fd_placeholder: (),
            _vhost_vsock_available: probe.vhost_vsock_dev,
        })
    }
}

// ── SandboxBackend impl ──────────────────────────────────────────────────────

impl SandboxBackend for ChBackend {
    // -- Configuration --------------------------------------------------------

    fn configure(&self, _params: ConfigureParams) -> Result<()> {
        // TODO(v30-spawn): store ConfigureParams (memory_mb, cpu_count,
        // base_rootfs, vm_dir) into a Mutex<Option<ConfigureParams>> field;
        // validate that memory_mb ≥ 256 and cpu_count ≥ 1.
        unimplemented!("V3.0-spawn: configure() — store params for VM spawn")
    }

    // -- VM lifecycle ---------------------------------------------------------

    fn create_vm(&self) -> Result<()> {
        // TODO(v30-spawn): build the CH JSON config (memory, cpus, kernel,
        // initrd, virtio-fs tags) and call vmm::create_vm().
        unimplemented!("V3.0-spawn: create_vm() — build CH JSON config via vmm module")
    }

    fn start_vm(&self) -> Result<()> {
        // TODO(v30-spawn): invoke vmm::start_vm(); wait for vsock handshake
        // via control::await_guest_ready() with a 30 s timeout.
        unimplemented!("V3.0-spawn: start_vm() — spawn CH process, await vsock handshake")
    }

    fn stop_vm(&self) -> Result<()> {
        // TODO(v30-spawn): send SIGTERM to CH child process; wait up to 5 s;
        // SIGKILL on timeout; clean up temp socket path.
        unimplemented!("V3.0-spawn: stop_vm() — terminate CH child process")
    }

    // -- State queries --------------------------------------------------------

    fn is_running(&self) -> Result<bool> {
        // TODO(v30-spawn): check if the CH child process is still alive
        // (try_wait() on the Child handle stored in vmm state).
        unimplemented!("V3.0-spawn: is_running() — check CH child process liveness")
    }

    fn is_guest_connected(&self) -> Result<bool> {
        // TODO(v30-vsock): ping the guest-agent over the vsock control socket.
        unimplemented!("V3.0-vsock: is_guest_connected() — ping guest-agent over vsock")
    }

    fn is_process_running(&self, _id: &JobId) -> Result<bool> {
        // TODO(v30-vsock): send {"method":"proc_status","id": <id>} RPC and
        // inspect the "running" field of the response.
        unimplemented!("V3.0-vsock: is_process_running() — query proc status via RPC")
    }

    // -- Shell management -----------------------------------------------------

    fn shell_id(&self) -> Result<JobId> {
        // TODO(v30-vsock): return the boot shell JobId negotiated during
        // start_vm() handshake (stored in control state).
        unimplemented!("V3.0-vsock: shell_id() — return boot-shell JobId from control state")
    }

    fn spawn_shell(&self, _opts: ShellOpts) -> Result<JobId> {
        // TODO(v30-vsock): send {"method":"open_shell","opts":{…}} RPC;
        // return the JobId from the response.
        unimplemented!("V3.0-vsock: spawn_shell() — open_shell RPC to guest-agent")
    }

    fn resize_shell(&self, _id: &JobId, _rows: u16, _cols: u16) -> Result<()> {
        // TODO(v30-vsock): send {"method":"resize_pty","id":…,"rows":…,"cols":…} RPC.
        unimplemented!("V3.0-vsock: resize_shell() — resize_pty RPC to guest-agent")
    }

    fn close_shell(&self, _id: &JobId) -> Result<()> {
        // TODO(v30-vsock): send {"method":"close_shell","id":…} RPC; remove
        // from shell registry in control state.
        unimplemented!("V3.0-vsock: close_shell() — close_shell RPC to guest-agent")
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        // TODO(v30-vsock): return shell registry snapshot from control state.
        unimplemented!("V3.0-vsock: list_shells() — snapshot shell registry")
    }

    fn write_stdin(&self, _id: &JobId, _data: &[u8]) -> Result<()> {
        // TODO(v30-vsock): write framed stdin bytes over the data channel
        // associated with _id in the vsock multiplexer.
        unimplemented!("V3.0-vsock: write_stdin() — framed stdin write to vsock data channel")
    }

    fn signal_shell(&self, _id: &JobId, _sig: i32) -> Result<()> {
        // TODO(v30-vsock): send {"method":"signal","id":…,"sig":…} RPC.
        unimplemented!("V3.0-vsock: signal_shell() — signal RPC to guest-agent")
    }

    // -- Event subscription ---------------------------------------------------

    fn subscribe(&self) -> Result<Receiver<Event>> {
        // TODO(v30-vsock): create an mpsc channel; register the Sender in
        // control state so the vsock reader loop can fan-out Events.
        // Return the Receiver to the caller.
        unimplemented!("V3.0-vsock: subscribe() — register mpsc Sender in event fan-out")
    }

    // -- Disk / debug ---------------------------------------------------------

    fn create_disk_image(&self, _path: &Path, _gib: u64) -> Result<()> {
        // TODO(v30-spawn): create a raw sparse file of _gib GiB using
        // fallocate / ftruncate; format as ext4 with mkfs.ext4 if requested.
        unimplemented!("V3.0-spawn: create_disk_image() — fallocate + optional mkfs")
    }

    fn set_debug_logging(&self, _enabled: bool) -> Result<()> {
        // TODO(v30-spawn): toggle CH's --log-file / --v flag or send a
        // CH API request to adjust log verbosity at runtime.
        unimplemented!("V3.0-spawn: set_debug_logging() — toggle CH log verbosity")
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        // TODO(v30-spawn): return the current debug logging flag value.
        unimplemented!("V3.0-spawn: is_debug_logging_enabled() — return debug log flag")
    }

    fn send_guest_response(&self, _raw: serde_json::Value) -> Result<()> {
        // TODO(v30-vsock): serialize _raw and send over the host-exec reply
        // channel on the vsock control socket.
        unimplemented!("V3.0-vsock: send_guest_response() — send JSON reply over vsock")
    }

    fn passthrough(&self, _method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
        // TODO(v30-vsock): forward arbitrary JSON-RPC call to the CH REST API
        // (http+unix:// via the CH API socket) and return the response body.
        unimplemented!("V3.0-vsock: passthrough() — forward RPC to CH REST API socket")
    }

    // -- Dynamic mounts -------------------------------------------------------

    fn add_mount(&self, _mount: Mount) -> Result<()> {
        // TODO(v30-spawn): use CH hotplug API (PUT /api/v1/vm/add-device) to
        // attach a new virtio-fs tag at runtime; update vmm state.
        unimplemented!("V3.0-spawn: add_mount() — CH hotplug virtio-fs add-device")
    }

    fn remove_mount(&self, _name: &str) -> Result<()> {
        // TODO(v30-spawn): use CH hotplug API (PUT /api/v1/vm/remove-device)
        // to detach the virtio-fs tag; update vmm state.
        unimplemented!("V3.0-spawn: remove_mount() — CH hotplug virtio-fs remove-device")
    }

    // -- Session management ---------------------------------------------------

    fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        // TODO(v30-vsock): query session registry in control state;
        // map to SessionSummary structs.
        unimplemented!("V3.0-vsock: list_sessions() — query session registry")
    }

    fn session_info(&self, _name: &str) -> Result<Option<SessionDetails>> {
        // TODO(v30-vsock): look up session by name in control state registry.
        unimplemented!("V3.0-vsock: session_info() — lookup session in control registry")
    }

    fn stop_session(&self, _name: &str) -> Result<()> {
        // TODO(v30-vsock): send close_shell for all shells in the session,
        // then remove from control state registry.
        unimplemented!("V3.0-vsock: stop_session() — close all shells for session")
    }

    // -- Host-Exec bridge -----------------------------------------------------
    // These default to Error::other() via the trait default impl. Override
    // once the vsock host-exec relay is implemented.
    //
    // TODO(v30-vsock): override add_host_command / remove_host_command /
    // set_host_commands / list_host_commands / on_host_exec with vsock relay.
}
