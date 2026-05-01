//! macOS backend implementing `SandboxBackend` via arcbox-vz + vsock init.

use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use arcbox_vz::VirtualMachine;

use crate::api::{ConfigureParams, Event, ExecOpts, ExecResult, JobId, NetworkPolicy, Plan9Share};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

use super::vm::{boot_vm, VmConfig};
use super::vsock_init_client::{SpawnInfo, VsockInitClient};

/// macOS backend: boots a Linux VM with `tokimo-sandbox-init`, communicates
/// over virtio-vsock.
pub struct MacosBackend {
    state: Mutex<State>,
    event_senders: Mutex<Vec<Sender<Event>>>,
    debug_logging: Mutex<bool>,
}

enum State {
    /// Just constructed, no config yet.
    Empty,
    /// Configured but VM not started.
    Configured { params: ConfigureParams },
    /// VM running, init handshake done.
    Running {
        params: ConfigureParams,
        vm: Arc<VirtualMachine>,
        init: Arc<VsockInitClient>,
        /// The long-lived shell child opened by start_vm (mirrors Windows backend).
        shell_id: String,
    },
    /// VM stopped or errored.
    Stopped,
}

impl MacosBackend {
    /// Construct an empty backend. Call `configure()` then `start_vm()` to boot.
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Mutex::new(State::Empty),
            event_senders: Mutex::new(Vec::new()),
            debug_logging: Mutex::new(false),
        })
    }

    fn emit_event(&self, event: Event) {
        let senders = self.event_senders.lock().unwrap();
        senders.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

impl SandboxBackend for MacosBackend {
    fn configure(&self, params: ConfigureParams) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            State::Empty => {
                *state = State::Configured { params };
                Ok(())
            }
            State::Configured { .. } => {
                *state = State::Configured { params };
                Ok(())
            }
            State::Running { .. } => Err(Error::VmAlreadyRunning),
            State::Stopped => Err(Error::other("backend is stopped, cannot reconfigure")),
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
            State::Running { .. } => return Err(Error::VmAlreadyRunning),
            State::Stopped => return Err(Error::other("backend is stopped")),
        };

        // NetworkPolicy plumbing on macOS:
        //   * AllowAll → arcbox-vz attaches a VZNATNetworkDeviceAttachment
        //     by default; the guest gets DHCP-assigned NAT egress for free.
        //     This is the natural "do nothing" path until per-policy NIC
        //     toggling lands in arcbox-vz.
        //   * Blocked  → would require asking arcbox-vz to omit the NIC.
        //     The current arcbox-vz API doesn't expose that toggle, so we
        //     surface a clear error rather than silently allowing traffic.
        match params.network {
            NetworkPolicy::AllowAll => {}
            NetworkPolicy::Blocked => {
                return Err(Error::other(
                    "NetworkPolicy::Blocked is not yet plumbed through to arcbox-vz on macOS",
                ));
            }
        }

        let vm_config = VmConfig {
            memory_mb: params.memory_mb,
            cpu_count: params.cpu_count,
            plan9_shares: params.plan9_shares.clone(),
            user_data_name: params.user_data_name.clone(),
        };

        let (vm, vsock_fd) = boot_vm(&vm_config)?;
        let init = Arc::new(VsockInitClient::new(vsock_fd)?);

        // Hello handshake.
        init.hello()?;

        // Send MountManifest (empty on macOS — no pre-allocated vsock mounts).
        init.mount_manifest(&[])?;

        // Open long-lived shell.
        let shell_argv = vec!["/bin/bash".to_string()];
        let shell_info = init.open_shell(&shell_argv, &[], None)?;
        let shell_id = shell_info.child_id.clone();

        // Emit Ready event.
        self.emit_event(Event::Ready);
        self.emit_event(Event::GuestConnected { connected: true });

        // Spawn event pump thread.
        let init_clone = init.clone();
        let event_senders = self.event_senders.clone();
        thread::Builder::new()
            .name("tokimo-macos-event-pump".into())
            .spawn(move || event_pump_loop(init_clone, event_senders))
            .map_err(|e| Error::other(format!("spawn event pump thread: {e}")))?;

        *state = State::Running {
            params,
            vm,
            init,
            shell_id,
        };

        Ok(())
    }

    fn stop_vm(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            State::Running { init, .. } => {
                let _ = init.shutdown();
                *state = State::Stopped;
                self.emit_event(Event::GuestConnected { connected: false });
                Ok(())
            }
            State::Empty | State::Configured { .. } => {
                Err(Error::VmNotRunning)
            }
            State::Stopped => Ok(()),
        }
    }

    fn is_running(&self) -> Result<bool> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running { init, .. } => Ok(!init.is_dead()),
            _ => Ok(false),
        }
    }

    fn is_guest_connected(&self) -> Result<bool> {
        self.is_running()
    }

    fn is_process_running(&self, id: &JobId) -> Result<bool> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::Running { init, .. } => {
                // Check if exit status is known.
                Ok(init.take_exit(id.as_str()).is_none())
            }
            _ => Err(Error::VmNotRunning),
        }
    }

    fn exec(&self, argv: &[String], opts: ExecOpts) -> Result<ExecResult> {
        let state = self.state.lock().unwrap();
        let init = match &*state {
            State::Running { init, .. } => init.clone(),
            _ => return Err(Error::VmNotRunning),
        };
        drop(state);

        // For now, ignore opts.pty (PTY mode not supported over VSOCK).
        if opts.pty {
            return Err(Error::not_implemented("PTY mode on macOS"));
        }

        let timeout = Duration::from_secs(300);
        let (stdout, stderr, code) =
            init.run_oneshot(argv, &opts.env, opts.cwd.as_deref(), timeout)?;

        Ok(ExecResult {
            stdout,
            stderr,
            exit_code: code,
            signal: None,
        })
    }

    fn spawn(&self, argv: &[String], opts: ExecOpts) -> Result<JobId> {
        let state = self.state.lock().unwrap();
        let init = match &*state {
            State::Running { init, .. } => init.clone(),
            _ => return Err(Error::VmNotRunning),
        };
        drop(state);

        if opts.pty {
            return Err(Error::not_implemented("PTY mode on macOS"));
        }

        let info = init.spawn_pipes(argv, &opts.env, opts.cwd.as_deref())?;

        // Send initial stdin if provided.
        if let Some(data) = opts.stdin {
            init.write(&info.child_id, &data)?;
        }

        Ok(JobId(info.child_id))
    }

    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        let state = self.state.lock().unwrap();
        let init = match &*state {
            State::Running { init, .. } => init.clone(),
            _ => return Err(Error::VmNotRunning),
        };
        drop(state);

        init.write(id.as_str(), data)
    }

    fn kill(&self, id: &JobId, signal: i32) -> Result<()> {
        let state = self.state.lock().unwrap();
        let init = match &*state {
            State::Running { init, .. } => init.clone(),
            _ => return Err(Error::VmNotRunning),
        };
        drop(state);

        init.signal(id.as_str(), signal, true)
    }

    fn subscribe(&self) -> Result<Receiver<Event>> {
        let (tx, rx) = channel();
        let mut senders = self.event_senders.lock().unwrap();
        senders.push(tx);
        Ok(rx)
    }

    fn create_disk_image(&self, _path: &std::path::Path, _gib: u64) -> Result<()> {
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

    fn add_plan9_share(&self, _share: Plan9Share) -> Result<()> {
        // TODO: macOS VZ backend lacks runtime virtio-fs hot-plug; would
        // require recreating the VZVirtualMachineConfiguration. The init
        // protocol path is wired up — see VsockInitClient::add_mount.
        Err(Error::not_implemented(
            "add_plan9_share on macOS (VZ runtime hot-plug TODO)",
        ))
    }

    fn remove_plan9_share(&self, _name: &str) -> Result<()> {
        Err(Error::not_implemented(
            "remove_plan9_share on macOS (VZ runtime hot-plug TODO)",
        ))
    }
}

/// Event pump loop: polls init client for stdout/stderr/exit events and
/// forwards them to all subscribers. Runs until init dies.
fn event_pump_loop(init: Arc<VsockInitClient>, event_senders: Arc<Mutex<Vec<Sender<Event>>>>) {
    use std::collections::HashMap;

    // Map of active children we're tracking.
    let mut children: HashMap<String, ()> = HashMap::new();

    loop {
        // Poll all known children for events.
        let child_ids: Vec<String> = children.keys().cloned().collect();
        for child_id in child_ids {
            // Drain stdout.
            for chunk in init.drain_stdout(&child_id) {
                let event = Event::Stdout {
                    id: JobId(child_id.clone()),
                    data: chunk,
                };
                let senders = event_senders.lock().unwrap();
                senders.retain(|tx| tx.send(event.clone()).is_ok());
            }

            // Drain stderr.
            for chunk in init.drain_stderr(&child_id) {
                let event = Event::Stderr {
                    id: JobId(child_id.clone()),
                    data: chunk,
                };
                let senders = event_senders.lock().unwrap();
                senders.retain(|tx| tx.send(event.clone()).is_ok());
            }

            // Check exit.
            if let Some((code, sig)) = init.take_exit(&child_id) {
                let event = Event::Exit {
                    id: JobId(child_id.clone()),
                    exit_code: code,
                    signal: sig,
                };
                let senders = event_senders.lock().unwrap();
                senders.retain(|tx| tx.send(event.clone()).is_ok());
                children.remove(&child_id);
            }
        }

        // If init is dead, break.
        if init.is_dead() {
            break;
        }

        // Sleep briefly before next poll.
        thread::sleep(Duration::from_millis(50));
    }

    // Emit final disconnected event.
    let event = Event::GuestConnected { connected: false };
    let senders = event_senders.lock().unwrap();
    for tx in senders.iter() {
        let _ = tx.send(event.clone());
    }
}
