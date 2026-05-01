//! Linux backend implementation — `bwrap` + `tokimo-sandbox-init`.
//!
//! Lifecycle:
//!  1. `new()` — construct empty backend state.
//!  2. `configure(params)` — store ConfigureParams.
//!  3. `create_vm()` — no-op (Linux has no VM).
//!  4. `start_vm()` — spawn `bwrap` + init, mount workspace + Plan9Shares,
//!     connect InitClient, send Hello + OpenShell.
//!  5. `exec/spawn/write_stdin/kill` — forward to InitClient.
//!  6. `stop_vm()` — InitClient::shutdown, kill bwrap process.
//!
//! Network policy is a TODO (always allow-all for now).

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, bind, listen, socket};

use crate::api::{ConfigureParams, Event, ExecOpts, ExecResult, JobId, NetworkPolicy, Plan9Share};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};
use crate::linux::init_client::{InitClient, SpawnInfo};

/// Shared mutable state for the Linux backend.
struct BackendState {
    config: Option<ConfigureParams>,
    bwrap_child: Option<Child>,
    init_client: Option<Arc<InitClient>>,
    /// Shell child_id from OpenShell (kept alive as sentinel).
    shell_child_id: Option<String>,
    /// PID of the bwrap process.
    bwrap_pid: Option<u32>,
    /// SEQPACKET socket path used to connect to init (host side).
    ctrl_sock_path: Option<PathBuf>,
    /// Per-JobId spawn info.
    jobs: HashMap<String, JobSpawnInfo>,
    /// Event subscribers (each gets a clone of incoming events).
    subscribers: Vec<std::sync::mpsc::Sender<Event>>,
    /// Next job id sequence.
    next_job_id: u64,
    /// Debug logging flag.
    debug_logging: bool,
}

struct JobSpawnInfo {
    child_id: String,
    pty_fd: Option<OwnedFd>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            config: None,
            bwrap_child: None,
            init_client: None,
            shell_child_id: None,
            bwrap_pid: None,
            ctrl_sock_path: None,
            jobs: HashMap::new(),
            subscribers: Vec::new(),
            next_job_id: 0,
            debug_logging: false,
        }
    }
}

/// Linux backend for the Sandbox API.
pub struct LinuxBackend {
    state: Mutex<BackendState>,
    /// Flag set to true when start_vm completes successfully (handshake done).
    running: AtomicBool,
    /// Event pump thread handle (spawned by start_vm).
    _event_pump: Mutex<Option<thread::JoinHandle<()>>>,
}

impl LinuxBackend {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Mutex::new(BackendState::default()),
            running: AtomicBool::new(false),
            _event_pump: Mutex::new(None),
        })
    }

    fn ensure_configured(&self) -> Result<()> {
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        if g.config.is_none() {
            return Err(Error::NotConfigured);
        }
        Ok(())
    }

    fn ensure_running(&self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(Error::VmNotRunning);
        }
        Ok(())
    }

    /// Broadcast an event to all subscribers.
    fn broadcast_event(state: &mut BackendState, event: Event) {
        state.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

impl SandboxBackend for LinuxBackend {
    fn configure(&self, params: ConfigureParams) -> Result<()> {
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        if self.running.load(Ordering::Relaxed) {
            return Err(Error::VmAlreadyRunning);
        }
        g.config = Some(params);
        Ok(())
    }

    fn create_vm(&self) -> Result<()> {
        // No-op on Linux (no VM concept).
        self.ensure_configured()?;
        Ok(())
    }

    fn start_vm(&self) -> Result<()> {
        self.ensure_configured()?;

        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        if self.running.load(Ordering::Relaxed) {
            return Err(Error::VmAlreadyRunning);
        }

        let config = g
            .config
            .as_ref()
            .ok_or_else(|| Error::NotConfigured)?
            .clone();

        // 1. Create a SEQPACKET socket pair for the init control channel.
        let temp_dir = env::temp_dir().join(format!("tokimo-sb-{}", std::process::id()));
        fs::create_dir_all(&temp_dir).map_err(|e| {
            Error::other(format!("create temp dir {}: {}", temp_dir.display(), e))
        })?;
        let ctrl_sock_path = temp_dir.join("ctrl.sock");
        let ctrl_fd = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|e| Error::other(format!("socket(SEQPACKET): {e}")))?;
        let addr = UnixAddr::new(&ctrl_sock_path)
            .map_err(|e| Error::other(format!("UnixAddr {ctrl_sock_path:?}: {e}")))?;
        bind(ctrl_fd.as_raw_fd(), &addr)
            .map_err(|e| Error::other(format!("bind {ctrl_sock_path:?}: {e}")))?;
        listen(&ctrl_fd, nix::sys::socket::Backlog::new(1).unwrap())
            .map_err(|e| Error::other(format!("listen {ctrl_sock_path:?}: {e}")))?;

        // 2. Find the init binary (tokimo-sandbox-init).
        let init_path = find_init_binary()?;

        // 3. Build bwrap args:
        //    * Bind workspace + Plan9Shares
        //    * Pass ctrl socket via --ro-bind on the socket file (init will connect)
        //    * Spawn tokimo-sandbox-init with the socket path as arg.
        let mut args = vec![
            "--ro-bind".to_string(),
            "/usr".to_string(),
            "/usr".to_string(),
            "--ro-bind".to_string(),
            "/lib".to_string(),
            "/lib".to_string(),
            "--ro-bind".to_string(),
            "/bin".to_string(),
            "/bin".to_string(),
            "--ro-bind".to_string(),
            "/sbin".to_string(),
            "/sbin".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
            "--unshare-pid".to_string(),
            "--unshare-ipc".to_string(),
            "--unshare-uts".to_string(),
            "--die-with-parent".to_string(),
            "--as-pid-1".to_string(),
        ];

        // Check if /lib64 exists (some distros have it, some don't).
        if Path::new("/lib64").is_dir() {
            args.push("--ro-bind".to_string());
            args.push("/lib64".to_string());
            args.push("/lib64".to_string());
        }

        // Workspace is mounted at /work (if any share named "work" or default).
        // For Plan9Share bindings: bind at guest_path.
        for share in &config.plan9_shares {
            let flag = if share.read_only { "--ro-bind" } else { "--bind" };
            args.push(flag.to_string());
            args.push(share.host_path.display().to_string());
            args.push(share.guest_path.display().to_string());
        }

        // Bind the control socket path so init can see it.
        args.push("--ro-bind".to_string());
        args.push(ctrl_sock_path.display().to_string());
        args.push(ctrl_sock_path.display().to_string());

        // Network policy.
        //   * AllowAll → bwrap inherits the host network namespace
        //     (default: no `--unshare-net` flag) → guest sees host NICs.
        //   * Blocked  → not yet implemented on Linux. Returning an
        //     error rather than silently allowing traffic is safer.
        //
        // Real Blocked support requires either `--unshare-net` plus a
        // loopback-only setup, or iptables/nftables egress rules.
        match config.network {
            NetworkPolicy::AllowAll => {}
            NetworkPolicy::Blocked => {
                return Err(Error::other(
                    "NetworkPolicy::Blocked is not yet implemented on the Linux backend",
                ));
            }
        }

        args.push("--".to_string());
        args.push(init_path.display().to_string());
        args.push("--ctrl-sock".to_string());
        args.push(ctrl_sock_path.display().to_string());

        // 4. Spawn bwrap.
        let bwrap_path = find_bwrap()?;
        let child = Command::new(bwrap_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::other(format!("spawn bwrap: {e}")))?;

        let bwrap_pid = child.id();
        g.bwrap_child = Some(child);
        g.bwrap_pid = Some(bwrap_pid);
        g.ctrl_sock_path = Some(ctrl_sock_path.clone());

        drop(g);

        // 5. Wait for init to connect (with timeout).
        let deadline = Instant::now() + Duration::from_secs(10);
        let init_client = loop {
            if Instant::now() >= deadline {
                return Err(Error::other("timeout waiting for init to connect"));
            }
            match InitClient::connect(&ctrl_sock_path) {
                Ok(client) => break client,
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        };

        // 6. Send Hello.
        init_client
            .hello()
            .map_err(|e| Error::other(format!("init hello failed: {e}")))?;

        // 7. OpenShell (sentinel process to keep init alive).
        let shell_info = init_client
            .open_shell(&["/bin/bash"], &[], None)
            .map_err(|e| Error::other(format!("init open_shell failed: {e}")))?;

        let init_client = Arc::new(init_client);

        // 8. Update state first (before starting event pump).
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.init_client = Some(Arc::clone(&init_client));
        g.shell_child_id = Some(shell_info.child_id);
        drop(g);

        // 9. Start event pump thread.
        // Cannot directly pass `self` to thread, so we'll poll in a detached way.
        // The event pump will be stopped when stop_vm is called (init_client.is_dead()).
        // For now, we skip the event pump thread to avoid architecture issues.
        // The events will be polled on-demand during exec/spawn operations.
        //
        // TODO: implement proper event pump with shared state.
        let event_pump = thread::Builder::new()
            .name("tokimo-linux-event-pump-stub".into())
            .spawn(move || {
                // Stub event pump — just sleeps. Real implementation would
                // need access to the backend state to broadcast events.
                loop {
                    thread::sleep(Duration::from_secs(1));
                    if init_client.is_dead() {
                        break;
                    }
                }
            })
            .map_err(|e| Error::other(format!("spawn event pump thread: {e}")))?;

        *self._event_pump.lock().unwrap() = Some(event_pump);

        self.running.store(true, Ordering::Relaxed);

        // Emit Ready + GuestConnected events to subscribers.
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        Self::broadcast_event(&mut g, Event::Ready);
        Self::broadcast_event(&mut g, Event::GuestConnected { connected: true });

        Ok(())
    }

    fn stop_vm(&self) -> Result<()> {
        self.ensure_running()?;

        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;

        // 1. Shutdown init.
        if let Some(ref client) = g.init_client {
            let _ = client.shutdown();
        }

        // 2. Wait for bwrap to exit (or kill after timeout).
        if let Some(mut child) = g.bwrap_child.take() {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        drop(g);
                        thread::sleep(Duration::from_millis(100));
                        g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
                    }
                    Err(_) => break,
                }
            }
        }

        // 3. Clean up.
        g.init_client = None;
        g.shell_child_id = None;
        g.bwrap_pid = None;
        g.jobs.clear();

        // Clean up temp dir with socket.
        if let Some(ref path) = g.ctrl_sock_path {
            let temp_dir = path.parent();
            if let Some(dir) = temp_dir {
                let _ = fs::remove_dir_all(dir);
            }
        }
        g.ctrl_sock_path = None;

        drop(g);
        self.running.store(false, Ordering::Relaxed);

        Ok(())
    }

    fn is_running(&self) -> Result<bool> {
        Ok(self.running.load(Ordering::Relaxed))
    }

    fn is_guest_connected(&self) -> Result<bool> {
        // On Linux, "guest connected" == running (no separate guest connect phase).
        Ok(self.running.load(Ordering::Relaxed))
    }

    fn is_process_running(&self, id: &JobId) -> Result<bool> {
        self.ensure_running()?;
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g
            .init_client
            .as_ref()
            .ok_or_else(|| Error::VmNotRunning)?;
        let job = g.jobs.get(id.as_str()).ok_or_else(|| {
            Error::other(format!("unknown job: {}", id.as_str()))
        })?;

        // Check if exit status has been recorded.
        let has_exit = client.take_exit(&job.child_id).is_some();
        Ok(!has_exit && !client.is_dead())
    }

    fn exec(&self, argv: &[String], opts: ExecOpts) -> Result<ExecResult> {
        self.ensure_running()?;

        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g
            .init_client
            .as_ref()
            .ok_or_else(|| Error::VmNotRunning)?
            .clone();
        drop(g);

        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let cwd = opts.cwd.as_deref();
        let timeout = Duration::from_secs(300); // 5 min default timeout.

        let (stdout_bytes, stderr_bytes, exit_code) = client
            .run_oneshot(&argv_refs, &opts.env, cwd, timeout)
            .map_err(|e| Error::other(format!("exec failed: {e}")))?;

        Ok(ExecResult {
            stdout: stdout_bytes,
            stderr: stderr_bytes,
            exit_code,
            signal: None,
        })
    }

    fn spawn(&self, argv: &[String], opts: ExecOpts) -> Result<JobId> {
        self.ensure_running()?;

        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g
            .init_client
            .as_ref()
            .ok_or_else(|| Error::VmNotRunning)?
            .clone();

        let job_id_num = g.next_job_id;
        g.next_job_id += 1;
        let job_id_str = format!("j{}", job_id_num);
        let job_id = JobId(job_id_str.clone());

        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let cwd = opts.cwd.as_deref();

        let (spawn_info, pty_fd) = if opts.pty {
            let (info, fd) = client
                .spawn_pty(&argv_refs, &opts.env, cwd, opts.pty_rows, opts.pty_cols)
                .map_err(|e| Error::other(format!("spawn pty failed: {e}")))?;
            (info, Some(fd))
        } else {
            let info = client
                .spawn_pipes(&argv_refs, &opts.env, cwd)
                .map_err(|e| Error::other(format!("spawn pipes failed: {e}")))?;
            (info, None)
        };

        g.jobs.insert(
            job_id_str.clone(),
            JobSpawnInfo {
                child_id: spawn_info.child_id.clone(),
                pty_fd,
            },
        );

        // If initial stdin is provided, write it.
        if let Some(ref data) = opts.stdin {
            if !opts.pty {
                // For pipes mode only; PTY would require writing to pty_fd.
                client
                    .write(&spawn_info.child_id, data)
                    .map_err(|e| Error::other(format!("write stdin failed: {e}")))?;
            }
        }

        drop(g);

        Ok(job_id)
    }

    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        self.ensure_running()?;
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g
            .init_client
            .as_ref()
            .ok_or_else(|| Error::VmNotRunning)?;
        let job = g.jobs.get(id.as_str()).ok_or_else(|| {
            Error::other(format!("unknown job: {}", id.as_str()))
        })?;

        if job.pty_fd.is_some() {
            // PTY mode: write to the master fd directly.
            // TODO: implement PTY master writes.
            return Err(Error::not_implemented("write_stdin for PTY jobs"));
        }

        client
            .write(&job.child_id, data)
            .map_err(|e| Error::other(format!("write_stdin failed: {e}")))?;
        Ok(())
    }

    fn kill(&self, id: &JobId, signal: i32) -> Result<()> {
        self.ensure_running()?;
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g
            .init_client
            .as_ref()
            .ok_or_else(|| Error::VmNotRunning)?;
        let job = g.jobs.get(id.as_str()).ok_or_else(|| {
            Error::other(format!("unknown job: {}", id.as_str()))
        })?;

        client
            .signal(&job.child_id, signal, true)
            .map_err(|e| Error::other(format!("kill failed: {e}")))?;
        Ok(())
    }

    fn subscribe(&self) -> Result<std::sync::mpsc::Receiver<Event>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.subscribers.push(tx);
        Ok(rx)
    }

    fn create_disk_image(&self, _path: &Path, _gib: u64) -> Result<()> {
        Err(Error::not_supported("create_disk_image on Linux"))
    }

    fn set_debug_logging(&self, enabled: bool) -> Result<()> {
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.debug_logging = enabled;
        Ok(())
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        Ok(g.debug_logging)
    }

    fn send_guest_response(&self, _raw: serde_json::Value) -> Result<()> {
        Err(Error::not_implemented("send_guest_response"))
    }

    fn passthrough(&self, method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
        Err(Error::not_implemented(format!("passthrough: {}", method)))
    }

    fn add_plan9_share(&self, _share: Plan9Share) -> Result<()> {
        // bwrap finalizes the mount namespace at process start; runtime
        // mount additions would require entering the child's mount ns
        // (`setns(CLONE_NEWNS)`) and calling mount(2) from there.
        // TODO: implement via VM-mode backend (see plan/architecture-alignment.md).
        Err(Error::not_supported(
            "add_plan9_share on Linux bwrap backend (requires VM-mode)",
        ))
    }

    fn remove_plan9_share(&self, _name: &str) -> Result<()> {
        Err(Error::not_supported(
            "remove_plan9_share on Linux bwrap backend (requires VM-mode)",
        ))
    }
}

// Note: Event pump architecture is simplified for this port.
// The Windows backend has a full event pump because the service streams
// events proactively. On Linux, InitClient buffers events internally
// (stdout/stderr/exit) and we drain them on-demand during exec/spawn/subscribe
// operations. A proper implementation would spawn a background thread that
// continuously polls InitClient::wait_for_event for all active jobs and
// broadcasts to subscribers, but that requires more complex state management.
//
// For now, events are only delivered for `exec()` (synchronously collected)
// and `spawn()` jobs can be polled via `subscribe()` if needed. This is
// sufficient for the initial port.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_bwrap() -> Result<PathBuf> {
    // Try PATH lookup.
    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            let candidate = PathBuf::from(dir).join("bwrap");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // Common locations.
    for candidate in ["/usr/bin/bwrap", "/bin/bwrap"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Ok(p);
        }
    }

    Err(Error::other("bwrap not found in PATH or /usr/bin"))
}

fn find_init_binary() -> Result<PathBuf> {
    // 1. Check if tokimo-sandbox-init is in PATH.
    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            let candidate = PathBuf::from(dir).join("tokimo-sandbox-init");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 2. Check relative to current_exe (for dev builds).
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("tokimo-sandbox-init");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 3. Check /usr/bin or /usr/local/bin.
    for candidate in [
        "/usr/bin/tokimo-sandbox-init",
        "/usr/local/bin/tokimo-sandbox-init",
    ] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Ok(p);
        }
    }

    Err(Error::other(
        "tokimo-sandbox-init not found in PATH, next to exe, or /usr/bin",
    ))
}
