//! Linux backend implementation — `bwrap` + `tokimo-sandbox-init`.
//!
//! Lifecycle:
//!  1. `new()` — construct empty backend state.
//!  2. `configure(params)` — store ConfigureParams.
//!  3. `create_vm()` — no-op (Linux has no VM).
//!  4. `start_vm()` — spawn `bwrap` + init, mount workspace + Mounts,
//!     connect InitClient, send Hello + OpenShell.
//!  5. `exec/spawn/write_stdin/kill` — forward to InitClient.
//!  6. `stop_vm()` — InitClient::shutdown, kill bwrap process.
//!
//! Network policy is a TODO (always allow-all for now).

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, thread};

use nix::sys::socket::{SockFlag, socketpair};

use crate::api::{ConfigureParams, Event, JobId, Mount, NetworkPolicy, ShellOpts};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};
use crate::linux::init_client::{DrainedEvent, InitClient};
use crate::vfs_host::FuseHost;
use crate::vfs_impls::LocalDirVfs;

/// Shared mutable state for the Linux backend.
struct BackendState {
    config: Option<ConfigureParams>,
    bwrap_child: Option<Child>,
    init_client: Option<Arc<InitClient>>,
    /// Shell child_id from OpenShell (kept alive as sentinel).
    shell_child_id: Option<String>,
    shell_job_id: Option<JobId>,
    /// PID of the bwrap process.
    bwrap_pid: Option<u32>,
    /// Per-JobId spawn info.
    jobs: HashMap<String, JobSpawnInfo>,
    /// Reverse map: init child_id → JobId, for the event pump.
    child_to_job: HashMap<String, JobId>,
    /// Host-side FUSE server for this session. One per Sandbox; serves
    /// all mount connections (boot-time + runtime).
    fuse_host: Option<Arc<FuseHost>>,
    /// Host-end socketpair fds kept alive for the session lifetime.
    /// Each mount gets its own socketpair; dropping the host end would
    /// tear down the FUSE connection.
    fuse_sockets: Vec<OwnedFd>,
    /// Names of FUSE-backed mounts declared at boot time (cannot be
    /// removed at runtime).
    boot_share_names: HashSet<String>,
    /// All FUSE-backed mounts currently registered (boot + runtime).
    fuse_mount_names: HashSet<String>,
    /// Event subscribers (each gets a clone of incoming events).
    subscribers: Vec<std::sync::mpsc::Sender<Event>>,
    /// Next job id sequence.
    next_job_id: u64,
    /// Debug logging flag.
    debug_logging: bool,
    /// Per-VM netstack shutdown flag (None when policy is Blocked, since
    /// no smoltcp thread is spawned). Setting to true makes the netstack
    /// reader/writer threads exit on their next loop iteration.
    netstack_shutdown: Option<Arc<AtomicBool>>,
    /// Unix-millisecond timestamp captured when `start_vm` flips
    /// `running` to `true`. `None` until first successful start.
    started_at_unix_ms: Option<u64>,
}

struct JobSpawnInfo {
    child_id: String,
    pty_fd: Option<OwnedFd>,
}

#[allow(clippy::derivable_impls)]
impl Default for BackendState {
    fn default() -> Self {
        Self {
            config: None,
            bwrap_child: None,
            init_client: None,
            shell_child_id: None,
            shell_job_id: None,
            bwrap_pid: None,
            jobs: HashMap::new(),
            child_to_job: HashMap::new(),
            fuse_host: None,
            fuse_sockets: Vec::new(),
            boot_share_names: HashSet::new(),
            fuse_mount_names: HashSet::new(),
            subscribers: Vec::new(),
            next_job_id: 0,
            debug_logging: false,
            netstack_shutdown: None,
            started_at_unix_ms: None,
        }
    }
}

/// Linux backend for the Sandbox API.
pub struct LinuxBackend {
    state: Mutex<BackendState>,
    /// Flag set to true when start_vm completes successfully (handshake done).
    running: AtomicBool,
    /// Signals the event pump to exit.
    pump_stop: Arc<AtomicBool>,
    /// Event pump thread handle (spawned by start_vm).
    event_pump: Mutex<Option<thread::JoinHandle<()>>>,
}

impl LinuxBackend {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Mutex::new(BackendState::default()),
            running: AtomicBool::new(false),
            pump_stop: Arc::new(AtomicBool::new(false)),
            event_pump: Mutex::new(None),
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

        let config = g.config.as_ref().ok_or(Error::NotConfigured)?.clone();

        // 1. socketpair(SEQPACKET) for the init control channel. The host
        //    side stays CLOEXEC; the child side has CLOEXEC cleared in
        //    pre_exec so it survives execve into bwrap → init.
        let (host_end, child_end) = socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(|e| Error::other(format!("socketpair(SEQPACKET): {e}")))?;
        let child_fd_raw = child_end.as_raw_fd();

        // 1b. Optional second socketpair (STREAM) for the userspace
        //     netstack. Always allocated regardless of policy: even
        //     under Blocked we still want the userspace stack so we can
        //     route LocalService entries (e.g. NFS) and have one uniform
        //     filter point. The guest end is handed to init via
        //     `--net-fd=N`; the host end is duplicated and fed to
        //     `netstack::spawn` with `EgressPolicy::Blocked` to drop
        //     upstream traffic.
        let (net_host_end, net_child_end): (Option<OwnedFd>, Option<OwnedFd>) = {
            let (h, c) = socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .map_err(|e| Error::other(format!("socketpair(STREAM,net): {e}")))?;
            (Some(h), Some(c))
        };
        let net_child_fd_raw = net_child_end.as_ref().map(|f| f.as_raw_fd());

        // 2. Find the init binary.
        let init_path = find_init_binary()?;
        let bwrap_path = find_bwrap()?;

        // 3. Build bwrap args.
        //
        // Binaries + libraries + user table come from the packaged rootfs
        // (vm/rootfs/) so all three platforms (Linux/macOS/Windows) see the
        // same tool versions inside the sandbox. Network/DNS/CA/runtime
        // config still come from the host: those are environmental, not
        // packaged content.
        let vm_dir = crate::vm_dir::find_vm_dir()?;
        let rootfs = vm_dir.join("rootfs");
        let rootfs_str = |sub: &str| -> String { rootfs.join(sub).to_string_lossy().into_owned() };
        for sub in ["usr", "bin", "sbin", "lib", "lib64"] {
            if !rootfs.join(sub).is_dir() {
                return Err(Error::other(format!(
                    "packaged rootfs is missing /{sub}: {}",
                    rootfs.join(sub).display()
                )));
            }
        }
        let mut args: Vec<String> = vec![
            "--ro-bind".to_string(),
            rootfs_str("usr"),
            "/usr".to_string(),
            "--ro-bind".to_string(),
            rootfs_str("bin"),
            "/bin".to_string(),
            "--ro-bind".to_string(),
            rootfs_str("sbin"),
            "/sbin".to_string(),
            "--ro-bind".to_string(),
            rootfs_str("lib"),
            "/lib".to_string(),
            "--ro-bind".to_string(),
            rootfs_str("lib64"),
            "/lib64".to_string(),
        ];
        // /sys handling depends on network policy:
        //   - AllowAll: bind-mount host's /sys so the guest sees the same
        //     NIC list as the host (the netns is shared).
        //   - Blocked:  provide an empty /sys mount point and let the init
        //     binary mount a fresh sysfs from inside the new netns. Sysfs
        //     in a fresh netns is filtered by the kernel to show only that
        //     netns's interfaces (lo). A bind-mount would leak the host
        //     view, so we cannot use it here.
        // The actual mount is appended below inside the network-policy
        // match block so the two modes stay symmetric.

        // /etc/alternatives — use rootfs version when present so symlinks
        // resolve against the packaged binary set. Falls back gracefully.
        if rootfs.join("etc/alternatives").is_dir() {
            args.extend([
                "--ro-bind".to_string(),
                rootfs_str("etc/alternatives"),
                "/etc/alternatives".to_string(),
            ]);
        }
        // /etc/passwd + /etc/group — always from rootfs so the sandbox
        // user table is independent of the host.
        for f in ["etc/passwd", "etc/group"] {
            if rootfs.join(f).is_file() {
                args.extend([
                    "--ro-bind".to_string(),
                    rootfs_str(f),
                    format!("/{f}"),
                ]);
            } else {
                return Err(Error::other(format!(
                    "packaged rootfs is missing /{f}: {}",
                    rootfs.join(f).display()
                )));
            }
        }
        // Network/DNS/CA/runtime config — still from the host (only if present).
        for p in [
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/ssl",
            "/etc/ca-certificates",
            "/etc/pki",
        ] {
            if Path::new(p).exists() {
                args.extend(["--ro-bind".to_string(), p.into(), p.into()]);
            }
        }
        // FUSE needs user_allow_other so any UID inside the sandbox can
        // access the mount (the guest shell may not run as root).
        let _fuse_conf_file = {
            let mut tmp =
                tempfile::NamedTempFile::new().map_err(|e| Error::other(format!("create fuse.conf tmpfile: {e}")))?;
            use std::io::Write;
            tmp.write_all(b"user_allow_other\n")
                .map_err(|e| Error::other(format!("write fuse.conf: {e}")))?;
            args.extend([
                "--ro-bind".to_string(),
                tmp.path().to_string_lossy().into_owned(),
                "/etc/fuse.conf".to_string(),
            ]);
            tmp
        };
        args.extend(
            [
                "--proc",
                "/proc",
                // NOTE: Avoid `--dev /dev` — bwrap's devtmpfs setup forces a
                // nested user_ns (uid_map "1000 0 1") in which init no longer
                // has CAP_SYS_ADMIN over outer-userns mounts. Stage /dev as
                // tmpfs + bind the standard device nodes individually.
                "--tmpfs",
                "/dev",
                "--dev-bind",
                "/dev/null",
                "/dev/null",
                "--dev-bind",
                "/dev/zero",
                "/dev/zero",
                "--dev-bind",
                "/dev/full",
                "/dev/full",
                "--dev-bind",
                "/dev/random",
                "/dev/random",
                "--dev-bind",
                "/dev/urandom",
                "/dev/urandom",
                "--dev-bind",
                "/dev/tty",
                "/dev/tty",
                // FUSE device — required for FUSE-over-socketpair mounts.
                // --dev-bind-try silently skips if the host doesn't have it.
                "--dev-bind-try",
                "/dev/fuse",
                "/dev/fuse",
                // fusermount3 needs /etc/mtab (→ /proc/self/mounts) and
                // /etc/passwd (for username lookup). /proc is mounted
                // below, so the symlink resolves correctly.
                "--symlink",
                "/proc/self/mounts",
                "/etc/mtab",
                "--symlink",
                "/proc/self/fd",
                "/dev/fd",
                "--symlink",
                "/proc/self/fd/0",
                "/dev/stdin",
                "--symlink",
                "/proc/self/fd/1",
                "/dev/stdout",
                "--symlink",
                "/proc/self/fd/2",
                "/dev/stderr",
                "--tmpfs",
                "/tmp",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--die-with-parent",
                // (Intentionally NOT using --as-pid-1: it creates a nested
                // user_ns where init no longer has CAP_SYS_ADMIN over the
                // mounts created by the outer bwrap user_ns. bwrap will sit
                // at PID 1 and init will be PID 2 inside the new pid_ns;
                // that's fine.)
                // Required for FUSE mounts: fusermount3's mount(2) syscall
                // needs CAP_SYS_ADMIN inside the user namespace.
                "--cap-add",
                "CAP_SYS_ADMIN",
                // CAP_NET_ADMIN: needed inside the new netns to bring up
                // `lo` (SIOCSIFFLAGS) and to open /dev/net/tun + TUNSETIFF
                // for the userspace netstack TAP. bwrap drops all caps by
                // default in unprivileged user_ns mode.
                "--cap-add",
                "CAP_NET_ADMIN",
                // CAP_NET_RAW: required for `ping`'s SOCK_RAW fallback
                // when the host's net.ipv4.ping_group_range disables
                // unprivileged ICMP (DGRAM). Smoltcp ingests the raw
                // ICMP frame via tk0 regardless, so this is purely a
                // guest-side capability concern.
                "--cap-add",
                "CAP_NET_RAW",
                // CAP_MKNOD: pump.rs falls back to mknod(/dev/net/tun)
                // inside the sandbox if the host node wasn't bind-mounted
                // (e.g. some hardened distros).
                "--cap-add",
                "CAP_MKNOD",
            ]
            .iter()
            .map(|s| s.to_string()),
        );

        // Boot-time mounts are now handled via FUSE-over-socketpair
        // (after the Hello handshake), not bwrap --bind. See the
        // post-handshake mount loop below.

        // Network policy.
        // Always: --unshare-net + a fresh sysfs + lo bringup so the
        // sandbox has zero default visibility into the host's network
        // stack. The userspace netstack (smoltcp) is layered on top in
        // every mode: the guest's tk0 TAP is bridged to the host's
        // smoltcp Interface through a STREAM socketpair. Egress is
        // gated by `EgressPolicy` inside the netstack rather than by
        // tearing down the bridge — this lets us route LocalService
        // entries (NFS, future helpers) under Blocked while still
        // dropping arbitrary upstream traffic. One unified L4
        // interception/audit point across all 3 backends.
        args.push("--unshare-net".to_string());
        args.extend(["--dir", "/sys"].iter().map(|s| s.to_string()));
        let mount_sysfs = true;
        let bringup_lo = true;
        let want_netstack = true;
        if want_netstack {
            // Make the TUN device node visible inside the sandbox. We
            // already mounted /dev as tmpfs above, so a bind-mount of
            // the host node into /dev/net/tun is the cleanest path.
            // bwrap will create parent dirs for `--dev-bind-try`.
            if Path::new("/dev/net/tun").exists() {
                args.extend(
                    ["--dev-bind-try", "/dev/net/tun", "/dev/net/tun"]
                        .iter()
                        .map(|s| s.to_string()),
                );
            } else {
                eprintln!(
                    "[linux/sandbox] WARN: /dev/net/tun not present on host; \
                     init will mknod inside the sandbox (CAP_MKNOD)"
                );
            }
        }

        args.push("--".to_string());
        args.push(init_path.display().to_string());
        // Init subcommand + flags. The control fd is inherited from the
        // socketpair via pre_exec (CLOEXEC cleared); init is told its
        // numeric value via argv. See `tokimo-sandbox-init bwrap` parser.
        args.push("bwrap".to_string());
        args.push(format!("--control-fd={child_fd_raw}"));
        if let Some(fd) = net_child_fd_raw {
            args.push(format!("--net-fd={fd}"));
        }
        if bringup_lo {
            args.push("--bringup-lo".to_string());
        }
        if mount_sysfs {
            args.push("--mount-sysfs".to_string());
        }

        // Make the init binary visible inside the container at the exact
        // same path we just substituted into argv. bwrap re-execs into
        // the container's mount namespace before running the init, so
        // the path must resolve there.
        let init_dir = init_path.parent().unwrap_or(Path::new("/"));
        // Insert this BEFORE the `--` separator. We tracked the tail
        // length (init_path + bwrap subcommand + flags) so we can splice
        // in --ro-bind without disturbing it.
        let tail_len = 1 /* init_path */ + 1 /* "bwrap" */ + 1 /* --control-fd */
            + net_child_fd_raw.is_some() as usize
            + bringup_lo as usize + mount_sysfs as usize;
        // The `--` separator sits before the tail; insert --ro-bind in
        // front of it.
        let insert_at = args.len() - tail_len - 1;
        args.insert(insert_at, "--ro-bind".to_string());
        args.insert(insert_at + 1, init_dir.display().to_string());
        args.insert(insert_at + 2, init_dir.display().to_string());

        // 4. Spawn bwrap. In pre_exec, clear CLOEXEC on the child end(s)
        //    so bwrap → init inherits them.
        let mut cmd = Command::new(bwrap_path);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let net_child_fd_for_pre_exec = net_child_fd_raw;
        unsafe {
            cmd.pre_exec(move || {
                let r = libc::fcntl(child_fd_raw, libc::F_SETFD, 0);
                if r == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(fd) = net_child_fd_for_pre_exec {
                    let r = libc::fcntl(fd, libc::F_SETFD, 0);
                    if r == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| Error::other(format!("spawn bwrap: {e}")))?;

        // 5. Drop our copy of the child ends. host_end is the active
        //    control fd; net_host_end (if any) feeds the netstack thread.
        drop(child_end);
        drop(net_child_end);

        let bwrap_pid = child.id();
        g.bwrap_child = Some(child);
        g.bwrap_pid = Some(bwrap_pid);
        drop(g);

        // 5b. Userspace netstack — always spawn (see comment above
        //     where net_host_end is allocated). Egress policy is
        //     enforced inside the smoltcp gateway, not by skipping the
        //     bridge.
        let netstack_shutdown = if let Some(host_fd) = net_host_end {
            let read_fd: OwnedFd = host_fd;
            let dup_raw = unsafe { libc::dup(read_fd.as_raw_fd()) };
            if dup_raw < 0 {
                return Err(Error::other(format!(
                    "netstack dup fd: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let write_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
            let read_file = std::fs::File::from(read_fd);
            let write_file = std::fs::File::from(write_fd);
            let shutdown = Arc::new(AtomicBool::new(false));
            let policy = match config.network {
                NetworkPolicy::AllowAll => crate::netstack::EgressPolicy::AllowAll,
                NetworkPolicy::Blocked => crate::netstack::EgressPolicy::Blocked,
            };
            let _ = crate::netstack::spawn(
                Box::new(read_file),
                Box::new(write_file),
                Arc::clone(&shutdown),
                policy,
                Vec::new(),
            );
            Some(shutdown)
        } else {
            None
        };

        // 6. Wrap host_end as InitClient and handshake.
        // bwrap mode: init runs as PID 2 (bwrap is PID 1) — we
        // intentionally avoid `--as-pid-1` because the nested user_ns
        // it creates strips CAP_SYS_ADMIN over our outer mounts.
        // `from_fd` defaults to expect_pid1=false (correct for bwrap).
        let init_client =
            InitClient::from_fd(host_end).map_err(|e| Error::other(format!("InitClient::from_fd: {e}")))?;
        init_client
            .hello()
            .map_err(|e| Error::other(format!("init hello failed: {e}")))?;

        // 6b. FUSE host — register backends and send MountFuse for each
        //     boot-time share. Each mount gets its own socketpair:
        //     host end → FuseHost::serve (in background thread),
        //     guest end → init → fuse child (via SCM_RIGHTS).
        let fuse_host: Arc<FuseHost> = Arc::new(FuseHost::new());
        let mut fuse_threads: Vec<thread::JoinHandle<()>> = Vec::new();
        let mut boot_share_names = HashSet::new();
        let mut fuse_mount_names = HashSet::new();
        for share in &config.mounts {
            if share.create_host_dir
                && !share.host_path.exists()
                && let Err(e) = std::fs::create_dir_all(&share.host_path)
            {
                return Err(Error::other(format!(
                    "create_host_dir {}: {e}",
                    share.host_path.display()
                )));
            }
            let backend = LocalDirVfs::arc(share.host_path.clone());
            fuse_host.register_mount(share.name.clone(), backend, share.read_only);

            let (host_end, guest_end) = socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .map_err(|e| Error::other(format!("socketpair(STREAM,fuse): {e}")))?;

            // Serve the host end in a background thread. FuseHost::serve
            // is async; we bridge it via a blocking thread with a
            // single-threaded tokio runtime.
            let fh = fuse_host.clone();
            let sname = share.name.clone();
            // host_end moves into the thread — do NOT extract raw fd
            // here, or the OwnedFd drop in the main thread closes it.
            let t = thread::Builder::new()
                .name(format!("tokimo-fuse-{}", share.name))
                .spawn(move || {
                    // SAFETY: host_end is exclusively owned by this thread.
                    let host_fd_raw = host_end.as_raw_fd();
                    eprintln!("[linux/fuse] thread {sname}: host_fd={host_fd_raw}");
                    // Set non-blocking for tokio.
                    unsafe {
                        let flags = libc::fcntl(host_fd_raw, libc::F_GETFL);
                        if flags >= 0 {
                            let _ = libc::fcntl(host_fd_raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
                        }
                    }
                    // Convert OwnedFd → std UnixStream → tokio UnixStream.
                    // into_raw_fd() transfers ownership without closing.
                    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(host_end.into_raw_fd()) };
                    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        Ok(rt) => {
                            // Enter the runtime context so tokio I/O
                            // registration (needed by UnixStream::from_std)
                            // uses *this* runtime, not an outer one.
                            let _guard = rt.enter();
                            match tokio::net::UnixStream::from_std(std_stream) {
                                Ok(stream) => {
                                    drop(_guard);
                                    eprintln!("[linux/fuse] thread {sname}: entering serve loop");
                                    rt.block_on(async {
                                        if let Err(e) = fh.serve(stream).await {
                                            eprintln!("[linux/fuse] serve {sname}: {e}");
                                        }
                                        eprintln!("[linux/fuse] thread {sname}: serve loop exited");
                                    });
                                }
                                Err(e) => {
                                    eprintln!("[linux/fuse] from_std {sname}: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[linux/fuse] tokio runtime {sname}: {e}");
                        }
                    }
                })
                .map_err(|e| Error::other(format!("spawn fuse serve thread: {e}")))?;
            fuse_threads.push(t);

            // Send MountFuse to init with the guest-end fd via SCM_RIGHTS.
            let guest = share.guest_path.to_string_lossy().into_owned();
            let guest_fd_raw = guest_end.as_raw_fd();
            init_client
                .mount_fuse_with_fd(&share.name, guest_fd_raw, &guest, share.read_only)
                .map_err(|e| Error::other(format!("mount_fuse {}: {e}", share.name)))?;

            // Drop our copy of the guest end — init inherited it via
            // SCM_RIGHTS.
            drop(guest_end);
            boot_share_names.insert(share.name.clone());
            fuse_mount_names.insert(share.name.clone());
        }

        let shell_info = init_client
            .open_shell(&["/bin/bash"], &[], None)
            .map_err(|e| Error::other(format!("init open_shell failed: {e}")))?;

        let init_client = Arc::new(init_client);

        // 7. Update state.
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.init_client = Some(Arc::clone(&init_client));
        g.netstack_shutdown = netstack_shutdown;
        g.fuse_host = Some(fuse_host);
        g.boot_share_names = boot_share_names;
        g.fuse_mount_names = fuse_mount_names;
        g.shell_child_id = Some(shell_info.child_id.clone());
        let shell_job_id = JobId(format!("j{}", g.next_job_id));
        g.next_job_id += 1;
        g.jobs.insert(
            shell_job_id.0.clone(),
            JobSpawnInfo {
                child_id: shell_info.child_id.clone(),
                pty_fd: None,
            },
        );
        g.child_to_job.insert(shell_info.child_id.clone(), shell_job_id.clone());
        g.shell_job_id = Some(shell_job_id);
        drop(g);

        // 8. Start event pump.
        self.pump_stop.store(false, Ordering::Relaxed);
        let pump_stop = Arc::clone(&self.pump_stop);
        let pump_state: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let _ = pump_state;
        // We need to share `&self.state` with the pump; do so via an Arc
        // wrapper that points back at the `Mutex<BackendState>`. Since
        // `self` is borrowed for the lifetime of the LinuxBackend, we
        // hand the pump a raw pointer wrapped in a SyncSendPtr — this is
        // safe because `LinuxBackend` outlives the pump (we join in
        // stop_vm before dropping).
        let backend_state_ptr = SyncStatePtr(&self.state as *const Mutex<BackendState>);
        let pump_client = Arc::clone(&init_client);
        let pump = thread::Builder::new()
            .name("tokimo-linux-event-pump".into())
            .spawn(move || {
                event_pump_loop(pump_client, pump_stop, backend_state_ptr);
            })
            .map_err(|e| Error::other(format!("spawn event pump: {e}")))?;
        *self.event_pump.lock().unwrap() = Some(pump);

        self.running.store(true, Ordering::Relaxed);

        // Emit Ready + GuestConnected events to subscribers.
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.started_at_unix_ms = Some(now_unix_ms());
        Self::broadcast_event(&mut g, Event::Ready);
        Self::broadcast_event(&mut g, Event::GuestConnected { connected: true });

        Ok(())
    }

    fn stop_vm(&self) -> Result<()> {
        self.ensure_running()?;

        // 1. Signal pump to stop and shutdown init.
        self.pump_stop.store(true, Ordering::Relaxed);
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        // Stop the userspace netstack first so its threads exit before we
        // tear down the bwrap process (which closes the socketpair under
        // them and would otherwise produce a noisy EBADF on shutdown).
        if let Some(s) = g.netstack_shutdown.take() {
            s.store(true, Ordering::Relaxed);
        }
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
        g.shell_job_id = None;
        g.bwrap_pid = None;
        g.jobs.clear();
        g.child_to_job.clear();
        g.fuse_host = None;
        g.fuse_sockets.clear();
        g.boot_share_names.clear();
        g.fuse_mount_names.clear();

        drop(g);
        self.running.store(false, Ordering::Relaxed);

        // 4. Join the pump thread.
        if let Some(handle) = self.event_pump.lock().unwrap().take() {
            let _ = handle.join();
        }

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
        let client = g.init_client.as_ref().ok_or(Error::VmNotRunning)?;
        let job = g
            .jobs
            .get(id.as_str())
            .ok_or_else(|| Error::other(format!("unknown job: {}", id.as_str())))?;

        // Check if exit status has been recorded.
        let has_exit = client.take_exit(&job.child_id).is_some();
        Ok(!has_exit && !client.is_dead())
    }

    fn shell_id(&self) -> Result<JobId> {
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.shell_job_id.clone().ok_or(Error::VmNotRunning)
    }

    fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId> {
        self.ensure_running()?;
        // Build argv (own the strings so we can release the state lock
        // before issuing the init RPC).
        let argv: Vec<String> = opts.argv.clone().unwrap_or_else(|| vec!["/bin/bash".to_string()]);
        let env = opts.env.clone();
        let cwd = opts.cwd.clone();

        let client = {
            let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
            Arc::clone(g.init_client.as_ref().ok_or(Error::VmNotRunning)?)
        };

        match opts.pty {
            None => {
                // Pipes mode. Use OpenShell (the existing path) when argv is
                // exactly the default; otherwise use Spawn { Pipes }.
                let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                let shell_info = client
                    .open_shell(&argv_refs, &env, cwd.as_deref())
                    .map_err(|e| Error::other(format!("init open_shell failed: {e}")))?;
                let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
                let job_id = JobId(format!("j{}", g.next_job_id));
                g.next_job_id += 1;
                g.jobs.insert(
                    job_id.0.clone(),
                    JobSpawnInfo {
                        child_id: shell_info.child_id.clone(),
                        pty_fd: None,
                    },
                );
                g.child_to_job.insert(shell_info.child_id, job_id.clone());
                Ok(job_id)
            }
            Some((rows, cols)) => {
                let (info, master_fd) = client
                    .spawn_pty(&argv, &env, cwd.as_deref(), rows, cols)
                    .map_err(|e| Error::other(format!("init spawn_pty failed: {e}")))?;
                // Dup the master fd for the host-side reader thread; the
                // original lives in JobSpawnInfo so write_stdin can use it.
                let dup_raw = unsafe { libc::dup(master_fd.as_raw_fd()) };
                if dup_raw < 0 {
                    return Err(Error::other(format!(
                        "dup pty master fd: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                // SAFETY: dup_raw is a freshly allocated fd we own.
                let reader_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };

                let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
                let job_id = JobId(format!("j{}", g.next_job_id));
                g.next_job_id += 1;
                g.jobs.insert(
                    job_id.0.clone(),
                    JobSpawnInfo {
                        child_id: info.child_id.clone(),
                        pty_fd: Some(master_fd),
                    },
                );
                g.child_to_job.insert(info.child_id.clone(), job_id.clone());
                drop(g);

                // Spawn host-side reader thread.
                let pump_state = SyncStatePtr(&self.state as *const Mutex<BackendState>);
                let job_for_thread = job_id.clone();
                thread::Builder::new()
                    .name("tokimo-pty-reader".into())
                    .spawn(move || pty_reader_loop(reader_fd, job_for_thread, pump_state))
                    .map_err(|e| Error::other(format!("spawn pty reader: {e}")))?;

                Ok(job_id)
            }
        }
    }

    fn resize_shell(&self, id: &JobId, rows: u16, cols: u16) -> Result<()> {
        self.ensure_running()?;
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g.init_client.as_ref().ok_or(Error::VmNotRunning)?;
        let job = g
            .jobs
            .get(id.as_str())
            .ok_or_else(|| Error::other(format!("unknown job: {}", id.as_str())))?;
        if job.pty_fd.is_none() {
            return Err(Error::other(format!(
                "resize_shell: {} is not a PTY shell",
                id.as_str()
            )));
        }
        let child_id = job.child_id.clone();
        client
            .resize(&child_id, rows, cols)
            .map_err(|e| Error::other(format!("resize_shell: {e}")))
    }

    fn close_shell(&self, id: &JobId) -> Result<()> {
        self.ensure_running()?;
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = Arc::clone(g.init_client.as_ref().ok_or(Error::VmNotRunning)?);
        let job = g
            .jobs
            .get(id.as_str())
            .ok_or_else(|| Error::other(format!("unknown job: {}", id.as_str())))?;
        let child_id = job.child_id.clone();
        // Drop the master fd first (if PTY): closes the master, slave gets
        // EOF, the reader thread observes EOF and exits, and the child
        // exits naturally. We still send SIGTERM as a fallback.
        let mut removed = g.jobs.remove(id.as_str());
        if let Some(ref mut job) = removed {
            job.pty_fd.take();
        }
        // Send SIGTERM to the shell's process group.
        let _ = client.signal(&child_id, 15, true);
        g.child_to_job.remove(&child_id);
        if g.shell_job_id.as_ref() == Some(id) {
            g.shell_job_id = None;
            g.shell_child_id = None;
        }
        Ok(())
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        // All entries in `jobs` come from open_shell calls (boot + spawned).
        // Order is unspecified per trait contract.
        Ok(g.jobs.keys().cloned().map(JobId).collect())
    }

    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        self.ensure_running()?;
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g.init_client.as_ref().ok_or(Error::VmNotRunning)?;
        let job = g
            .jobs
            .get(id.as_str())
            .ok_or_else(|| Error::other(format!("unknown job: {}", id.as_str())))?;

        if let Some(ref pty_fd) = job.pty_fd {
            // PTY mode: write directly to the master fd in the host process.
            let bf = unsafe { BorrowedFd::borrow_raw(pty_fd.as_raw_fd()) };
            let mut written = 0usize;
            while written < data.len() {
                match nix::unistd::write(bf, &data[written..]) {
                    Ok(0) => return Err(Error::other("write_stdin: pty write returned 0")),
                    Ok(n) => written += n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => return Err(Error::other(format!("write_stdin pty: {e}"))),
                }
            }
            return Ok(());
        }

        client
            .write(&job.child_id, data)
            .map_err(|e| Error::other(format!("write_stdin failed: {e}")))?;
        Ok(())
    }

    fn signal_shell(&self, id: &JobId, sig: i32) -> Result<()> {
        self.ensure_running()?;
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let client = g.init_client.as_ref().ok_or(Error::VmNotRunning)?;
        let job = g
            .jobs
            .get(id.as_str())
            .ok_or_else(|| Error::other(format!("unknown job: {}", id.as_str())))?;
        client
            .signal(&job.child_id, sig, true)
            .map_err(|e| Error::other(format!("signal_shell: {e}")))
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

    fn add_mount(&self, share: Mount) -> Result<()> {
        self.ensure_running()?;

        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let rs_fuse_host = g.fuse_host.as_ref().ok_or(Error::VmNotRunning)?.clone();
        let client = g.init_client.as_ref().ok_or(Error::VmNotRunning)?.clone();

        if g.boot_share_names.contains(&share.name) {
            return Err(Error::validation(format!(
                "share name '{}' is reserved by a boot-time share",
                share.name
            )));
        }
        if g.fuse_mount_names.contains(&share.name) {
            return Err(Error::validation(format!("share '{}' is already mounted", share.name)));
        }
        if share.name == "work" || share.name.is_empty() || share.name.contains('/') {
            return Err(Error::validation(format!("invalid share name: '{}'", share.name)));
        }
        drop(g);

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
        let mount_id = rs_fuse_host.register_mount(share.name.clone(), backend, share.read_only);

        // 2. Create socketpair for this mount.
        let (host_end, guest_end) = socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(|e| Error::other(format!("socketpair(STREAM,fuse): {e}")))?;

        // 3. Serve the host end in a background thread.
        let fh = rs_fuse_host.clone();
        let sname = share.name.clone();
        // host_end moves into the thread — do NOT extract raw fd here.
        thread::Builder::new()
            .name(format!("tokimo-fuse-{}", share.name))
            .spawn(move || {
                let host_fd_raw = host_end.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(host_fd_raw, libc::F_GETFL);
                    if flags >= 0 {
                        let _ = libc::fcntl(host_fd_raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }
                }
                let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(host_end.into_raw_fd()) };
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => {
                        let _guard = rt.enter();
                        match tokio::net::UnixStream::from_std(std_stream) {
                            Ok(stream) => {
                                drop(_guard);
                                rt.block_on(async {
                                    if let Err(e) = fh.serve(stream).await {
                                        eprintln!("[linux/fuse] serve {sname}: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("[linux/fuse] from_std {sname}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[linux/fuse] tokio runtime {sname}: {e}");
                    }
                }
            })
            .map_err(|e| Error::other(format!("spawn fuse serve thread: {e}")))?;

        // 4. Send MountFuse to init with the guest-end fd via SCM_RIGHTS.
        let guest = share.guest_path.to_string_lossy().into_owned();
        let guest_fd_raw = guest_end.as_raw_fd();
        if let Err(e) = client.mount_fuse_with_fd(&share.name, guest_fd_raw, &guest, share.read_only) {
            // Roll back: remove the FUSE mount registration.
            let _ = rs_fuse_host.remove_mount(mount_id);
            drop(guest_end);
            return Err(e);
        }
        drop(guest_end);

        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        g.fuse_mount_names.insert(share.name);
        Ok(())
    }

    fn remove_mount(&self, name: &str) -> Result<()> {
        self.ensure_running()?;
        let mut g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        if g.boot_share_names.contains(name) {
            return Err(Error::validation(format!(
                "share '{name}' was declared at boot time and cannot be removed at runtime"
            )));
        }
        if !g.fuse_mount_names.remove(name) {
            return Err(Error::validation(format!("no such share '{name}'")));
        }
        let client = g.init_client.as_ref().ok_or(Error::VmNotRunning)?.clone();
        let fuse_host = g.fuse_host.as_ref().ok_or(Error::VmNotRunning)?.clone();
        drop(g);

        // Ask init to umount + reap the fuse child.
        let unmount_err = client.unmount_fuse(name).err();
        // Remove from host-side FuseHost.
        if let Some(mount_id) = fuse_host.mount_id_by_name(name) {
            let _ = fuse_host.remove_mount(mount_id);
        }
        if let Some(e) = unmount_err {
            return Err(e);
        }
        Ok(())
    }

    fn list_sessions(&self) -> Result<Vec<crate::SessionSummary>> {
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let Some(cfg) = g.config.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(vec![crate::SessionSummary {
            name: session_name_from_config(cfg),
            user_data_name: cfg.user_data_name.clone(),
            running: self.running.load(Ordering::Relaxed),
            guest_connected: g.init_client.is_some(),
            memory_mb: cfg.memory_mb,
            started_at_unix_ms: g.started_at_unix_ms,
        }])
    }

    fn session_info(&self, name: &str) -> Result<Option<crate::SessionDetails>> {
        let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
        let Some(cfg) = g.config.as_ref() else {
            return Ok(None);
        };
        if session_name_from_config(cfg) != name {
            return Ok(None);
        }
        Ok(Some(crate::SessionDetails {
            summary: crate::SessionSummary {
                name: session_name_from_config(cfg),
                user_data_name: cfg.user_data_name.clone(),
                running: self.running.load(Ordering::Relaxed),
                guest_connected: g.init_client.is_some(),
                memory_mb: cfg.memory_mb,
                started_at_unix_ms: g.started_at_unix_ms,
            },
            owner_pid: None,
            shell_count: g.jobs.len(),
            mount_count: g.fuse_mount_names.len(),
        }))
    }

    fn stop_session(&self, name: &str) -> Result<()> {
        let matches = {
            let g = self.state.lock().map_err(|_| Error::other("state poisoned"))?;
            g.config
                .as_ref()
                .map(|cfg| session_name_from_config(cfg) == name)
                .unwrap_or(false)
        };
        if !matches {
            return Ok(());
        }
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.stop_vm()
    }
}

/// Linux/macOS sandboxes are in-process and have no remote owner; we
/// derive a stable session name from the configured `user_data_name`,
/// falling back to the caller-supplied `session_id` if non-empty.
fn session_name_from_config(cfg: &ConfigureParams) -> String {
    if !cfg.session_id.is_empty() {
        cfg.session_id.clone()
    } else {
        cfg.user_data_name.clone()
    }
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

/// `*const Mutex<BackendState>` wrapped to be Send so the event pump can
/// hold it. Safety contract: the pointed-at LinuxBackend outlives the pump
/// thread (we join on stop_vm before dropping).
struct SyncStatePtr(*const Mutex<BackendState>);
unsafe impl Send for SyncStatePtr {}
unsafe impl Sync for SyncStatePtr {}

fn event_pump_loop(client: Arc<InitClient>, stop: Arc<AtomicBool>, state_ptr: SyncStatePtr) {
    loop {
        if stop.load(Ordering::Relaxed) || client.is_dead() {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(200);
        client.wait_any_event_or_eof(deadline);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // SAFETY: see SyncStatePtr.
        let state = unsafe { &*state_ptr.0 };
        let ids: std::collections::HashSet<String> = match state.lock() {
            Ok(g) => g.child_to_job.keys().cloned().collect(),
            Err(_) => return,
        };
        if ids.is_empty() {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let drained = client.drain_pending_events_for(&ids);
        if drained.is_empty() {
            // Either there's no data at all (timeout) or the pending data
            // belongs to a non-tracked transient child (e.g. an in-flight
            // `exec()`). Sleep briefly to avoid spinning.
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let mut g = match state.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        for ev in drained {
            match ev {
                DrainedEvent::Stdout { child_id, data } => {
                    if let Some(jid) = g.child_to_job.get(&child_id).cloned() {
                        LinuxBackend::broadcast_event(&mut g, Event::Stdout { id: jid, data });
                    }
                }
                DrainedEvent::Stderr { child_id, data } => {
                    if let Some(jid) = g.child_to_job.get(&child_id).cloned() {
                        LinuxBackend::broadcast_event(&mut g, Event::Stderr { id: jid, data });
                    }
                }
                DrainedEvent::Exit { child_id, code, signal } => {
                    if let Some(jid) = g.child_to_job.get(&child_id).cloned() {
                        LinuxBackend::broadcast_event(
                            &mut g,
                            Event::Exit {
                                id: jid,
                                exit_code: code,
                                signal,
                            },
                        );
                    }
                }
            }
        }
    }
}

/// Drain a PTY master fd and broadcast each chunk as `Event::Stdout` for
/// `job`. Spawned by `spawn_shell` when `opts.pty` is `Some`. Exits on
/// EOF / read error / job removal.
fn pty_reader_loop(reader_fd: OwnedFd, job: JobId, state_ptr: SyncStatePtr) {
    use std::io::Read;
    // SAFETY: reader_fd is a freshly dup'd OwnedFd; converting to File
    // takes ownership and closes it on drop.
    let mut file = std::fs::File::from(reader_fd);
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // SAFETY: see SyncStatePtr.
                let state = unsafe { &*state_ptr.0 };
                let mut g = match state.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                // Stop pumping once the job has been removed (close_shell).
                if !g.jobs.contains_key(job.as_str()) {
                    return;
                }
                LinuxBackend::broadcast_event(
                    &mut g,
                    Event::Stdout {
                        id: job.clone(),
                        data: buf[..n].to_vec(),
                    },
                );
            }
            Err(_) => break,
        }
    }
}

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
    if let Ok(exe) = env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let candidate = parent.join("tokimo-sandbox-init");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    // 3. Check /usr/bin or /usr/local/bin.
    for candidate in ["/usr/bin/tokimo-sandbox-init", "/usr/local/bin/tokimo-sandbox-init"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Ok(p);
        }
    }

    Err(Error::other(
        "tokimo-sandbox-init not found in PATH, next to exe, or /usr/bin",
    ))
}
