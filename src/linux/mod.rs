//! Linux sandbox: bubblewrap (preferred) or firejail (fallback).

pub(crate) mod bridge;
pub(crate) mod init_client;
pub(crate) mod l4;
pub(crate) mod seccomp;

use crate::config::{NetworkPolicy, SandboxConfig, SystemLayout};
use crate::host::common::{pipe_stdio, spawn_run, which};
use crate::host::net_observer::{self, ProxyConfig, ProxyHandle};
use crate::linux::l4::{L4Config, L4Handle};
use crate::linux::seccomp::generate_bpf_file;
use crate::{Error, ExecutionResult, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Sensitive home-relative paths that are tmpfs-hidden inside the sandbox.
const HIDE_HOME_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".config",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".bash_history",
    ".zsh_history",
    ".git-credentials",
];

/// Keep-alive holder for resources that must outlive the spawned child
/// (e.g., the seccomp BPF tempdir whose fd is dup'd into the child).
pub(crate) struct BwrapKeepAlive {
    _seccomp_tmp: Option<tempfile::TempDir>,
    _proxy: Option<ProxyHandle>,
    _l4: Option<L4Handle>,
    l4_pending: Option<(l4::Pending, L4Config)>,
}

pub(crate) fn run(cmd: &[impl AsRef<str>], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    if cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }

    if let Some(bwrap) = which("bwrap") {
        return run_with_bwrap(&bwrap, cmd, cfg);
    }
    if let Some(firejail) = which("firejail") {
        return run_with_firejail(&firejail, cmd, cfg);
    }
    Err(Error::ToolNotFound(
        "neither `bwrap` nor `firejail` is installed (apt install bubblewrap)".into(),
    ))
}

/// Build a bwrap-wrapped Command running `inner_argv` inside the sandbox.
/// Returns the Command (with stdio still inheritable / unconfigured) and a
/// keep-alive handle that must live until the child exits.
/// Like `build_bwrap_command_with_extras` with no extras. Currently unused
/// but retained for symmetry with the legacy code path.
#[allow(dead_code)]
pub(crate) fn build_bwrap_command(inner_argv: &[&str], cfg: &SandboxConfig) -> Result<(Command, BwrapKeepAlive)> {
    let bwrap = which("bwrap")
        .ok_or_else(|| Error::ToolNotFound("`bwrap` is not installed (apt install bubblewrap)".into()))?;
    let (cmd, keepalive) = build_bwrap_command_inner(&bwrap, inner_argv, cfg, &[], false)?;
    Ok((cmd, keepalive))
}

/// Like `build_bwrap_command` but injects `extra_args` into the bwrap
/// argv just before the `inner_argv` (i.e., after all standard mounts, env,
/// seccomp, etc.). Used by `spawn_init` to add `--as-pid-1` and the init
/// binary / control socket bind mounts.
#[allow(dead_code)] // Currently only used via build_bwrap_command_with_extras_inner
pub(crate) fn build_bwrap_command_with_extras(
    inner_argv: &[&str],
    cfg: &SandboxConfig,
    extra_args: &[&str],
) -> Result<(Command, BwrapKeepAlive)> {
    build_bwrap_command_with_extras_inner(inner_argv, cfg, extra_args, false)
}

fn build_bwrap_command_with_extras_inner(
    inner_argv: &[&str],
    cfg: &SandboxConfig,
    extra_args: &[&str],
    skip_seccomp: bool,
) -> Result<(Command, BwrapKeepAlive)> {
    let bwrap = which("bwrap")
        .ok_or_else(|| Error::ToolNotFound("`bwrap` is not installed (apt install bubblewrap)".into()))?;
    let (cmd, keepalive) = build_bwrap_command_inner(&bwrap, inner_argv, cfg, extra_args, skip_seccomp)?;
    Ok((cmd, keepalive))
}

fn run_with_bwrap(bwrap: &Path, user_cmd: &[impl AsRef<str>], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    let argv: Vec<&str> = user_cmd.iter().map(|s| s.as_ref()).collect();
    let (mut cmd, mut keepalive) = build_bwrap_command_inner(bwrap, &argv, cfg, &[], false)?;
    pipe_stdio(&mut cmd);
    let stdin_bytes = cfg.stdin.as_deref();
    // We need to spawn, then finalize L4 (recv listener fd), then wait.
    // `spawn_run` does spawn+wait together, so break that apart here.
    use std::process::Stdio;
    let _ = stdin_bytes;
    // Actually re-use spawn_run but finalize via a tiny wrapper — we know
    // spawn_run calls spawn() internally. Simplest: let spawn_run spawn the
    // child; pre_exec runs synchronously before exec in the child, so by
    // the time `.spawn()` returns in the parent, the sendmsg has happened.
    // spawn_run then waits. We can't interleave finalize_l4 easily without
    // refactoring spawn_run. Instead: finalize the L4 observer's parent
    // side in a thread BEFORE spawn_run waits — but we don't have the
    // Child. Accept a small refactor: if L4 is pending, do manual spawn.
    if keepalive.l4_pending.is_some() {
        let _ = Stdio::piped();
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::exec(format!("spawn bwrap failed: {}", e)))?;
        let child_pid = child.id() as i32;
        let exit_rx = keepalive.finalize_l4(child_pid)?;
        let result = crate::host::common::wait_with_io_ext(
            &mut child,
            cfg.stdin.as_deref(),
            &cfg.limits,
            cfg.stream_stderr,
            exit_rx,
        )?;
        drop(keepalive);
        Ok(result)
    } else {
        let result = spawn_run(&mut cmd, stdin_bytes, &cfg.limits, cfg.stream_stderr)?;
        drop(keepalive);
        Ok(result)
    }
}

fn build_bwrap_command_inner(
    bwrap: &Path,
    inner_argv: &[&str],
    cfg: &SandboxConfig,
    extra_args: &[&str],
    skip_seccomp: bool,
) -> Result<(Command, BwrapKeepAlive)> {
    let work_dir = cfg
        .work_dir
        .canonicalize()
        .map_err(|e| Error::validation(format!("work_dir canonicalize: {}", e)))?;
    let work_dir_str = work_dir.to_string_lossy().into_owned();

    // Generate seccomp BPF in a temp dir sibling to work_dir (not inside work_dir,
    // so tenant can't tamper with it).
    let seccomp_tmp = tempfile::tempdir()?;
    let bpf_path = seccomp_tmp.path().join("seccomp.bpf");
    let seccomp_fd: Option<i32> = match generate_bpf_file(&bpf_path) {
        Ok(()) => {
            use std::os::unix::io::IntoRawFd;
            match std::fs::File::open(&bpf_path) {
                Ok(f) => {
                    let fd = f.into_raw_fd();
                    // Rust opens files with O_CLOEXEC; clear it so the child inherits fd.
                    unsafe {
                        use nix::libc::{F_GETFD, F_SETFD, FD_CLOEXEC, fcntl};
                        let flags = fcntl(fd, F_GETFD, 0);
                        if flags >= 0 {
                            fcntl(fd, F_SETFD, flags & !FD_CLOEXEC);
                        }
                    }
                    Some(fd)
                }
                Err(e) => {
                    tracing::warn!("sandbox: open bpf failed: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!("sandbox: generate bpf failed: {}", e);
            None
        }
    };

    let mut cmd = Command::new(bwrap);
    cmd.args(["--unshare-all", "--die-with-parent"]);

    // Read-only system trees (so /bin/sh, /usr/bin/rm, etc. exist).
    match cfg.system_layout {
        SystemLayout::HostShared => {
            for p in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
                if Path::new(p).exists() {
                    cmd.args(["--ro-bind", p, p]);
                }
            }

            // Minimal /etc pieces for DNS + TLS to keep bash/common tools working.
            for etc in [
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d",
                "/etc/resolv.conf",
                "/etc/nsswitch.conf",
                "/etc/hosts",
                "/etc/ssl/certs",
                "/etc/ca-certificates.conf",
                "/etc/alternatives",
            ] {
                if Path::new(etc).exists() {
                    cmd.args(["--ro-bind", etc, etc]);
                }
            }

            // Empty HOME + /root so anything written there dies with the sandbox.
            cmd.args(["--dir", "/home"]);
            cmd.args(["--dir", "/root"]);

            // Hide sensitive dotfiles under the host HOME. Although we empty-dir
            // /home, a user might mount their HOME explicitly via extra_mounts —
            // make sure the dotfiles are blanked. Only meaningful for HostShared,
            // since CallerProvided does not expose the host's /home at all and
            // referencing $HOME there would leak the host username via bwrap's
            // implicit mkdir of intermediate dirs.
            if let Ok(home) = std::env::var("HOME") {
                for name in HIDE_HOME_DIRS {
                    let p = PathBuf::from(&home).join(name);
                    if p.exists() {
                        cmd.args(["--tmpfs", &p.to_string_lossy()]);
                    }
                }
            }
        }
        SystemLayout::CallerProvided => {
            // Caller is responsible for providing the full rootfs via
            // `extra_mounts`; skip all default host bind mounts.
        }
    }

    // work_dir mounted at /tmp, read-write, but at both the host path and /tmp,
    // so commands using either will find it. We prefer /tmp as the cwd.
    cmd.args(["--bind", &work_dir_str, "/tmp"]);

    // Extra mounts.
    for m in &cfg.extra_mounts {
        let src = m
            .host
            .canonicalize()
            .map_err(|e| Error::validation(format!("mount canonicalize: {}", e)))?;
        let src_s = src.to_string_lossy().into_owned();
        let dst = m
            .guest
            .clone()
            .unwrap_or_else(|| src.clone())
            .to_string_lossy()
            .into_owned();
        if m.read_only {
            cmd.args(["--ro-bind", &src_s, &dst]);
        } else {
            cmd.args(["--bind", &src_s, &dst]);
        }
    }

    // /dev and /proc. In Docker, mounting procfs from a user namespace is blocked.
    cmd.args(["--dev", "/dev"]);
    let in_container = Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("containerd") || s.contains("kubepods"))
            .unwrap_or(false);
    if in_container {
        cmd.args(["--dir", "/proc"]);
    } else {
        cmd.args(["--proc", "/proc"]);
    }

    // Network.
    let (proxy_handle, l4_prep): (Option<ProxyHandle>, Option<(l4::ChildInstall, l4::Pending, L4Config)>) =
        match &cfg.network {
            NetworkPolicy::Blocked => {
                cmd.args(["--unshare-net"]);
                (None, None)
            }
            NetworkPolicy::AllowAll => {
                cmd.args(["--share-net"]);
                (None, None)
            }
            NetworkPolicy::Observed { sink } => {
                cmd.args(["--share-net"]);
                let bridge = Arc::new(crate::linux::bridge::L4L7Bridge::new());
                let handle = net_observer::start_proxy(ProxyConfig {
                    sink: sink.clone(),
                    allow_hosts: vec![],
                    enforce_allow: false,
                    bridge: Some(bridge.clone()),
                })
                .map_err(|e| Error::exec(format!("start net observer proxy: {}", e)))?;
                let l4_cfg = L4Config {
                    sink: sink.clone(),
                    allow_hosts: vec![],
                    enforce_allow: false,
                    bridge: Some(bridge),
                };
                let l4_prep = match l4::prepare(l4_cfg.clone()) {
                    Ok((ci, pend)) => Some((ci, pend, l4_cfg)),
                    Err(e) => {
                        tracing::warn!("sandbox: L4 observer disabled, continuing with L7 only: {}", e);
                        None
                    }
                };
                (Some(handle), l4_prep)
            }
            NetworkPolicy::Gated {
                sink,
                allow_hosts,
                dns_policy: _,
            } => {
                cmd.args(["--share-net"]);
                let bridge = Arc::new(crate::linux::bridge::L4L7Bridge::new());
                let handle = net_observer::start_proxy(ProxyConfig {
                    sink: sink.clone(),
                    allow_hosts: allow_hosts.clone(),
                    enforce_allow: true,
                    bridge: Some(bridge.clone()),
                })
                .map_err(|e| Error::exec(format!("start net observer proxy: {}", e)))?;
                let l4_cfg = L4Config {
                    sink: sink.clone(),
                    allow_hosts: allow_hosts.clone(),
                    enforce_allow: true,
                    bridge: Some(bridge),
                };
                let l4_prep = match l4::prepare(l4_cfg.clone()) {
                    Ok((ci, pend)) => Some((ci, pend, l4_cfg)),
                    Err(e) => {
                        tracing::warn!("sandbox: L4 observer disabled, continuing with L7 only: {}", e);
                        None
                    }
                };
                (Some(handle), l4_prep)
            }
        };

    // Environment: clear default, set explicit.
    cmd.args(["--clearenv"]);

    // Library defaults first; the caller's `cfg.env` is applied AFTER so
    // it can override anything below (HOME, PATH, TMPDIR, ...).
    cmd.args([
        "--setenv",
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ]);
    cmd.args(["--setenv", "HOME", "/tmp"]);
    cmd.args(["--setenv", "TMPDIR", "/tmp"]);
    cmd.args(["--setenv", "SAFEBOX", "1"]);
    // Force UTF-8 locale so `ls`, bash, and downstream tools display
    // non-ASCII filenames (CJK, emoji) as-is instead of `ls`'s default
    // C-locale `''$'\346\226\260'...''` octal escapes.
    cmd.args(["--setenv", "LANG", "C.UTF-8"]);
    cmd.args(["--setenv", "LC_ALL", "C.UTF-8"]);

    // Caller-provided env: applied last so callers can override the
    // library defaults above (e.g. set a different HOME, custom PATH).
    for (k, v) in &cfg.env {
        cmd.args(["--setenv", k.to_string_lossy().as_ref(), v.to_string_lossy().as_ref()]);
    }

    // Point cooperating clients at the in-process L7 observer proxy.
    if let Some(h) = &proxy_handle {
        let proxy_url = format!("http://{}", h.addr());
        for k in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.args(["--setenv", k, &proxy_url]);
        }
        // Local services never hit the proxy.
        cmd.args(["--setenv", "NO_PROXY", "localhost,127.0.0.1,::1"]);
        cmd.args(["--setenv", "no_proxy", "localhost,127.0.0.1,::1"]);
    }

    // cwd inside sandbox.
    let cwd_inside = cfg.cwd.clone().unwrap_or_else(|| PathBuf::from("/tmp"));
    cmd.args(["--chdir", &cwd_inside.to_string_lossy()]);

    // Seccomp BPF via fd 3. When `skip_seccomp` is set (workspace mode),
    // init installs seccomp per-child after fork so init itself can call
    // mount() / umount2() for dynamic bind mount.
    if !skip_seccomp && seccomp_fd.is_some() {
        cmd.args(["--seccomp", "3"]);
    }

    // Extra bwrap flags injected by callers (e.g., spawn_init for --as-pid-1
    // and the init binary / control-socket bind mounts). Must be inserted
    // BEFORE the `--` separator, otherwise bwrap treats them as the program
    // to run.
    for a in extra_args {
        cmd.arg(a);
    }

    // The command to run.
    cmd.arg("--");

    for a in inner_argv {
        cmd.arg(a);
    }

    // rlimits + dup seccomp fd into slot 3 (pre_exec, post-fork pre-exec).
    let limits = cfg.limits;
    let l4_install = l4_prep.as_ref().map(|(ci, _, _)| *ci);
    unsafe {
        cmd.pre_exec(move || {
            use nix::libc::{F_GETFD, F_SETFD, FD_CLOEXEC, close, dup2, fcntl};
            crate::host::common::apply_rlimits(&limits);
            if let Some(src_fd) = seccomp_fd {
                const SLOT: i32 = 3;
                if src_fd == SLOT {
                    let flags = fcntl(SLOT, F_GETFD, 0);
                    if flags >= 0 {
                        fcntl(SLOT, F_SETFD, flags & !FD_CLOEXEC);
                    }
                } else if dup2(src_fd, SLOT) >= 0 {
                    let flags = fcntl(SLOT, F_GETFD, 0);
                    if flags >= 0 {
                        fcntl(SLOT, F_SETFD, flags & !FD_CLOEXEC);
                    }
                    close(src_fd);
                }
            }
            // L4 seccomp-notify install: MUST run BEFORE bwrap's own seccomp
            // so the listener fd is created, SCM_RIGHTS'd to parent, and
            // closed in child. Async-signal-safe raw libc only.
            if let Some(ci) = l4_install {
                l4::child_install(ci)?;
            }
            Ok(())
        });
    }

    // Stash the L4 pending state on the keepalive; caller must finalize
    // AFTER `Command::spawn` returns (pre_exec has sent the listener fd).
    let l4_pending_finalize: Option<(l4::Pending, L4Config)> = l4_prep.map(|(_, p, c)| (p, c));

    Ok((
        cmd,
        BwrapKeepAlive {
            _seccomp_tmp: Some(seccomp_tmp),
            _proxy: proxy_handle,
            _l4: None,
            l4_pending: l4_pending_finalize,
        },
    ))
}

impl BwrapKeepAlive {
    /// Finalize L4 observer after `Command::spawn` returns. Must be called
    /// exactly once if the sandbox config requested L4 observation; noop
    /// otherwise.
    ///
    /// For the seccomp-trace backend, returns `Some(Receiver<ExitStatus>)`;
    /// the caller MUST use that to obtain the child's exit status instead of
    /// `Child::wait()` (the tracer thread reaps the child via `waitpid`).
    pub(crate) fn finalize_l4(
        &mut self,
        child_pid: i32,
    ) -> Result<Option<std::sync::mpsc::Receiver<std::process::ExitStatus>>> {
        if let Some((pending, cfg)) = self.l4_pending.take() {
            let (handle, exit_rx) = l4::finalize(pending, cfg, child_pid)
                .map_err(|e| Error::exec(format!("finalize L4 observer: {}", e)))?;
            self._l4 = Some(handle);
            Ok(exit_rx)
        } else {
            Ok(None)
        }
    }
}

fn run_with_firejail(firejail: &Path, user_cmd: &[impl AsRef<str>], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    let work_dir = cfg
        .work_dir
        .canonicalize()
        .map_err(|e| Error::validation(format!("work_dir canonicalize: {}", e)))?;

    let mut cmd = Command::new(firejail);
    cmd.arg("--quiet");
    cmd.arg("--noprofile");
    cmd.arg("--private-dev");
    cmd.arg("--private-tmp");
    cmd.arg(format!("--private={}", work_dir.display()));

    match cfg.network {
        NetworkPolicy::Blocked => {
            cmd.arg("--net=none");
        }
        NetworkPolicy::AllowAll => {}
        NetworkPolicy::Observed { .. } | NetworkPolicy::Gated { .. } => {
            return Err(Error::validation(
                "NetworkPolicy::Observed / Gated require bubblewrap (apt install bubblewrap); not supported via firejail fallback",
            ));
        }
    }

    for dir in HIDE_HOME_DIRS {
        cmd.arg(format!("--blacklist=~/{}", dir));
    }
    cmd.arg("--blacklist=/etc/shadow");
    cmd.arg("--blacklist=/etc/sudoers");

    for m in &cfg.extra_mounts {
        if m.read_only {
            cmd.arg(format!("--whitelist={}", m.host.display()));
            cmd.arg(format!("--read-only={}", m.host.display()));
        } else {
            cmd.arg(format!("--whitelist={}", m.host.display()));
        }
    }

    cmd.arg("--");
    for a in user_cmd {
        cmd.arg(a.as_ref());
    }

    for (k, v) in &cfg.env {
        cmd.env(k, v);
    }
    if let Some(c) = &cfg.cwd {
        cmd.current_dir(c);
    } else {
        cmd.current_dir(&work_dir);
    }
    pipe_stdio(&mut cmd);

    let limits = cfg.limits;
    unsafe {
        cmd.pre_exec(move || {
            crate::host::common::apply_rlimits(&limits);
            Ok(())
        });
    }
    let stdin_bytes = cfg.stdin.as_deref();
    spawn_run(&mut cmd, stdin_bytes, &cfg.limits, cfg.stream_stderr)
}

/// Spawn a long-running bash inside the sandbox with stdin/stdout/stderr piped.
/// Used by `Session` for persistent multi-exec sessions.
///
/// IMPORTANT: bwrap is launched with `--die-with-parent`, which under the hood
/// calls `prctl(PR_SET_PDEATHSIG, SIGKILL)` inside bwrap. The "parent" the
/// kernel tracks is the **thread that called `clone()`/`fork()`**, NOT the
/// process. If the spawning thread exits while the rest of the process keeps
/// running, the kernel sends SIGKILL to bwrap (and cascades to bash).
///
/// `Session` is typically opened from `tokio::task::spawn_blocking`. Tokio's
/// default blocking pool reaps idle worker threads after **10 seconds**, which
/// caused bash to mysteriously die ~10s after Session creation. To avoid this
/// we spawn bwrap on a dedicated `std::thread` that parks for the lifetime of
/// the Session — that thread is bwrap's PDEATHSIG anchor and only exits when
/// the keep-alive guard is dropped (i.e., when the Session itself drops).
///
/// **Architecture (post init-shim):** the host no longer pipes bash directly.
/// Instead `tokimo-sandbox-init` runs as PID 1 inside the bwrap container,
/// the host opens a SEQPACKET control socket to it, requests `OpenShell`, and
/// the bash process becomes init's child. Inside the host we splice init's
/// `Stdout`/`Stderr` events into two anonymous OS pipes whose read-ends look
/// identical to a normal `Child`'s stdout/stderr to the sentinel parser —
/// keeping the framing logic in `session.rs` unchanged.
pub(crate) fn spawn_session_shell(cfg: &SandboxConfig) -> Result<crate::session::ShellHandle> {
    use crate::linux::init_client::InitClient;
    use std::io::Write as _;
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    let mut spawned = crate::linux::spawn_init(cfg)?;
    let host_sock = spawned.host_control_dir.path().join("control.sock");

    // Wait for init to bind the control socket. Bwrap may take a beat.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !host_sock.exists() {
        // Check if init has already exited — if so, grab its stderr for
        // diagnostics before we report the timeout.
        if let Ok(Some(status)) = spawned.child.try_wait() {
            let mut stderr = String::new();
            if let Some(ref mut pipe) = spawned.child.stderr {
                use std::io::Read;
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Err(Error::exec(format!(
                "init exited with {status} before binding control socket at {}; stderr: {stderr}",
                host_sock.display()
            )));
        }
        if Instant::now() > deadline {
            return Err(Error::exec(format!(
                "control socket never appeared at {} (init did not start)",
                host_sock.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let client = Arc::new(InitClient::connect(&host_sock)?);
    client.hello()?;
    let info = client.open_shell(&["/bin/bash", "--noprofile", "--norc"], &[], None)?;
    let child_id = info.child_id;

    // Bridge pipes: pump thread takes init events → write end; sentinel
    // reader threads consume the read end.
    let (out_r_raw, out_w_raw) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
        .map_err(|e| Error::exec(format!("pipe2 stdout bridge: {e}")))?;
    let (err_r_raw, err_w_raw) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
        .map_err(|e| Error::exec(format!("pipe2 stderr bridge: {e}")))?;
    let out_w: OwnedFd = out_w_raw;
    let err_w: OwnedFd = err_w_raw;
    let out_r: OwnedFd = out_r_raw;
    let err_r: OwnedFd = err_r_raw;

    // Convert read-ends to std::fs::File for blocking Read impl.
    let stdout_read = unsafe { std::fs::File::from_raw_fd(out_r.into_raw_fd()) };
    let stderr_read = unsafe { std::fs::File::from_raw_fd(err_r.into_raw_fd()) };

    let lifecycle = Arc::new(InitLifecycle {
        exit_code: Mutex::new(None),
        cv: Condvar::new(),
    });
    let stop = Arc::new(AtomicBool::new(false));

    // Pump: drain InitClient events → bridge pipes. Holds OwnedFds for write
    // ends; on exit drops them, propagating EOF to the sentinel readers.
    let pump_client = client.clone();
    let pump_child_id = child_id.clone();
    let pump_lifecycle = lifecycle.clone();
    let pump_stop = stop.clone();
    let pump = std::thread::Builder::new()
        .name("tps-init-pump".into())
        .spawn(move || {
            let mut out_w = unsafe { std::fs::File::from_raw_fd(out_w.into_raw_fd()) };
            let mut err_w = unsafe { std::fs::File::from_raw_fd(err_w.into_raw_fd()) };
            loop {
                if pump_stop.load(Ordering::Relaxed) {
                    break;
                }
                let dead = pump_client.is_dead();
                let deadline = Instant::now() + Duration::from_millis(200);
                let _ = pump_client.wait_for_event(&pump_child_id, deadline);
                for chunk in pump_client.drain_stdout(&pump_child_id) {
                    if out_w.write_all(&chunk).is_err() {
                        break;
                    }
                }
                for chunk in pump_client.drain_stderr(&pump_child_id) {
                    if err_w.write_all(&chunk).is_err() {
                        break;
                    }
                }
                if let Some((code, _sig)) = pump_client.take_exit(&pump_child_id) {
                    let mut g = pump_lifecycle.exit_code.lock().expect("lifecycle");
                    *g = Some(code);
                    pump_lifecycle.cv.notify_all();
                    break;
                }
                if dead {
                    let mut g = pump_lifecycle.exit_code.lock().expect("lifecycle");
                    if g.is_none() {
                        *g = Some(-1);
                    }
                    pump_lifecycle.cv.notify_all();
                    break;
                }
            }
            // Drop write fds → sentinel readers see EOF.
        })
        .map_err(|e| Error::exec(format!("spawn tps-init-pump thread: {e}")))?;

    let stdin = InitClientStdin {
        client: client.clone(),
        child_id: child_id.clone(),
        closed: false,
    };

    let try_wait_lifecycle = lifecycle.clone();
    let kill_client = client.clone();
    let kill_child_id = child_id.clone();
    let kill_lifecycle = lifecycle.clone();
    let try_wait =
        Box::new(move || -> bool { try_wait_lifecycle.exit_code.lock().map(|g| g.is_some()).unwrap_or(true) });
    let kill = Box::new(move || {
        // Best-effort: SIGKILL the bash pgrp.
        let _ = kill_client.signal(&kill_child_id, libc::SIGKILL, true);
        // Wait briefly for pump to observe the exit.
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut g = match kill_lifecycle.exit_code.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        while g.is_none() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (g2, _) = match kill_lifecycle.cv.wait_timeout(g, deadline - now) {
                Ok(x) => x,
                Err(_) => return,
            };
            g = g2;
        }
    });

    let exit_lifecycle = lifecycle.clone();
    let shell_exit_code: Box<dyn FnMut() -> Option<i32> + Send> =
        Box::new(move || -> Option<i32> { exit_lifecycle.exit_code.lock().ok().and_then(|g| *g) });

    let stop_for_keepalive = stop.clone();
    let keepalive = Box::new(InitKeepalive {
        spawned: Some(spawned),
        client: Some(client.clone()),
        pump: Some(pump),
        pump_stop: stop_for_keepalive,
    });

    // PTY factory: clone the InitClient and let it spawn additional PTY
    // children on demand.
    let pty_client = client.clone();
    let open_pty: crate::session::OpenPtyFn = Box::new(
        move |rows: u16, cols: u16, argv: &[String], env: &[(String, String)], cwd: Option<&str>| {
            crate::linux::open_pty_via_init(&pty_client, rows, cols, argv, env, cwd)
        },
    );

    // One-shot factory: each call is an independent pipes-mode child of
    // init. No mutex, fully concurrent with Session::exec and with each
    // other.
    let oneshot_client = client.clone();
    let run_oneshot: crate::session::RunOneshotFn = Box::new(move |cmd: &str, timeout: Duration| {
        let argv: [&str; 3] = ["/bin/bash", "-c", cmd];
        let (stdout, stderr, code) = oneshot_client.run_oneshot(&argv, &[], None, timeout)?;
        Ok(crate::session::ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
        })
    });

    // Shared job_id → child_id mapping for kill_job support.
    let job_map: Arc<Mutex<HashMap<u64, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // Async spawn factory: each call spawns a child that inherits the shell's
    // cwd/env via `/proc/<pid>/cwd` + `/proc/<pid>/environ`. Returns a
    // `JobOutput` handle immediately; output is collected on `wait_with_timeout`.
    let spawn_client = client.clone();
    let spawn_shell_cid = child_id.clone();
    let spawn_job_map = job_map.clone();
    let spawn_async: crate::session::SpawnAsyncFn = Box::new(move |job_id: u64, cmd: &str| {
        let handle =
            spawn_client.spawn_pipes_inherit_async(&["/bin/bash", "-c", cmd], &[], None, Some(&spawn_shell_cid))?;
        let child_id = handle.child_id().to_string();
        spawn_job_map
            .lock()
            .map_err(|_| Error::exec("job map poisoned"))?
            .insert(job_id, child_id);
        Ok(Box::new(PipeJobOutput {
            handle,
            _client: spawn_client.clone(),
        }))
    });

    // Kill factory: looks up a child_id by job_id and sends SIGKILL via init.
    let kill_client = client.clone();
    let kill_job_map = job_map.clone();
    let kill_spawn: crate::session::KillSpawnFn = Box::new(move |job_id: u64| {
        let child_id = {
            let map = kill_job_map.lock().map_err(|_| Error::exec("job map poisoned"))?;
            map.get(&job_id).cloned()
        };
        if let Some(cid) = child_id {
            // Best-effort: send SIGKILL, ignore result (child may already be dead).
            let _ = kill_client.signal(&cid, libc::SIGKILL, true);
        }
        // Always return Ok — caller uses wait_with_timeout to confirm death.
        Ok(())
    });

    Ok(crate::session::ShellHandle {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout_read),
        stderr: Box::new(stderr_read),
        try_wait,
        kill,
        keepalive,
        open_pty: Some(Arc::new(open_pty)),
        run_oneshot: Some(Arc::new(run_oneshot)),
        spawn_async: Some(Arc::new(spawn_async)),
        kill_spawn: Some(Arc::new(kill_spawn)),
        shell_exit_code,
    })
}

/// [`JobOutput`] implementation backed by init's pipe mode.
/// The [`ChildHandle`] drains stdout/stderr events into memory via the
/// shared `InitClient` reader thread.
struct PipeJobOutput {
    handle: crate::linux::init_client::ChildHandle,
    /// Keep the `InitClient` alive until wait completes.
    _client: Arc<crate::linux::init_client::InitClient>,
}

impl crate::session::JobOutput for PipeJobOutput {
    fn wait_with_timeout(&self, timeout: std::time::Duration) -> crate::Result<crate::session::ExecOutput> {
        let (stdout, stderr, code) = self.handle.wait_with_timeout(timeout)?;
        Ok(crate::session::ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
        })
    }
}

/// Open a PTY child via the given init client. Used by both
/// `Session::open_pty` and the PTY factory closure stored on `ShellHandle`.
pub(crate) fn open_pty_via_init(
    client: &Arc<crate::linux::init_client::InitClient>,
    rows: u16,
    cols: u16,
    argv: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
) -> Result<crate::session::PtyHandle> {
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (info, master_fd) = client.spawn_pty(&argv_refs, env, cwd, rows, cols)?;
    let child_id = info.child_id;

    let resize_client = client.clone();
    let resize_id = child_id.clone();
    let resize_fn: Box<dyn Fn(u16, u16) -> Result<()> + Send + Sync> =
        Box::new(move |r, c| resize_client.resize(&resize_id, r, c));

    let kill_client = client.clone();
    let kill_id = child_id.clone();
    let kill_fn: Box<dyn Fn() + Send + Sync> = Box::new(move || {
        let _ = kill_client.signal(&kill_id, libc::SIGKILL, true);
    });

    let wait_client = client.clone();
    let wait_id = child_id.clone();
    let wait_fn: Box<dyn Fn(std::time::Duration) -> Option<i32> + Send + Sync> = Box::new(move |timeout| {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some((rc, _sig)) = wait_client.take_exit(&wait_id) {
                return Some(rc);
            }
            if wait_client.is_dead() {
                return Some(-1);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            wait_client.wait_for_event(&wait_id, deadline);
        }
    });

    // Keepalive: hold an Arc<InitClient> so the control socket outlives the
    // PtyHandle even if the originating Session is dropped.
    let keepalive: Box<dyn std::any::Any + Send + Sync> = Box::new(client.clone());
    Ok(crate::session::PtyHandle::new(
        master_fd, child_id, resize_fn, kill_fn, wait_fn, keepalive,
    ))
}

struct InitLifecycle {
    exit_code: Mutex<Option<i32>>,
    cv: Condvar,
}

use std::sync::Condvar;

struct InitClientStdin {
    client: Arc<crate::linux::init_client::InitClient>,
    child_id: String,
    closed: bool,
}

impl std::io::Write for InitClientStdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "InitClientStdin closed",
            ));
        }
        // Stay well below MAX_FRAME_BYTES (64 KiB) accounting for base64
        // expansion + JSON overhead.
        for chunk in buf.chunks(32 * 1024) {
            self.client
                .write(&self.child_id, chunk)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for InitClientStdin {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.client.close_child(&self.child_id);
        }
    }
}

/// Drop order matters: pump thread must be told to stop and joined before
/// the InitClient socket is closed (so the pump's `wait_for_event` wakes
/// up). Then `SpawnedInit` drops, which drops the spawner-guard, which
/// causes bwrap to receive `SIGKILL` via `PDEATHSIG`.
struct InitKeepalive {
    spawned: Option<crate::linux::SpawnedInit>,
    client: Option<Arc<crate::linux::init_client::InitClient>>,
    pump: Option<std::thread::JoinHandle<()>>,
    pump_stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for InitKeepalive {
    fn drop(&mut self) {
        // 1. Tell pump to stop and wait for it (so it stops touching the
        //    socket before we drop the client).
        self.pump_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(j) = self.pump.take() {
            // Pump may be in `wait_for_event`; that wakes up on socket EOF
            // (which happens when bwrap dies). Give it a moment, then
            // continue regardless.
            let _ = j.join();
        }
        // 2. Drop client (closes control socket).
        self.client.take();
        // 3. Drop SpawnedInit → spawner-guard → bwrap PDEATHSIG → init dies.
        self.spawned.take();
    }
}

/// Keeps the dedicated `sandbox-spawner` thread alive for the lifetime of a
/// `Session`. Dropping this guard closes `_stop`, the spawner thread wakes up
/// from its `recv()` with `Err(_)`, exits, and the kernel then delivers
/// `PDEATHSIG` (SIGKILL) to bwrap — which is exactly what we want at session
/// teardown.
struct SessionSpawnerGuard {
    _stop: std::sync::mpsc::Sender<()>,
    _join: Option<std::thread::JoinHandle<()>>,
}

// ---------------------------------------------------------------------------
// Init (PID-1 docker-shim) sandbox lifecycle
// ---------------------------------------------------------------------------

/// Locate the `tokimo-sandbox-init` binary on disk.
///
/// Resolution order:
///   1. `TOKIMO_SANDBOX_INIT_BIN` env override.
///   2. `option_env!("CARGO_BIN_EXE_tokimo-sandbox-init")` baked at compile time
///      when the test/example was built via cargo (works for examples + tests
///      in this same crate).
///   3. Sibling of `current_exe()` named `tokimo-sandbox-init`.
pub fn locate_init_binary() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TOKIMO_SANDBOX_INIT_BIN") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Some(baked) = option_env!("CARGO_BIN_EXE_tokimo-sandbox-init") {
        let pb = PathBuf::from(baked);
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let pb = dir.join("tokimo-sandbox-init");
        if pb.exists() {
            return Ok(pb);
        }
        // Workspace target/debug/examples/<name> -> target/debug/tokimo-sandbox-init
        if let Some(parent) = dir.parent() {
            let pb = parent.join("tokimo-sandbox-init");
            if pb.exists() {
                return Ok(pb);
            }
        }
    }
    Err(Error::ToolNotFound(
        "tokimo-sandbox-init binary not found (set TOKIMO_SANDBOX_INIT_BIN or build it)".into(),
    ))
}

/// Result of `spawn_init`: a long-lived bwrap child running our PID-1 init,
/// plus the host-side directory whose contents are visible inside the sandbox
/// at `/run/tk-sandbox/`. The control socket appears at
/// `<host_control_dir>/control.sock` once init binds it.
pub struct SpawnedInit {
    pub child: std::process::Child,
    pub host_control_dir: tempfile::TempDir,
    /// Keep-alive guard. Drop this after the child to release the spawner
    /// thread + bwrap PDEATHSIG anchor.
    pub keepalive: Box<dyn std::any::Any + Send>,
}

/// Spawn a long-lived sandbox container whose PID 1 is `tokimo-sandbox-init`.
///
/// The init binary is ro-bind-mounted at
/// `/usr/local/libexec/tokimo/tokimo-sandbox-init` and bwrap is invoked with
/// `--as-pid-1` so init really is PID 1 inside the user/pid namespace. A host
/// scratch directory is bind-mounted at `/run/tk-sandbox/` for the unix
/// control socket; the init binary is told (via env) to bind it at
/// `/run/tk-sandbox/control.sock`.
///
/// Mirrors `spawn_session_shell` exactly for the bwrap spawn / PDEATHSIG
/// anchor: bwrap is forked from a dedicated `std::thread` that parks until
/// the keep-alive guard is dropped.
pub fn spawn_init(cfg: &SandboxConfig) -> Result<SpawnedInit> {
    use std::process::Stdio;
    use std::sync::mpsc;

    if which("bwrap").is_none() {
        return Err(Error::ToolNotFound(
            "`bwrap` is required for sandbox init on Linux (apt install bubblewrap)".into(),
        ));
    }
    let init_bin = locate_init_binary()?;
    let init_bin_str = init_bin.to_string_lossy().into_owned();
    let host_control_dir = tempfile::Builder::new()
        .prefix("tk-sandbox-ctrl-")
        .tempdir()
        .map_err(|e| Error::exec(format!("create control dir: {e}")))?;
    // Restrict to current user; init will create the socket inside.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(host_control_dir.path(), std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::exec(format!("chmod control dir: {e}")))?;
    let host_control_dir_str = host_control_dir.path().to_string_lossy().into_owned();

    // Inner argv: run our init binary. bwrap's --as-pid-1 makes it PID 1.
    // Bind it at a path on bwrap's own tmpfs root (writable), since /usr is
    // ro-bound from host and can't be mkdir'd into.
    let inner_argv = ["/.tokimo-sandbox-init"];
    let extra = [
        "--as-pid-1",
        "--ro-bind",
        init_bin_str.as_str(),
        "/.tokimo-sandbox-init",
        "--bind",
        host_control_dir_str.as_str(),
        "/run/tk-sandbox",
        "--setenv",
        "TOKIMO_SANDBOX_CONTROL_SOCK",
        "/run/tk-sandbox/control.sock",
    ];
    let (mut cmd, mut keepalive) = build_bwrap_command_with_extras_inner(&inner_argv, cfg, &extra, false)?;

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let (result_tx, result_rx) = mpsc::channel::<std::io::Result<std::process::Child>>();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let join = std::thread::Builder::new()
        .name("sandbox-init-spawner".into())
        .spawn(move || {
            let mut cmd = cmd;
            let res = cmd.spawn();
            let ok = res.is_ok();
            let _ = result_tx.send(res);
            if ok {
                let _ = stop_rx.recv();
            }
        })
        .map_err(|e| Error::exec(format!("spawn sandbox-init-spawner thread: {e}")))?;

    let child = result_rx
        .recv()
        .map_err(|e| Error::exec(format!("recv child from spawner thread: {e}")))?
        .map_err(|e| Error::exec(format!("spawn bwrap init failed: {e}")))?;
    let child_pid = child.id() as i32;
    let _ = keepalive.finalize_l4(child_pid)?;

    let guard = SessionSpawnerGuard {
        _stop: stop_tx,
        _join: Some(join),
    };
    Ok(SpawnedInit {
        child,
        host_control_dir,
        keepalive: Box::new((keepalive, guard)),
    })
}

/// Like [`spawn_init`] but without bwrap-level seccomp. Instead init
/// installs seccomp per-child after fork so init itself can call mount()
/// and umount2() for dynamic bind mounts. Used by [`super::Workspace`].
pub fn spawn_init_workspace(cfg: &SandboxConfig) -> Result<SpawnedInit> {
    use std::process::Stdio;
    use std::sync::mpsc;

    if which("bwrap").is_none() {
        return Err(Error::ToolNotFound(
            "`bwrap` is required for sandbox init on Linux (apt install bubblewrap)".into(),
        ));
    }
    let init_bin = locate_init_binary()?;
    let init_bin_str = init_bin.to_string_lossy().into_owned();
    let host_control_dir = tempfile::Builder::new()
        .prefix("tk-sandbox-ctrl-")
        .tempdir()
        .map_err(|e| Error::exec(format!("create control dir: {e}")))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(host_control_dir.path(), std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::exec(format!("chmod control dir: {e}")))?;
    let host_control_dir_str = host_control_dir.path().to_string_lossy().into_owned();

    let inner_argv = ["/.tokimo-sandbox-init"];
    // Pass BPF bytes to init for per-child seccomp install.
    let bpf_bytes = crate::linux::seccomp::generate_bpf_bytes();
    let bpf_b64: String = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&bpf_bytes)
    };
    let extra: [&str; 13] = [
        "--as-pid-1",
        "--ro-bind",
        init_bin_str.as_str(),
        "/.tokimo-sandbox-init",
        "--bind",
        host_control_dir_str.as_str(),
        "/run/tk-sandbox",
        "--setenv",
        "TOKIMO_SANDBOX_CONTROL_SOCK",
        "/run/tk-sandbox/control.sock",
        "--setenv",
        "TOKIMO_SANDBOX_SECCOMP_B64",
        bpf_b64.as_str(),
    ];
    let (mut cmd, mut keepalive) = build_bwrap_command_with_extras_inner(&inner_argv, cfg, &extra, true)?;

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let (result_tx, result_rx) = mpsc::channel::<std::io::Result<std::process::Child>>();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let join = std::thread::Builder::new()
        .name("sandbox-init-spawner".into())
        .spawn(move || {
            let mut cmd = cmd;
            let res = cmd.spawn();
            let ok = res.is_ok();
            let _ = result_tx.send(res);
            if ok {
                let _ = stop_rx.recv();
            }
        })
        .map_err(|e| Error::exec(format!("spawn sandbox-init-spawner thread: {e}")))?;

    let child = result_rx
        .recv()
        .map_err(|e| Error::exec(format!("recv child from spawner thread: {e}")))?
        .map_err(|e| Error::exec(format!("spawn bwrap init failed: {e}")))?;
    let child_pid = child.id() as i32;
    let _ = keepalive.finalize_l4(child_pid)?;

    let guard = SessionSpawnerGuard {
        _stop: stop_tx,
        _join: Some(join),
    };
    Ok(SpawnedInit {
        child,
        host_control_dir,
        keepalive: Box::new((keepalive, guard)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_layout_default_is_host_shared() {
        assert_eq!(SystemLayout::default(), SystemLayout::HostShared);
    }

    #[test]
    fn sandbox_config_system_layout_builder() {
        let tmp = std::env::temp_dir();
        let cfg = SandboxConfig::new(&tmp);
        assert_eq!(cfg.system_layout, SystemLayout::HostShared);

        let cfg = cfg.system_layout(SystemLayout::CallerProvided);
        assert_eq!(cfg.system_layout, SystemLayout::CallerProvided);
    }
}
