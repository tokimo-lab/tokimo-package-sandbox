//! Linux sandbox: bubblewrap (preferred) or firejail (fallback).

#![cfg(target_os = "linux")]

use crate::common::{pipe_stdio, spawn_run, which};
use crate::config::{NetworkPolicy, SandboxConfig};
use crate::l4::{self, L4Config, L4Handle};
use crate::net_observer::{self, ProxyConfig, ProxyHandle};
use crate::seccomp::generate_bpf_file;
use crate::{Error, ExecutionResult, Result};
use std::sync::Arc;

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
pub(crate) fn build_bwrap_command(
    inner_argv: &[&str],
    cfg: &SandboxConfig,
) -> Result<(Command, BwrapKeepAlive)> {
    let bwrap = which("bwrap").ok_or_else(|| {
        Error::ToolNotFound("`bwrap` is not installed (apt install bubblewrap)".into())
    })?;
    let (cmd, keepalive) = build_bwrap_command_inner(&bwrap, inner_argv, cfg)?;
    Ok((cmd, keepalive))
}

fn run_with_bwrap(
    bwrap: &Path,
    user_cmd: &[impl AsRef<str>],
    cfg: &SandboxConfig,
) -> Result<ExecutionResult> {
    let argv: Vec<&str> = user_cmd.iter().map(|s| s.as_ref()).collect();
    let (mut cmd, mut keepalive) = build_bwrap_command_inner(bwrap, &argv, cfg)?;
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
        let result = crate::common::wait_with_io_ext(
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
                        use nix::libc::{fcntl, FD_CLOEXEC, F_GETFD, F_SETFD};
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

    // Hide sensitive dotfiles under HOME. Although we empty-dir /home, a user
    // might mount their HOME explicitly — make sure the dotfiles are blanked.
    if let Ok(home) = std::env::var("HOME") {
        for name in HIDE_HOME_DIRS {
            let p = PathBuf::from(&home).join(name);
            if p.exists() {
                cmd.args(["--tmpfs", &p.to_string_lossy()]);
            }
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
    let (proxy_handle, l4_prep): (Option<ProxyHandle>, Option<(l4::ChildInstall, l4::Pending, L4Config)>) = match &cfg.network {
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
            let bridge = Arc::new(crate::bridge::L4L7Bridge::new());
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
                    tracing::warn!(
                        "sandbox: L4 observer disabled, continuing with L7 only: {}",
                        e
                    );
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
            let bridge = Arc::new(crate::bridge::L4L7Bridge::new());
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
                    tracing::warn!(
                        "sandbox: L4 observer disabled, continuing with L7 only: {}",
                        e
                    );
                    None
                }
            };
            (Some(handle), l4_prep)
        }
    };

    // Environment: clear default, set explicit.
    cmd.args(["--clearenv"]);
    let mut saw_path = false;
    for (k, v) in &cfg.env {
        let k_s = k.to_string_lossy();
        if k_s.eq_ignore_ascii_case("PATH") {
            saw_path = true;
        }
        cmd.args([
            "--setenv",
            k_s.as_ref(),
            v.to_string_lossy().as_ref(),
        ]);
    }
    if !saw_path {
        cmd.args(["--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]);
    }
    cmd.args(["--setenv", "HOME", "/tmp"]);
    cmd.args(["--setenv", "TMPDIR", "/tmp"]);
    cmd.args(["--setenv", "SAFEBOX", "1"]);

    // Point cooperating clients at the in-process L7 observer proxy.
    if let Some(h) = &proxy_handle {
        let proxy_url = format!("http://{}", h.addr());
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"] {
            cmd.args(["--setenv", k, &proxy_url]);
        }
        // Local services never hit the proxy.
        cmd.args(["--setenv", "NO_PROXY", "localhost,127.0.0.1,::1"]);
        cmd.args(["--setenv", "no_proxy", "localhost,127.0.0.1,::1"]);
    }

    // cwd inside sandbox.
    let cwd_inside = cfg
        .cwd
        .clone()
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    cmd.args(["--chdir", &cwd_inside.to_string_lossy()]);

    // Seccomp BPF via fd 3.
    if seccomp_fd.is_some() {
        cmd.args(["--seccomp", "3"]);
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
            use nix::libc::{close, dup2, fcntl, FD_CLOEXEC, F_GETFD, F_SETFD};
            crate::common::apply_rlimits(&limits);
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
    let l4_pending_finalize: Option<(l4::Pending, L4Config)> =
        l4_prep.map(|(_, p, c)| (p, c));

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

fn run_with_firejail(
    firejail: &Path,
    user_cmd: &[impl AsRef<str>],
    cfg: &SandboxConfig,
) -> Result<ExecutionResult> {
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
            crate::common::apply_rlimits(&limits);
            Ok(())
        });
    }
    let stdin_bytes = cfg.stdin.as_deref();
    spawn_run(&mut cmd, stdin_bytes, &cfg.limits, cfg.stream_stderr)
}

/// Spawn a long-running bash inside the sandbox with stdin/stdout/stderr piped.
/// Used by `Session` for persistent multi-exec sessions.
pub(crate) fn spawn_session_shell(
    cfg: &SandboxConfig,
) -> Result<(std::process::Child, Box<dyn std::any::Any + Send>)> {
    use std::process::Stdio;
    if which("bwrap").is_none() {
        return Err(Error::ToolNotFound(
            "`bwrap` is required for Session on Linux (apt install bubblewrap)".into(),
        ));
    }
    let argv = ["/bin/bash", "--noprofile", "--norc"];
    let (mut cmd, mut keepalive) = build_bwrap_command(&argv, cfg)?;
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| Error::exec(format!("spawn bwrap session shell failed: {}", e)))?;
    let child_pid = child.id() as i32;
    let _ = keepalive.finalize_l4(child_pid)?;
    Ok((child, Box::new(keepalive)))
}
