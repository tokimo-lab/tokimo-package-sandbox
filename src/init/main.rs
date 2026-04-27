//! `tokimo-sandbox-init` — PID 1 inside an `AgentSandbox` bwrap container.
//!
//! Listens on a SEQPACKET unix socket bound at `/run/tk-sandbox/control.sock`
//! (passed in via env var `TOKIMO_SANDBOX_CONTROL_SOCK` for tests) and serves
//! the wire protocol defined in `tokimo_package_sandbox::init_protocol`.
//!
//! Hard responsibilities of being PID 1:
//!   - reap orphaned children via `signalfd(SIGCHLD)` + `waitpid(-1, WNOHANG)`
//!   - keep mappings of {child_id ↔ pid, pgid, master_fd, stdio pipes}
//!   - never panic out of the event loop (each op is wrapped in catch_unwind)

use std::env;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;

use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket};
use nix::unistd::getpid;

mod child;
mod pty;
mod server;

const ENV_CONTROL_SOCK: &str = "TOKIMO_SANDBOX_CONTROL_SOCK";
const DEFAULT_CONTROL_SOCK: &str = "/run/tk-sandbox/control.sock";

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("[tokimo-sandbox-init] fatal: {e}");
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

fn run() -> Result<(), String> {
    // Hard requirement: bwrap MUST have launched us with `--as-pid-1`.
    let pid = getpid();
    if pid.as_raw() != 1 {
        return Err(format!("init must be PID 1 (got {}); host forgot --as-pid-1", pid));
    }

    // Block the signals we want to receive via signalfd. SIGCHLD is the
    // critical one; SIGTERM/SIGINT/SIGHUP/SIGQUIT let us shutdown gracefully
    // when bwrap (or anyone with our pid) sends them.
    let mut mask = SigSet::empty();
    for s in [
        Signal::SIGCHLD,
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGHUP,
        Signal::SIGQUIT,
        Signal::SIGPIPE,
    ] {
        mask.add(s);
    }
    mask.thread_block().map_err(|e| format!("sigprocmask: {e}"))?;

    let sigfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .map_err(|e| format!("signalfd: {e}"))?;

    // Bind the control socket. We do NOT remove a stale file (the host
    // bind-mounts a fresh empty dir per agent), but if a leftover exists we
    // unlink it here for resilience.
    let sock_path = env::var(ENV_CONTROL_SOCK)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONTROL_SOCK));
    if let Some(parent) = sock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&sock_path);

    let listener_fd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|e| format!("socket(SEQPACKET): {e}"))?;
    let addr = UnixAddr::new(&sock_path).map_err(|e| format!("UnixAddr: {e}"))?;
    bind(listener_fd.as_raw_fd(), &addr).map_err(|e| format!("bind {sock_path:?}: {e}"))?;
    listen(&listener_fd, Backlog::new(8).unwrap()).map_err(|e| format!("listen: {e}"))?;

    // Snapshot the protected base env (bwrap's --setenv set these in our
    // environ; we'll preserve them across child Spawn.env_overlay).
    let base_env = server::snapshot_base_env();

    let listener: OwnedFd = listener_fd;
    let sigfd_owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(sigfd.as_raw_fd()) };
    // signalfd impls Drop that closes the fd; we pulled the fd out so leak
    // the original wrapper to avoid double-close.
    std::mem::forget(sigfd);

    server::run_loop(listener, sigfd_owned, base_env).map_err(|e| format!("event loop: {e}"))
}
