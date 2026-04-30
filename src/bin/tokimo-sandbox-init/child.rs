//! Spawn helpers for the init binary. Two flavors: pipes (anonymous fds for
//! stdin/stdout/stderr) and PTY (controlling tty + setsid + TIOCSCTTY).
//!
//! Uses raw `fork`/`execve`/`pipe2` because we need precise control over fd
//! inheritance and pre-exec setup that the std `Command` API can't express
//! when running as PID 1.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::stat::Mode;
use nix::unistd::{ForkResult, Pid, chdir, dup2, fork, pipe2, setpgid, setsid};

use tokimo_package_sandbox::protocol::types::{ErrorCode, ErrorReply};

use crate::pty as ptymod;

#[derive(Debug, Clone, Copy)]
pub enum ChildKind {
    Shell,
    Generic,
}

pub struct ChildRecord {
    pub pid: i32,
    pub pgid: i32,
    #[allow(dead_code)]
    pub slot: usize,
    #[allow(dead_code)]
    pub kind: ChildKind,
    pub stdin_fd: Option<OwnedFd>,
    pub stdout_fd: Option<OwnedFd>,
    pub stderr_fd: Option<OwnedFd>,
    pub master_fd: Option<OwnedFd>,
    pub shutdown_pending: bool,
    pub owner_fd: RawFd,
}

pub struct Spawned {
    pub pid: i32,
    pub stdin_fd: Option<OwnedFd>,
    pub stdout_fd: Option<OwnedFd>,
    pub stderr_fd: Option<OwnedFd>,
    pub master_fd: Option<OwnedFd>,
}

/// Spawn `argv` with three pipes connected to stdin/stdout/stderr.
pub fn spawn_pipes(argv: &[String], env: &[(String, String)], cwd: Option<&str>) -> Result<Spawned, ErrorReply> {
    if argv.is_empty() {
        return Err(ErrorReply::new(ErrorCode::BadRequest, "empty argv"));
    }
    let (stdin_r, stdin_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("pipe2 stdin: {e}")))?;
    // IMPORTANT: pipe2(O_NONBLOCK) makes BOTH ends non-blocking, which would
    // expose EAGAIN to the child process's stdout/stderr writes — most
    // programs (including bash/coreutils) treat that as a hard write error
    // and silently truncate output. Create blocking pipes here, then set
    // O_NONBLOCK only on init's read end below (after fork).
    let (stdout_r, stdout_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("pipe2 stdout: {e}")))?;
    let (stderr_r, stderr_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("pipe2 stderr: {e}")))?;

    let cargv = build_cstr_argv(argv)?;
    let cenv = build_cstr_env(env)?;

    // Pre-exec error pipe (CLOEXEC), child writes errno before execve.
    let (err_r, err_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("pipe2 err: {e}")))?;

    // SAFETY: fork() in PID-1 init; we control the entire program. After
    // fork we only call async-signal-safe libc + nix functions in child.
    let res = unsafe { fork() }.map_err(|e| ErrorReply::new(ErrorCode::ForkFailed, format!("fork: {e}")))?;
    match res {
        ForkResult::Child => {
            // We never return from child.
            child_setup_pipes(
                stdin_r.as_raw_fd(),
                stdout_w.as_raw_fd(),
                stderr_w.as_raw_fd(),
                err_w.as_raw_fd(),
                cwd,
                &cargv,
                &cenv,
            );
        }
        ForkResult::Parent { child } => {
            // Close child-side fds in the parent.
            drop(stdin_r);
            drop(stdout_w);
            drop(stderr_w);
            drop(err_w);

            // Make the parent-side read fds non-blocking so init's mio
            // drain_pipe loop doesn't get stuck on the final read.
            let _ = fcntl(stdout_r.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK));
            let _ = fcntl(stderr_r.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK));

            // Set child as own pgid for clean killpg semantics. Race-free if
            // both sides do it; child also tries.
            let _ = setpgid(child, child);

            // Read errno from the pre-exec pipe; if any bytes arrive, exec failed.
            // err_r is CLOEXEC + blocking — set non-blocking briefly.
            let _ = fcntl(err_r.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK));
            let mut buf = [0u8; 4];
            let n = unsafe { libc::read(err_r.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n == 4 {
                let errno = i32::from_ne_bytes(buf);
                let code = match errno {
                    libc::ENOENT => ErrorCode::ExecNotFound,
                    libc::EACCES | libc::EPERM => ErrorCode::PermissionDenied,
                    libc::ENOTDIR => ErrorCode::InvalidCwd,
                    _ => ErrorCode::Internal,
                };
                // Reap zombie.
                let _ = nix::sys::wait::waitpid(child, None);
                return Err(ErrorReply::new(code, format!("exec failed: errno {errno}")));
            }

            Ok(Spawned {
                pid: child.as_raw(),
                stdin_fd: Some(stdin_w),
                stdout_fd: Some(stdout_r),
                stderr_fd: Some(stderr_r),
                master_fd: None,
            })
        }
    }
}

/// Spawn `argv` attached to a freshly allocated PTY pair. Returns the master
/// fd; the slave is dup'd over fd 0/1/2 in the child and then closed.
pub fn spawn_pty(
    argv: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
    rows: u16,
    cols: u16,
) -> Result<Spawned, ErrorReply> {
    if argv.is_empty() {
        return Err(ErrorReply::new(ErrorCode::BadRequest, "empty argv"));
    }
    let (master, slave_path) =
        ptymod::open_pty().map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("openpty: {e}")))?;
    ptymod::set_winsize(master.as_raw_fd(), rows, cols).map_err(|e| ErrorReply::new(ErrorCode::Internal, e))?;

    let cargv = build_cstr_argv(argv)?;
    let cenv = build_cstr_env(env)?;
    let (err_r, err_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("pipe2 err: {e}")))?;

    let res = unsafe { fork() }.map_err(|e| ErrorReply::new(ErrorCode::ForkFailed, format!("fork: {e}")))?;
    match res {
        ForkResult::Child => {
            child_setup_pty(&slave_path, err_w.as_raw_fd(), cwd, &cargv, &cenv);
        }
        ForkResult::Parent { child } => {
            drop(err_w);
            // NOTE: do NOT call setpgid(child, child) here. The child runs
            // setsid() in child_setup_pty which atomically creates a new
            // session AND new process group. If we race ahead and setpgid
            // first, the child becomes a pgrp leader, which makes its
            // subsequent setsid() fail with EPERM, leaving the shell with
            // no controlling tty ("cannot set terminal process group").

            let _ = fcntl(err_r.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK));
            let mut buf = [0u8; 4];
            let n = unsafe { libc::read(err_r.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n == 4 {
                let errno = i32::from_ne_bytes(buf);
                let code = match errno {
                    libc::ENOENT => ErrorCode::ExecNotFound,
                    libc::EACCES | libc::EPERM => ErrorCode::PermissionDenied,
                    libc::ENOTDIR => ErrorCode::InvalidCwd,
                    _ => ErrorCode::Internal,
                };
                let _ = nix::sys::wait::waitpid(child, None);
                return Err(ErrorReply::new(code, format!("exec failed: errno {errno}")));
            }

            // Master fd left blocking on purpose: init does NOT read from it
            // (host owns reads), and host-side consumers use std::fs::File
            // which would treat WouldBlock as Err and tear the session down.
            // Keeping it blocking lets host reader threads block on read().
            Ok(Spawned {
                pid: child.as_raw(),
                stdin_fd: None,
                stdout_fd: None,
                stderr_fd: None,
                master_fd: Some(master),
            })
        }
    }
}

fn child_setup_pipes(
    stdin_r: i32,
    stdout_w: i32,
    stderr_w: i32,
    err_w: i32,
    cwd: Option<&str>,
    argv: &[CString],
    env: &[CString],
) -> ! {
    // setsid so the child has its own session; setpgid mirrors parent's call.
    let _ = setsid();
    let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));
    if let Some(cwd) = cwd
        && let Ok(c) = CString::new(cwd)
        && chdir(c.as_c_str()).is_err()
    {
        report_errno_and_exit(err_w, Errno::ENOTDIR as i32);
    }
    // Move pipe ends into 0/1/2.
    if dup2(stdin_r, 0).is_err() {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    if dup2(stdout_w, 1).is_err() {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    if dup2(stderr_w, 2).is_err() {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    // Clear CLOEXEC on 0/1/2 so they survive execve.
    for f in 0..3 {
        let _ = fcntl(f, FcntlArg::F_SETFD(FdFlag::empty()));
    }
    // Unblock signals we blocked in init main (so child sees default SIGINT etc).
    unblock_signals();
    // Install seccomp if BPF bytes were passed (workspace mode).
    install_seccomp_from_env();
    let argv_p: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_p: Vec<*const libc::c_char> = env
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let _ = unsafe { libc::execve(argv_p[0], argv_p.as_ptr(), env_p.as_ptr()) };
    report_errno_and_exit(err_w, Errno::last_raw());
}

fn child_setup_pty(slave_path: &str, err_w: i32, cwd: Option<&str>, argv: &[CString], env: &[CString]) -> ! {
    let sid_rc = unsafe { libc::setsid() };
    if sid_rc < 0 {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    // Open slave AFTER setsid so it becomes our controlling tty implicitly
    // on Linux when O_NOCTTY is not used.
    let slave_c = match CString::new(slave_path) {
        Ok(c) => c,
        Err(_) => report_errno_and_exit(err_w, Errno::EINVAL as i32),
    };
    let slave_fd = unsafe { libc::open(slave_c.as_ptr(), libc::O_RDWR) };
    if slave_fd < 0 {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    // Explicit TIOCSCTTY: must be session leader (we just did setsid above).
    // If this fails the child shell will have no controlling tty.
    if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) } < 0 {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    // Make this process the foreground process group on the new controlling
    // tty so the child shell's tcsetpgrp/tcgetpgrp checks succeed and full
    // job control (Ctrl-C, fg/bg) works. Without this, bash prints
    // "cannot set terminal process group (-1): Inappropriate ioctl" and
    // disables job control. setsid() above already made us a session +
    // process group leader, so getpid() == getpgrp().
    unsafe {
        let _ = libc::tcsetpgrp(slave_fd, libc::getpid());
    }
    if let Some(cwd) = cwd
        && let Ok(c) = CString::new(cwd)
        && chdir(c.as_c_str()).is_err()
    {
        report_errno_and_exit(err_w, Errno::ENOTDIR as i32);
    }
    if dup2(slave_fd, 0).is_err() || dup2(slave_fd, 1).is_err() || dup2(slave_fd, 2).is_err() {
        report_errno_and_exit(err_w, Errno::last_raw());
    }
    if slave_fd > 2 {
        unsafe { libc::close(slave_fd) };
    }
    for f in 0..3 {
        let _ = fcntl(f, FcntlArg::F_SETFD(FdFlag::empty()));
    }
    unblock_signals();
    // Install seccomp if BPF bytes were passed (workspace mode).
    install_seccomp_from_env();
    let argv_p: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_p: Vec<*const libc::c_char> = env
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let _ = unsafe { libc::execve(argv_p[0], argv_p.as_ptr(), env_p.as_ptr()) };
    report_errno_and_exit(err_w, Errno::last_raw());
}

fn report_errno_and_exit(err_w: i32, errno: i32) -> ! {
    let bytes = errno.to_ne_bytes();
    unsafe {
        let _ = libc::write(err_w, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(127);
    }
}

fn unblock_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    }
}

/// Install seccomp BPF filter from the `TOKIMO_SANDBOX_SECCOMP_B64` env var.
/// Called in the child after fork, before exec. If the env var is absent (e.g.,
/// in single-user Session mode where bwrap handles seccomp), this is a no-op.
fn install_seccomp_from_env() {
    let b64 = match std::env::var("TOKIMO_SANDBOX_SECCOMP_B64") {
        Ok(v) => v,
        Err(_) => return,
    };
    let bytes = match base64_decode(&b64) {
        Some(b) => b,
        None => return,
    };
    if bytes.is_empty() {
        return;
    }
    // Convert to sock_fprog for prctl.
    // Each BPF instruction is 8 bytes: (u16 code, u8 jt, u8 jf, u32 k).
    let len = bytes.len() / 8;
    if len == 0 {
        return;
    }
    let prog = libc::sock_fprog {
        len: len as u16,
        filter: bytes.as_ptr() as *mut libc::sock_filter,
    };
    unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const libc::sock_fprog,
        );
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn build_cstr_argv(argv: &[String]) -> Result<Vec<CString>, ErrorReply> {
    argv.iter()
        .map(|s| {
            CString::new(s.as_bytes()).map_err(|e| ErrorReply::new(ErrorCode::BadRequest, format!("argv NUL: {e}")))
        })
        .collect()
}

fn build_cstr_env(env: &[(String, String)]) -> Result<Vec<CString>, ErrorReply> {
    env.iter()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}"))
                .map_err(|e| ErrorReply::new(ErrorCode::BadRequest, format!("env NUL: {e}")))
        })
        .collect()
}

#[allow(dead_code)]
fn _silence_unused() {
    let _ = Mode::from_bits;
    let _ = OwnedFd::as_raw_fd;
    let _: Option<OwnedFd> = unsafe { Some(OwnedFd::from_raw_fd(1)) };
    let _ = OwnedFd::into_raw_fd;
}
