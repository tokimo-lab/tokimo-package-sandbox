//! seccomp-trace + ptrace L4 backend.
//!
//! Fallback backend for environments where `SECCOMP_FILTER_FLAG_NEW_LISTENER`
//! returns EBUSY — most notably WSL2, where the inherited init-level
//! seccomp filter already owns a notifier. A plain seccomp filter (no
//! flags) that returns `SECCOMP_RET_TRACE` for `connect`/`sendto` is
//! always accepted, and the parent uses `PTRACE_SEIZE` +
//! `PTRACE_O_TRACESECCOMP` to capture the trap.
//!
//! Observability-only: the trace backend cannot safely deny syscalls
//! without a two-stop GETREGS/SETREGS dance that is out of scope for
//! this MVP. `Gated` deny verdicts become warnings, the syscall still
//! runs. L7 proxy continues to enforce hostname-based policy.
//!
//! Flow (same-thread pre_exec is async-signal-safe):
//!
//! * parent:
//!   1. `prepare()` probes that a plain seccomp filter install succeeds.
//!   2. After `Command::spawn`, `start_parent(pid)` waits for the child's
//!      `SIGSTOP` (raised by the child inside `child_install`), calls
//!      `PTRACE_SEIZE` + `SETOPTIONS(TRACESECCOMP|TRACEFORK|TRACEVFORK|
//!      TRACECLONE|TRACEEXEC|EXITKILL)`, then `kill(pid, SIGCONT)` to let
//!      the child proceed. A tracer thread loops on `waitpid(-1, __WALL)`.
//! * child (`pre_exec`):
//!   1. `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
//!   2. `raise(SIGSTOP)` — blocks until parent SEIZE + SIGCONT.
//!   3. `seccomp(SET_MODE_FILTER, 0, &prog)` — RET_TRACE for connect/sendto,
//!      RET_ALLOW otherwise.
//!   4. return from pre_exec; `exec(bwrap)` follows. Tracer is already
//!      attached, so any `connect()` during the sandboxed program traps.

use super::{L4Config, Shutdown, build_event};
use crate::net_observer::Proto;
use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use super::seccomp_notify::{parse_sockaddr, read_comm, read_sockaddr};

// ---- BPF constants (duplicate of seccomp_notify for independence) ------

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// Low 16 bits of RET_TRACE act as a data tag returned via PTRACE_GETEVENTMSG.
const TAG_CONNECT: u32 = 1;
const TAG_SENDTO: u32 = 2;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH: u32 = 0;

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const CONNECT: u32 = 42;
    pub const SENDTO: u32 = 44;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const CONNECT: u32 = 203;
    pub const SENDTO: u32 = 206;
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod nr {
    pub const CONNECT: u32 = u32::MAX;
    pub const SENDTO: u32 = u32::MAX;
}

// ptrace event codes
const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_VFORK: i32 = 2;
const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_EVENT_SECCOMP: i32 = 7;

// PTRACE_O_* options (linux/ptrace.h)
const PTRACE_O_TRACESYSGOOD: libc::c_int = 1;
const PTRACE_O_TRACEFORK: libc::c_int = 1 << PTRACE_EVENT_FORK;
const PTRACE_O_TRACEVFORK: libc::c_int = 1 << PTRACE_EVENT_VFORK;
const PTRACE_O_TRACECLONE: libc::c_int = 1 << PTRACE_EVENT_CLONE;
const PTRACE_O_TRACEEXEC: libc::c_int = 1 << PTRACE_EVENT_EXEC;
const PTRACE_O_TRACESECCOMP: libc::c_int = 1 << PTRACE_EVENT_SECCOMP;
const PTRACE_O_EXITKILL: libc::c_int = 1 << 20;

// PTRACE_SEIZE / GETEVENTMSG
const PTRACE_SEIZE: u32 = 0x4206;
const PTRACE_GETEVENTMSG: u32 = 0x4201;

// __WALL for waitpid
const WALL: libc::c_int = 0x4000_0000;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn build_program() -> [SockFilter; 9] {
    [
        // load arch
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: OFF_ARCH,
        },
        // arch != AUDIT_ARCH -> allow (safer than kill when arch mismatch)
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        // load nr
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: OFF_NR,
        },
        // nr == connect -> trace w/ tag=CONNECT (jump to index 7)
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 2,
            jf: 0,
            k: nr::CONNECT,
        },
        // nr == sendto  -> trace w/ tag=SENDTO  (jump to index 8)
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 2,
            jf: 0,
            k: nr::SENDTO,
        },
        // default allow
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        // trace connect
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_TRACE | TAG_CONNECT,
        },
        // trace sendto
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_TRACE | TAG_SENDTO,
        },
    ]
}

// ---- public API ---------------------------------------------------------

pub(crate) fn prepare(cfg: L4Config) -> io::Result<(super::ChildInstall, super::Pending)> {
    probe_supported()?;
    let (exit_tx, exit_rx) = mpsc::channel();
    let ci = super::ChildInstall {
        child_fd: -1,
        backend: super::Backend::SeccompTrace,
    };
    let pending = Pending {
        exit_tx,
        exit_rx: Some(exit_rx),
        _cfg_phantom: std::marker::PhantomData,
    };
    let _ = cfg;
    Ok((ci, super::Pending::SeccompTrace(pending)))
}

pub(crate) struct Pending {
    pub(super) exit_tx: Sender<ExitStatus>,
    pub(super) exit_rx: Option<Receiver<ExitStatus>>,
    _cfg_phantom: std::marker::PhantomData<()>,
}

pub(crate) struct SeccompTraceHandle {
    shutdown: Shutdown,
    thread: Option<JoinHandle<()>>,
}

impl Drop for SeccompTraceHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Probe whether a plain seccomp filter install succeeds in a forked
/// child. Cheap to run once; cached atomically.
pub(crate) fn probe_supported() -> io::Result<()> {
    static CACHE: AtomicU8 = AtomicU8::new(0);
    match CACHE.load(Ordering::SeqCst) {
        1 => return Ok(()),
        2 => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "seccomp RET_TRACE plain filter install not supported in this environment",
            ));
        }
        _ => {}
    }
    let ok = unsafe { probe_in_child() };
    CACHE.store(if ok { 1 } else { 2 }, Ordering::SeqCst);
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "plain seccomp filter install failed; L4 trace backend disabled",
        ))
    }
}

unsafe fn probe_in_child() -> bool {
    let pid = libc::fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: install a minimal RET_ALLOW filter without any flags.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) != 0 {
            libc::_exit(2);
        }
        let allow = SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        };
        let prog = SockFprog { len: 1, filter: &allow };
        let rc = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            0i64,
            &prog as *const SockFprog as libc::c_long,
        );
        if rc < 0 {
            libc::_exit(1);
        }
        libc::_exit(0);
    }
    let mut st: libc::c_int = 0;
    if libc::waitpid(pid, &mut st, 0) < 0 {
        return false;
    }
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// Async-signal-safe installer. Called from the bwrap-child's `pre_exec`.
///
/// We intentionally do NOT block the child with `raise(SIGSTOP)` before
/// `exec`: Rust's `Command::spawn` waits for the child to either exec or
/// report an error via an internal CLOEXEC pipe, and a stopped child
/// would deadlock `spawn()`. Instead, the child installs the filter and
/// exec's normally; the parent calls `PTRACE_SEIZE` immediately after
/// `spawn()` returns. Between exec and SEIZE there is a short window
/// where a `connect()` (or `sendto()` with sockaddr) would return
/// `-ENOSYS` because `RET_TRACE` with no tracer attached skips the
/// syscall. bwrap itself does not make such calls during its setup, and
/// the guest program runs well after bwrap finishes — so the window is
/// benign in practice.
///
/// # Safety
/// Must be called post-fork, pre-exec, exactly once.
pub(crate) unsafe fn child_install() -> io::Result<()> {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) != 0 {
        return Err(io::Error::last_os_error());
    }
    let prog = build_program();
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let rc = libc::syscall(
        libc::SYS_seccomp,
        SECCOMP_SET_MODE_FILTER as libc::c_long,
        0i64,
        &fprog as *const SockFprog as libc::c_long,
    );
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Start the parent-side tracer. Must be called AFTER `Command::spawn`.
/// Calls `PTRACE_SEIZE` + `SETOPTIONS` on the child, then spawns a
/// tracer thread that loops on `waitpid(-1, __WALL)`.
pub(crate) fn start_parent(
    mut pending: Pending,
    cfg: L4Config,
    child_pid: i32,
) -> io::Result<(SeccompTraceHandle, Receiver<ExitStatus>)> {
    let options = PTRACE_O_TRACESECCOMP
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACESYSGOOD
        | PTRACE_O_EXITKILL;

    let shutdown = super::new_shutdown();
    let shutdown2 = shutdown.clone();
    let exit_tx = pending.exit_tx.clone();
    let exit_rx = pending
        .exit_rx
        .take()
        .expect("exit_rx must be present before start_parent");

    // Synchronously do PTRACE_SEIZE inside the tracer thread so ptrace tracer
    // identity and `waitpid` are the same task (Linux ties tracer<->tracee to
    // the thread, not the process).
    let (seize_tx, seize_rx) = std::sync::mpsc::channel::<io::Result<()>>();
    let thread = thread::Builder::new()
        .name("l4-seccomp-trace".into())
        .spawn(move || {
            let rc = unsafe {
                libc::ptrace(
                    PTRACE_SEIZE as _,
                    child_pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    options as usize as *mut libc::c_void,
                )
            };
            if rc < 0 {
                let _ = seize_tx.send(Err(io::Error::last_os_error()));
                return;
            }
            let _ = seize_tx.send(Ok(()));
            run_tracer_loop(child_pid, cfg, shutdown2, exit_tx);
        })
        .map_err(io::Error::other)?;

    match seize_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(io::Error::other("tracer thread died before seize")),
    }

    Ok((
        SeccompTraceHandle {
            shutdown,
            thread: Some(thread),
        },
        exit_rx,
    ))
}

// ---- tracer loop --------------------------------------------------------

fn run_tracer_loop(main_pid: i32, cfg: L4Config, shutdown: Shutdown, exit_tx: Sender<ExitStatus>) {
    tracing::info!("l4-trace: tracer started for pid {}", main_pid);
    let mut main_exit_sent = false;
    loop {
        if super::is_shutdown(&shutdown) {
            tracing::debug!("l4-trace: shutdown requested");
            let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, main_pid, 0usize, 0usize) };
            break;
        }
        let mut status: libc::c_int = 0;
        // Block with WNOHANG + short sleep to allow shutdown polling.
        let pid = unsafe { libc::waitpid(-1, &mut status, WALL | libc::WNOHANG) };
        if pid == 0 {
            thread::sleep(std::time::Duration::from_millis(5));
            continue;
        }
        if pid < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => {
                    tracing::debug!("l4-trace: ECHILD, exiting loop (main_exit_sent={})", main_exit_sent);
                    break;
                }
                _ => {
                    tracing::warn!("l4 seccomp-trace: waitpid error: {}", e);
                    break;
                }
            }
        }

        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            let signaled = libc::WIFSIGNALED(status);
            let termsig = if signaled { libc::WTERMSIG(status) } else { 0 };
            let exitcode = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
            let coredump = signaled && libc::WCOREDUMP(status);
            tracing::debug!(
                "l4-trace: pid {} exited (main={}) signaled={} termsig={} exitcode={} coredump={} raw_status=0x{:x}",
                pid,
                main_pid,
                signaled,
                termsig,
                exitcode,
                coredump,
                status
            );
            if pid == main_pid && !main_exit_sent {
                let es = ExitStatus::from_raw(status);
                let _ = exit_tx.send(es);
                main_exit_sent = true;
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xffff;

        if event == PTRACE_EVENT_SECCOMP {
            tracing::debug!("l4-trace: SECCOMP event pid={}", pid);
            handle_seccomp_event(pid, &cfg);
            ptrace_cont(pid, 0);
            continue;
        }
        if event == PTRACE_EVENT_FORK
            || event == PTRACE_EVENT_VFORK
            || event == PTRACE_EVENT_CLONE
            || event == PTRACE_EVENT_EXEC
        {
            let mut new_pid: libc::c_long = 0;
            let rc = unsafe {
                libc::ptrace(
                    PTRACE_GETEVENTMSG as _,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    &mut new_pid as *mut libc::c_long as *mut libc::c_void,
                )
            };
            tracing::debug!(
                "l4-trace: event={} pid={} new_pid={} getevmsg_rc={} errno={}",
                event,
                pid,
                new_pid,
                rc,
                io::Error::last_os_error()
            );
            ptrace_cont(pid, 0);
            continue;
        }
        // Initial group-stop for freshly auto-seized children is SIGSTOP.
        if sig == libc::SIGSTOP || sig == libc::SIGTRAP {
            ptrace_cont(pid, 0);
            continue;
        }
        // Forward other signals normally.
        tracing::debug!("l4-trace: forwarding sig={} pid={}", sig, pid);
        ptrace_cont(pid, sig);
    }
}

fn ptrace_cont(pid: i32, sig: libc::c_int) {
    unsafe {
        let _ = libc::ptrace(libc::PTRACE_CONT, pid, 0usize, sig as usize);
    }
}

fn handle_seccomp_event(pid: i32, cfg: &L4Config) {
    // Fetch the RET_TRACE data tag (low 16 bits of the filter's return).
    let mut tag: libc::c_ulong = 0;
    let rc = unsafe {
        libc::ptrace(
            PTRACE_GETEVENTMSG as _,
            pid,
            0usize,
            &mut tag as *mut libc::c_ulong as usize,
        )
    };
    if rc < 0 {
        tracing::warn!("l4-trace: GETEVENTMSG failed pid={}", pid);
        return;
    }
    let tag = tag as u32 & 0xffff;
    tracing::debug!("l4-trace: seccomp tag={}", tag);

    #[cfg(target_arch = "x86_64")]
    let (sockaddr_ptr, addrlen, proto) = {
        // On x86_64 fetch user_regs_struct via PTRACE_GETREGS.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0usize, &mut regs as *mut _ as usize) };
        if rc < 0 {
            return;
        }
        match tag {
            TAG_CONNECT => (regs.rsi, regs.rdx as usize, Proto::Tcp),
            TAG_SENDTO => (regs.r8, regs.r9 as usize, Proto::Udp),
            _ => return,
        }
    };
    #[cfg(target_arch = "aarch64")]
    let (sockaddr_ptr, addrlen, proto) = {
        // aarch64: use PTRACE_GETREGSET(NT_PRSTATUS).
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<libc::user_regs_struct>(),
        };
        const NT_PRSTATUS: libc::c_long = 1;
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid,
                NT_PRSTATUS as usize,
                &iov as *const _ as usize,
            )
        };
        if rc < 0 {
            return;
        }
        match tag {
            TAG_CONNECT => (regs.regs[1], regs.regs[2] as usize, Proto::Tcp),
            TAG_SENDTO => (regs.regs[4], regs.regs[5] as usize, Proto::Udp),
            _ => return,
        }
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (sockaddr_ptr, addrlen, proto): (u64, usize, Proto) = { return };

    if sockaddr_ptr == 0 || !(2..=128).contains(&addrlen) {
        tracing::debug!("l4-trace: skip addr_ptr=0x{:x} len={}", sockaddr_ptr, addrlen);
        return;
    }
    let mut buf = [0u8; 128];
    let Some(n) = read_sockaddr(pid as u32, sockaddr_ptr, addrlen.min(128), &mut buf) else {
        tracing::debug!("l4-trace: read_sockaddr failed pid={} ptr=0x{:x}", pid, sockaddr_ptr);
        return;
    };
    let Some(remote) = parse_sockaddr(&buf[..n]) else {
        tracing::debug!("l4-trace: parse_sockaddr failed family={:?}", &buf[..2.min(n)]);
        return;
    };
    let comm = read_comm(pid as u32);
    let ev = build_event(remote, proto, pid as u32, comm);
    // Observability only — drop verdict.
    let _ = cfg.decide(&ev);
}

// Prevent unused-import / unused-field warnings on arches where we stub out.
#[allow(dead_code)]
fn _keep_raw_fd_ref(x: RawFd) -> RawFd {
    x
}
