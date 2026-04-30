//! Seccomp-notify L4 backend.
//!
//! Design (summary — see `docs/network-observability.md` and session plan):
//!
//! 1. Parent creates a `socketpair(AF_UNIX, SOCK_SEQPACKET)` (`sp_parent`,
//!    `sp_child`). `sp_child` is dup'd into the child without `CLOEXEC` so
//!    it survives `exec(bwrap)`.
//! 2. In pre_exec (runs in the bwrap-child process, post-fork pre-exec):
//!    a. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — required for non-root seccomp.
//!    b. `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
//!       &prog)` → returns `listener_fd`.
//!    c. `sendmsg SCM_RIGHTS(listener_fd)` over `sp_child`.
//!    d. close `listener_fd`, close `sp_child`.
//!    e. fall through — bwrap then sets its own seccomp on top.
//! 3. Parent `recvmsg SCM_RIGHTS` on `sp_parent` → owns `listener_fd`.
//! 4. Parent spawns a thread looping `ioctl(NOTIF_RECV)` / `NOTIF_SEND`.
//!    For each notify: `ID_VALID` → `process_vm_readv` sockaddr → build
//!    `NetEvent` → sink verdict → respond `CONTINUE` (Allow) or `-EPERM`
//!    (Deny).
//!
//! Filter traps `connect` and `sendto` on x86_64 / aarch64 only. `sendmsg`
//! is deliberately NOT trapped: our own bootstrap `sendmsg(SCM_RIGHTS)`
//! would deadlock.

use super::{L4Config, Shutdown, build_event, close_fd, new_shutdown};
use crate::host::net_observer::{Proto, Verdict};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;
use std::thread::{self, JoinHandle};

// ---- seccomp / BPF constants --------------------------------------------

// BPF instruction opcodes (from linux/filter.h)
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// offset into seccomp_data
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

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
    // Fallback: disable L4 trap on unsupported arches.
    pub const CONNECT: u32 = u32::MAX;
    pub const SENDTO: u32 = u32::MAX;
}

// ioctl numbers, hand-computed (see _IOC layout).
// SECCOMP_IOCTL_NOTIF_RECV     = _IOWR('!', 0, 80) = 0xc050_2100
// SECCOMP_IOCTL_NOTIF_SEND     = _IOWR('!', 1, 24) = 0xc018_2101
// SECCOMP_IOCTL_NOTIF_ID_VALID = _IOW ('!', 2, 8)  = 0x4008_2102
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// ---- on-the-wire structs ------------------------------------------------

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// ---- filter program -----------------------------------------------------

// Program layout:
//   ld [arch]
//   jeq AUDIT_ARCH, 1, 0     ; match arch → skip next
//   ret ALLOW                ; wrong arch → allow (do not trap)
//   ld [nr]
//   jeq NR_CONNECT, 0, 1     ; if connect → jump to ret USER_NOTIF (below)
//   ja  +1                   ; (emulated via jeq-false offset to sendto check)
//   (No — we use independent jeq for each with ret embedded between)
//
// Concrete (8 insns):
//   0: BPF_LD|W|ABS k=4    ; A = arch
//   1: BPF_JEQ k=AUDIT_ARCH jt=1 jf=0 ; arch match → pc+1+1
//   2: BPF_RET k=ALLOW
//   3: BPF_LD|W|ABS k=0    ; A = nr
//   4: BPF_JEQ k=CONNECT jt=2 jf=0    ; if connect → pc+1+2 = 7
//   5: BPF_JEQ k=SENDTO  jt=1 jf=0    ; if sendto → pc+1+1 = 7
//   6: BPF_RET k=ALLOW
//   7: BPF_RET k=USER_NOTIF
const PROG_LEN: u16 = 8;

fn build_program() -> [SockFilter; 8] {
    [
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: OFF_ARCH,
        },
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
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: OFF_NR,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 2,
            jf: 0,
            k: nr::CONNECT,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: nr::SENDTO,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
    ]
}

// ---- parent-side preparation --------------------------------------------

pub(crate) struct Pending {
    /// Parent's end of the socketpair. Used to receive the listener fd via
    /// SCM_RIGHTS after the child runs pre_exec.
    pub sp_parent: RawFd,
    /// Kept alive until `start_parent` so the child's end isn't
    /// prematurely closed.
    #[allow(dead_code)]
    pub sp_child_dup: RawFd,
    pub shutdown: Shutdown,
}

pub(crate) fn prepare(cfg: L4Config) -> io::Result<(super::ChildInstall, super::Pending)> {
    // Probe: does this host even allow SECCOMP_FILTER_FLAG_NEW_LISTENER?
    // Some environments (e.g. WSL2 with inherited seccomp filters, some
    // container runtimes) reject it with EBUSY. Rather than have
    // `Command::spawn` fail opaquely, short-circuit here.
    probe_new_listener_supported()?;

    let mut sv: [RawFd; 2] = [-1, -1];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let (sp_parent, sp_child) = (sv[0], sv[1]);
    let _ = cfg;
    Ok((
        super::ChildInstall {
            child_fd: sp_child,
            backend: super::Backend::SeccompNotify,
        },
        super::Pending::SeccompNotify(Pending {
            sp_parent,
            sp_child_dup: sp_child,
            shutdown: new_shutdown(),
        }),
    ))
}

/// Fork a tiny child, attempt to install a seccomp filter with
/// `NEW_LISTENER`, and exit with status 0 on success, 1 on failure. Results
/// are cached after first probe.
fn probe_new_listener_supported() -> io::Result<()> {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHE: AtomicU8 = AtomicU8::new(0); // 0=unknown, 1=yes, 2=no

    match CACHE.load(Ordering::SeqCst) {
        1 => return Ok(()),
        2 => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "seccomp NEW_LISTENER not available on this host \
                 (likely inherited seccomp filter or WSL2 / container runtime); \
                 L4 observer disabled. L7 proxy observer is unaffected.",
            ));
        }
        _ => {}
    }

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // Child: try to install. Use a tiny RET_ALLOW filter.
            let allow = SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            };
            let prog = SockFprog { len: 1, filter: &allow };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) != 0 {
                libc::_exit(2);
            }
            let r = libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &prog as *const SockFprog as *const libc::c_void,
            );
            if r < 0 {
                libc::_exit(1);
            }
            libc::_exit(0);
        }
        // Parent: wait.
        let mut status: libc::c_int = 0;
        let w = libc::waitpid(pid, &mut status, 0);
        if w < 0 {
            return Err(io::Error::last_os_error());
        }
        let ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        CACHE.store(if ok { 1 } else { 2 }, Ordering::SeqCst);
        if ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "seccomp NEW_LISTENER probe failed (EBUSY or equivalent); \
                 L4 observer disabled. L7 proxy observer is unaffected.",
            ))
        }
    }
}

// ---- child-side (pre_exec) installer ------------------------------------

/// Runs in the bwrap-child's pre_exec. **async-signal-safe only.** No heap
/// allocation, no Rust synchronisation primitives. Returns `Ok` on success;
/// on failure, returns the errno so `Command::spawn` fails cleanly.
pub(crate) unsafe fn child_install(sp_child: RawFd) -> io::Result<()> {
    unsafe {
        // 1. Clear CLOEXEC on the child-end socket so sendmsg below works AFTER
        //    exec-safety — actually we send BEFORE exec, so CLOEXEC is moot.
        //    Still clear it for belt-and-braces in case bwrap itself forks.
        let flags = libc::fcntl(sp_child, libc::F_GETFD, 0);
        if flags >= 0 {
            libc::fcntl(sp_child, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }

        // 2. NO_NEW_PRIVS is required for non-root seccomp filters.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) != 0 {
            return Err(io::Error::last_os_error());
        }

        // 3. Install the filter with NEW_LISTENER. Filter program on the stack.
        let prog = build_program();
        let fprog = SockFprog {
            len: PROG_LEN,
            filter: prog.as_ptr(),
        };
        let listener_fd = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFprog as *const libc::c_void,
        );
        if listener_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let listener_fd = listener_fd as RawFd;

        // 4. sendmsg the listener fd via SCM_RIGHTS over sp_child.
        //    Layout manually — no CMSG_* macros needed given fixed size.
        //
        //    struct cmsghdr { cmsg_len; cmsg_level; cmsg_type; } + [fd]
        //
        //    We build:
        //      iov = single-byte payload '!'
        //      control = cmsg_len=CMSG_LEN(sizeof(int))
        //                cmsg_level=SOL_SOCKET cmsg_type=SCM_RIGHTS
        //                data=listener_fd
        let payload: u8 = b'!';
        let mut iov = libc::iovec {
            iov_base: &payload as *const u8 as *mut libc::c_void,
            iov_len: 1,
        };
        // cmsg buffer: enough for one int fd. Over-size safely.
        let mut cbuf: [u8; 64] = [0; 64];
        let cmsg = cbuf.as_mut_ptr() as *mut libc::cmsghdr;
        (*cmsg).cmsg_len = libc_cmsg_len(mem::size_of::<libc::c_int>()) as _;
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        let data_ptr = libc_cmsg_data(cmsg) as *mut libc::c_int;
        *data_ptr = listener_fd as libc::c_int;
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = std::ptr::null_mut();
        msg.msg_namelen = 0;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc_cmsg_space(mem::size_of::<libc::c_int>()) as _;
        let sent = libc::sendmsg(sp_child, &msg, 0);
        if sent < 0 {
            let e = io::Error::last_os_error();
            libc::close(listener_fd);
            return Err(e);
        }

        // 5. Child no longer needs listener or socketpair. Parent owns them.
        libc::close(listener_fd);
        libc::close(sp_child);
        Ok(())
    }
}

// glibc CMSG_* macros recomputed without allocation.
#[inline]
fn libc_cmsg_align(len: usize) -> usize {
    let sz = mem::size_of::<libc::size_t>();
    (len + sz - 1) & !(sz - 1)
}
#[inline]
fn libc_cmsg_len(data_len: usize) -> libc::size_t {
    (libc_cmsg_align(mem::size_of::<libc::cmsghdr>()) + data_len) as libc::size_t
}
#[inline]
fn libc_cmsg_space(data_len: usize) -> libc::size_t {
    (libc_cmsg_align(mem::size_of::<libc::cmsghdr>()) + libc_cmsg_align(data_len)) as libc::size_t
}
#[inline]
unsafe fn libc_cmsg_data(cmsg: *const libc::cmsghdr) -> *const u8 {
    unsafe { (cmsg as *const u8).add(libc_cmsg_align(mem::size_of::<libc::cmsghdr>())) }
}

// ---- parent-side listener -----------------------------------------------

pub(crate) struct SeccompNotifyHandle {
    shutdown: Shutdown,
    listener_fd: RawFd,
    thread: Option<JoinHandle<()>>,
}

impl Drop for SeccompNotifyHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        // Close listener_fd from under the ioctl to wake the loop.
        close_fd(self.listener_fd);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

pub(crate) fn start_parent(pending: Pending, cfg: L4Config) -> io::Result<SeccompNotifyHandle> {
    // Receive listener fd from child via SCM_RIGHTS.
    let listener_fd = recv_listener_fd(pending.sp_parent)?;
    // sp_parent no longer needed.
    close_fd(pending.sp_parent);

    let shutdown = pending.shutdown.clone();
    let shutdown_thread = shutdown.clone();
    let thread = thread::Builder::new()
        .name("tokimo-l4-notify".into())
        .spawn(move || run_notify_loop(listener_fd, cfg, shutdown_thread))
        .map_err(io::Error::other)?;

    Ok(SeccompNotifyHandle {
        shutdown,
        listener_fd,
        thread: Some(thread),
    })
}

fn recv_listener_fd(sp_parent: RawFd) -> io::Result<RawFd> {
    let mut payload: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut payload as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cbuf: [u8; 64] = [0; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;
    let n = unsafe { libc::recvmsg(sp_parent, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // Extract first cmsg.
    let cmsg = cbuf.as_ptr() as *const libc::cmsghdr;
    unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other("expected SCM_RIGHTS from pre_exec"));
        }
        let data_ptr = libc_cmsg_data(cmsg) as *const libc::c_int;
        let fd = *data_ptr as RawFd;
        if fd < 0 {
            return Err(io::Error::other("bad listener fd"));
        }
        Ok(fd)
    }
}

fn run_notify_loop(listener_fd: RawFd, cfg: L4Config, shutdown: Shutdown) {
    loop {
        if super::is_shutdown(&shutdown) {
            return;
        }
        let mut notif: SeccompNotif = unsafe { mem::zeroed() };
        let rc = unsafe {
            libc::ioctl(
                listener_fd,
                SECCOMP_IOCTL_NOTIF_RECV as _,
                &mut notif as *mut SeccompNotif,
            )
        };
        if rc < 0 {
            // EINTR → retry; everything else (listener closed on drop) → exit.
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
        handle_one(listener_fd, &notif, &cfg);
    }
}

fn handle_one(listener_fd: RawFd, notif: &SeccompNotif, cfg: &L4Config) {
    // Extract sockaddr pointer + len from syscall args.
    let syscall_nr = notif.data.nr as u32;
    let (addr_arg_idx, len_arg_idx) = match syscall_nr {
        n if n == nr::CONNECT => (1usize, 2usize),
        n if n == nr::SENDTO => (4usize, 5usize),
        _ => {
            // Shouldn't happen given filter; allow-continue.
            let _ = respond_continue(listener_fd, notif.id);
            return;
        }
    };
    let addr_ptr = notif.data.args[addr_arg_idx];
    let addr_len = notif.data.args[len_arg_idx] as usize;
    if addr_ptr == 0 || addr_len == 0 {
        // E.g. UDP send with no dest — pass.
        let _ = respond_continue(listener_fd, notif.id);
        return;
    }

    // Read the sockaddr from the target via process_vm_readv. Cap size.
    let mut buf = [0u8; 128];
    let n = read_sockaddr(notif.pid, addr_ptr, addr_len.min(buf.len()), &mut buf);
    if n.is_none() {
        let _ = respond_continue(listener_fd, notif.id);
        return;
    }
    let n = n.unwrap();

    // Re-validate notif id AFTER the read: the target could have been
    // killed and its pid reused, which would make our read data stale.
    if !notif_id_valid(listener_fd, notif.id) {
        // Target is gone; nothing to respond to.
        return;
    }

    let sa = parse_sockaddr(&buf[..n]);
    let proto = if syscall_nr == nr::SENDTO {
        Proto::Udp
    } else {
        Proto::Tcp
    };

    if let Some(remote) = sa {
        let comm = read_comm(notif.pid);
        let ev = build_event(remote, proto, notif.pid, comm);
        let verdict = cfg.decide(&ev);
        match verdict {
            Verdict::Allow => {
                let _ = respond_continue(listener_fd, notif.id);
            }
            Verdict::Deny(_reason) => {
                // Return -EPERM to the guest.
                let _ = respond_errno(listener_fd, notif.id, libc::EPERM);
            }
        }
    } else {
        // AF_UNIX or unrecognised — allow without firing an event.
        let _ = respond_continue(listener_fd, notif.id);
    }
}

fn respond_continue(listener_fd: RawFd, id: u64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_SEND as _,
            &resp as *const SeccompNotifResp,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn respond_errno(listener_fd: RawFd, id: u64, errno: i32) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_SEND as _,
            &resp as *const SeccompNotifResp,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn notif_id_valid(listener_fd: RawFd, id: u64) -> bool {
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &id as *const u64) };
    rc == 0
}

/// Read `len` bytes from the target process's address space. Returns
/// `None` on failure (Yama ptrace restriction, target dead, etc.).
pub(super) fn read_sockaddr(pid: u32, remote_ptr: u64, len: usize, out: &mut [u8]) -> Option<usize> {
    let local = libc::iovec {
        iov_base: out.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: remote_ptr as *mut libc::c_void,
        iov_len: len,
    };
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        // Fallback: /proc/<pid>/mem pread.
        read_via_proc_mem(pid, remote_ptr, len, out)
    } else {
        Some(n as usize)
    }
}

fn read_via_proc_mem(pid: u32, remote_ptr: u64, len: usize, out: &mut [u8]) -> Option<usize> {
    use std::os::unix::fs::FileExt;
    let path = format!("/proc/{}/mem", pid);
    let f = std::fs::OpenOptions::new().read(true).open(&path).ok()?;
    let n = f.read_at(&mut out[..len], remote_ptr).ok()?;
    if n == 0 { None } else { Some(n) }
}

pub(super) fn read_comm(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    Some(s.trim_end_matches('\n').to_string())
}

pub(super) fn parse_sockaddr(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family as libc::c_int {
        libc::AF_INET => {
            if buf.len() < mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // sockaddr_in layout: sin_family(2), sin_port(2, BE),
            // sin_addr(4, BE), sin_zero(8).
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            if buf.len() < mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let _flowinfo = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            let scope = u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]);
            let ip = Ipv6Addr::from(octets);
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
        }
        _ => {
            let _ = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // silence unused import in some cfgs
            None
        }
    }
}

// ---- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_has_expected_length() {
        let p = build_program();
        assert_eq!(p.len() as u16, PROG_LEN);
    }

    #[test]
    fn parse_v4_sockaddr() {
        // AF_INET (2), port 443 (0x01bb BE), 1.1.1.1
        let mut buf = [0u8; 16];
        // family is native-endian u16 in sockaddr_*.
        let f = (libc::AF_INET as u16).to_ne_bytes();
        buf[0] = f[0];
        buf[1] = f[1];
        buf[2] = 0x01;
        buf[3] = 0xbb;
        buf[4..8].copy_from_slice(&[1, 1, 1, 1]);
        let sa = parse_sockaddr(&buf).unwrap();
        assert_eq!(sa.port(), 443);
        assert_eq!(sa.ip().to_string(), "1.1.1.1");
    }

    #[test]
    fn cmsg_sizes_sane() {
        let l = libc_cmsg_len(4);
        let s = libc_cmsg_space(4);
        assert!(l as usize >= mem::size_of::<libc::cmsghdr>() + 4);
        assert!((s as usize) >= l as usize);
    }
}
