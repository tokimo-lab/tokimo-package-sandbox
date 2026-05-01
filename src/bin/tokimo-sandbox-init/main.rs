//! `tokimo-sandbox-init` — PID 1 inside the sandbox container.
//!
//! Linux-only binary. On other platforms this binary is a no-op stub.
//!
//! ## Transports
//!
//! - **Unix SEQPACKET** (default): listens on a SEQPACKET Unix socket at the
//!   path in `TOKIMO_SANDBOX_CONTROL_SOCK` (default
//!   `/run/tk-sandbox/control.sock`). Used by the Linux bwrap backend.
//! - **VSOCK stream** (opt-in): if `TOKIMO_SANDBOX_VSOCK_PORT` is set, binds
//!   on AF_VSOCK with that port instead. Uses length-prefixed stream framing
//!   (`init_wire` stream functions). Used by the macOS VZ backend.

#[cfg(target_os = "linux")]
mod child;
#[cfg(target_os = "linux")]
mod pty;
#[cfg(target_os = "linux")]
mod server;

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use nix::sys::signal::{SigSet, Signal};
#[cfg(target_os = "linux")]
use nix::sys::signalfd::{SfdFlags, SignalFd};
#[cfg(target_os = "linux")]
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, UnixAddr, VsockAddr, bind, connect, listen, socket,
};
#[cfg(target_os = "linux")]
use nix::unistd::getpid;

#[cfg(target_os = "linux")]
const ENV_CONTROL_SOCK: &str = "TOKIMO_SANDBOX_CONTROL_SOCK";
#[cfg(target_os = "linux")]
const DEFAULT_CONTROL_SOCK: &str = "/run/tk-sandbox/control.sock";
#[cfg(target_os = "linux")]
const ENV_VSOCK_PORT: &str = "TOKIMO_SANDBOX_VSOCK_PORT";
/// If set, use stdin/stdout (the virtio serial console) for the control
/// channel instead of a VSOCK or Unix socket. Used when the kernel lacks
/// AF_VSOCK support.
#[cfg(target_os = "linux")]
const ENV_SERIAL_MODE: &str = "TOKIMO_SANDBOX_SERIAL_MODE";

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    // Subcommand: load kernel modules from the rootfs.
    //
    // Usage: tokimo-sandbox-init --load-modules <module-path> [<module-path>...]
    //
    // Each module-path is the absolute path to a .ko file inside the
    // rootfs. The shim uses this to bring up vsock + 9p before mounting
    // the workspace, since a minimal Ubuntu base has no `modprobe`.
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--load-modules") {
        let mut failed = 0usize;
        for path in &args[2..] {
            match load_kernel_module(path) {
                Ok(()) => eprintln!("[tokimo-init] loaded {path}"),
                Err(e) => {
                    eprintln!("[tokimo-init] WARN {path}: {e}");
                    failed += 1;
                }
            }
        }
        return if failed > 0 {
            ExitCode::from(1)
        } else {
            ExitCode::from(0)
        };
    }

    if let Err(e) = run() {
        eprintln!("[tokimo-sandbox-init] fatal: {e}");
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

/// Load a kernel module from a file path using the `finit_module(2)`
/// syscall. Idempotent: returns `Ok` if the module is already loaded
/// (`EEXIST`).
#[cfg(target_os = "linux")]
fn load_kernel_module(path: &str) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let empty = CString::new("").unwrap();
    let r = unsafe { libc::syscall(libc::SYS_finit_module, f.as_raw_fd(), empty.as_ptr(), 0i32) };
    if r == 0 {
        return Ok(());
    }
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::EEXIST {
        return Ok(());
    }
    Err(format!("finit_module errno={errno}"))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tokimo-sandbox-init is Linux-only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let pid = getpid();
    if pid.as_raw() != 1 {
        return Err(format!("init must be PID 1 (got {}); host forgot --as-pid-1", pid));
    }

    // VM mode (macOS VZ / Windows HCS) starts init on a bare Linux kernel
    // with nothing mounted, so init must mount /proc /sys /dev itself.
    // bwrap mode (Linux) already mounted those before exec'ing init via
    // `--proc /proc --dev /dev`, and on modern kernels (Ubuntu 24.04+) a
    // second `mount(2)` of procfs from inside an unprivileged userns is
    // refused with EPERM (not EBUSY), so we cannot attempt it blindly.
    let is_vm_mode = env::var(ENV_VSOCK_PORT).is_ok() || env::var(ENV_SERIAL_MODE).is_ok();
    // In `serial=stdio` mode (legacy Windows HCS) or `pre_chrooted=1` mode
    // (current Windows HCS vsock path) init.sh has already done the
    // mounts + chroot before exec'ing us; skip the VM-mode setup.
    let serial_stdio = env::var(ENV_SERIAL_MODE).as_deref() == Ok("stdio");
    let pre_chrooted = env::var("TOKIMO_SANDBOX_PRE_CHROOTED").as_deref() == Ok("1");
    if is_vm_mode && !serial_stdio && !pre_chrooted {
        for (src, tgt, fstype) in &[
            ("proc", "/proc", "proc"),
            ("sysfs", "/sys", "sysfs"),
            ("devtmpfs", "/dev", "devtmpfs"),
        ] {
            match mount_fs(src, tgt, fstype, 0, "") {
                Ok(()) => {}
                Err(e) if e.contains("Resource busy") || e.contains("16") => {
                    eprintln!("[tokimo-sandbox-init] {tgt} already mounted, skipping");
                }
                Err(e) => return Err(e),
            }
        }

        // Mount virtiofs (VM mode only).
        let _ = std::fs::create_dir_all("/mnt/work");
        match mount_fs("work", "/mnt/work", "virtiofs", 0, "") {
            Ok(()) => eprintln!("[tokimo-sandbox-init] mounted virtiofs at /mnt/work"),
            Err(e) if e.contains("Resource busy") || e.contains("16") => {
                eprintln!("[tokimo-sandbox-init] virtiofs already mounted");
            }
            Err(e) => {
                eprintln!("[tokimo-sandbox-init] WARNING: virtiofs mount failed: {e}");
            }
        }
        // Try loading VSOCK kernel modules from rootfs.
        load_vsock_modules()?;

        // Bind-mount /proc and /sys into the rootfs before chrooting,
        // so that /proc/<pid>/cwd and /proc/<pid>/environ work inside.
        let _ = std::fs::create_dir_all("/mnt/work/proc");
        let _ = std::fs::create_dir_all("/mnt/work/sys");
        let _ = std::fs::create_dir_all("/mnt/work/dev");
        mount_fs("proc", "/mnt/work/proc", "proc", 0, "").ok();
        mount_fs("sysfs", "/mnt/work/sys", "sysfs", 0, "").ok();
        // Bind-mount /dev (already mounted via devtmpfs at /dev)
        mount_fs("/dev", "/mnt/work/dev", "", libc::MS_BIND, "").ok();

        eprintln!("[tokimo-sandbox-init] chroot to /mnt/work");
        if let Err(e) = chroot("/mnt/work") {
            return Err(format!("chroot /mnt/work: {e}"));
        }
    }

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

    // Choose transport.
    // macOS VZ: guest listens (bind_vsock), host connects to guest.
    // Windows HCS: guest connects (connect_vsock), host listens.
    let (listener, write_fd, transport) = if env::var(ENV_SERIAL_MODE).is_ok() {
        let (r, w) = bind_serial()?;
        (r, w, server::Transport::Serial)
    } else if let Ok(port_str) = env::var(ENV_VSOCK_PORT) {
        let port: u32 = port_str
            .parse()
            .map_err(|e| format!("{ENV_VSOCK_PORT}={port_str}: {e}"))?;
        let guest_listens = env::var("TOKIMO_SANDBOX_GUEST_LISTENS").as_deref() == Ok("1");
        if guest_listens {
            // macOS VZ: guest listens, host connects.
            (bind_vsock(port)?, None, server::Transport::Vsock)
        } else {
            // Windows HCS: host listens, guest connects.
            (connect_vsock(port)?, None, server::Transport::Vsock)
        }
    } else {
        (bind_unix()?, None, server::Transport::SeqPacket)
    };

    let base_env = server::snapshot_base_env();

    let sigfd_owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(sigfd.as_raw_fd()) };
    std::mem::forget(sigfd);

    eprintln!("[tokimo-sandbox-init] READY");
    klog("READY-mainline, calling run_loop");
    server::run_loop(listener, write_fd, sigfd_owned, base_env, transport).map_err(|e| format!("event loop: {e}"))
}

#[cfg(target_os = "linux")]
fn klog(s: &str) {
    let line = format!("[tokimo-init-klog] {s}\n");
    unsafe {
        let fd = libc::open(c"/dev/kmsg".as_ptr(), libc::O_WRONLY);
        if fd >= 0 {
            libc::write(fd, line.as_ptr().cast(), line.len());
            libc::close(fd);
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_unix() -> Result<OwnedFd, String> {
    let sock_path = env::var(ENV_CONTROL_SOCK)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONTROL_SOCK));
    if let Some(parent) = sock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&sock_path);

    let fd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|e| format!("socket(SEQPACKET): {e}"))?;
    let addr = UnixAddr::new(&sock_path).map_err(|e| format!("UnixAddr: {e}"))?;
    bind(fd.as_raw_fd(), &addr).map_err(|e| format!("bind {sock_path:?}: {e}"))?;
    listen(&fd, Backlog::new(8).unwrap()).map_err(|e| format!("listen: {e}"))?;
    Ok(fd)
}

/// Serial mode.
///
/// `TOKIMO_SANDBOX_SERIAL_MODE=stdio` (Windows HCS): control channel is
/// fd 0 (read) and fd 1 (write) — i.e. a serial console (COM1) directly
/// wired by `init.sh` via `exec 0<>/dev/ttyS0 1>&0`. We dup the fds
/// (so the rest of init can repoint stdio to /dev/null) and put both in
/// non-blocking mode.
///
/// Any other value (legacy path): use a virtiofs mailbox at
/// `/mnt/work/.tps_{host_to_guest,guest_to_host}`.
#[cfg(target_os = "linux")]
fn bind_serial() -> Result<(OwnedFd, Option<OwnedFd>), String> {
    if env::var(ENV_SERIAL_MODE).as_deref() == Ok("stdio") {
        eprintln!("[tokimo-sandbox-init] serial mode: stdio (fd 0/1)");
        // Put the TTY in raw mode (no echo, no canonical processing).
        // Otherwise the kernel line discipline garbles our binary frames.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) == 0 {
                libc::cfmakeraw(&mut t);
                let _ = libc::cfsetspeed(&mut t, libc::B4000000);
                t.c_cc[libc::VMIN] = 1;
                t.c_cc[libc::VTIME] = 0;
                let _ = libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
        let r = unsafe { libc::dup(0) };
        if r < 0 {
            return Err(format!("dup(0): {}", std::io::Error::last_os_error()));
        }
        let w = unsafe { libc::dup(1) };
        if w < 0 {
            unsafe { libc::close(r) };
            return Err(format!("dup(1): {}", std::io::Error::last_os_error()));
        }
        // Set O_NONBLOCK on the read fd so the mio poll loop doesn't stall.
        unsafe {
            let flags = libc::fcntl(r, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(r, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            // Set CLOEXEC on both.
            libc::fcntl(r, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(w, libc::F_SETFD, libc::FD_CLOEXEC);
            // Repoint our own stdin/stdout to /dev/null so child processes
            // launched by init don't accidentally write debug to the wire.
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if null >= 0 {
                libc::dup2(null, 0);
                libc::dup2(null, 1);
                libc::close(null);
            }
        }
        return Ok((
            unsafe { OwnedFd::from_raw_fd(r) },
            Some(unsafe { OwnedFd::from_raw_fd(w) }),
        ));
    }

    eprintln!("[tokimo-sandbox-init] serial mode: virtiofs mailbox on /mnt/work");
    // Open the FIFO-like mailbox: read from host→guest file.
    let r = unsafe {
        libc::open(
            c"/mnt/work/.tps_host_to_guest".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if r < 0 {
        return Err(format!("open host→guest mailbox: {}", std::io::Error::last_os_error()));
    }
    let w = unsafe {
        libc::open(
            c"/mnt/work/.tps_guest_to_host".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_APPEND,
        )
    };
    if w < 0 {
        unsafe { libc::close(r) };
        return Err(format!("open guest→host mailbox: {}", std::io::Error::last_os_error()));
    }
    Ok((
        unsafe { OwnedFd::from_raw_fd(r) },
        Some(unsafe { OwnedFd::from_raw_fd(w) }),
    ))
}

/// Try to load VSOCK kernel modules from the rootfs. The Debian cloud kernel
/// ships VSOCK as modules (CONFIG_VSOCKETS=m), and the build strips them.
/// We load them here before binding the VSOCK socket.
#[cfg(target_os = "linux")]
fn load_vsock_modules() -> Result<(), String> {
    // Module names needed for vsock, in dependency order.
    let vsock_mods: &[&str] = &[
        "vsock",
        "vmw_vsock_virtio_transport_common",
        "vmw_vsock_virtio_transport",
    ];

    // Layout 1: CI-style flat directory at /modules/*.ko (uncompressed).
    if std::fs::metadata("/modules").map(|m| m.is_dir()).unwrap_or(false) {
        for name in vsock_mods {
            let path = format!("/modules/{name}.ko");
            load_one_module(&path).ok();
        }
        return Ok(());
    }

    // Layout 2: Traditional /lib/modules/<kver>/... tree (may be .ko.xz).
    let mod_bases: &[&str] = &["/lib/modules", "/mnt/work/lib/modules"];
    let rel_paths: &[&str] = &["kernel/net/vmw_vsock", "drivers/vhost"];
    for base in mod_bases {
        if !std::fs::metadata(base).map(|m| m.is_dir()).unwrap_or(false) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(base) else { continue };
        let Some(kdir) = entries
            .flatten()
            .find(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
        else {
            continue;
        };

        for name in vsock_mods {
            let mut found = false;
            for rel in rel_paths {
                for ext in &[".ko", ".ko.xz"] {
                    let path = kdir.join(rel).join(format!("{name}{ext}"));
                    if path.exists() {
                        load_one_module(&path.to_string_lossy()).ok();
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }
        }
        return Ok(());
    }

    eprintln!("[tokimo-sandbox-init] no module directory found, skipping vsock modprobe");
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_one_module(path: &str) -> Result<(), String> {
    load_kernel_module(path)
}

/// Chroot and chdir to the given path.
#[cfg(target_os = "linux")]
fn chroot(path: &str) -> Result<(), String> {
    let p = std::ffi::CString::new(path).unwrap();
    if unsafe { libc::chdir(p.as_ptr()) } != 0 {
        return Err(format!("chdir {path}: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::chroot(p.as_ptr()) } != 0 {
        return Err(format!("chroot {path}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Tiny mount wrapper — panics are fine here (init is PID 1, no one to recover).
#[cfg(target_os = "linux")]
fn mount_fs(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> Result<(), String> {
    let src = std::ffi::CString::new(source).unwrap();
    let tgt = std::ffi::CString::new(target).unwrap();
    let fst = std::ffi::CString::new(fstype).unwrap();
    let dat = std::ffi::CString::new(data).unwrap();
    let _ = std::fs::create_dir_all(target);
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            flags,
            dat.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("mount {source} on {target}: {e}"));
    }
    Ok(())
}

/// Bind and listen on an AF_VSOCK port (macOS VZ / Linux bwrap model).
/// The host connects TO the guest on this port. Blocks until the host
/// connects, then returns the accepted (connected) fd.
#[cfg(target_os = "linux")]
fn bind_vsock(port: u32) -> Result<OwnedFd, String> {
    let lfd = socket(AddressFamily::Vsock, SockType::Stream, SockFlag::SOCK_CLOEXEC, None)
        .map_err(|e| format!("socket(AF_VSOCK): {e}"))?;

    let addr = VsockAddr::new(libc::VMADDR_CID_ANY, port);
    bind(lfd.as_raw_fd(), &addr).map_err(|e| format!("bind VSOCK port {port}: {e}"))?;
    listen(&lfd, Backlog::new(1).unwrap()).map_err(|e| format!("listen VSOCK: {e}"))?;

    eprintln!("[tokimo-sandbox-init] listening on VSOCK port {port}, waiting for host...");

    // Accept the host's connection. This blocks until the host connects.
    let conn_raw = nix::sys::socket::accept(lfd.as_raw_fd()).map_err(|e| format!("accept VSOCK: {e}"))?;

    // Set non-blocking after accept so mio can poll it.
    unsafe {
        let flags = libc::fcntl(conn_raw, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(conn_raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    // Close the listening socket — we only need one connection.
    drop(lfd);

    eprintln!("[tokimo-sandbox-init] accepted VSOCK connection on port {port}");
    Ok(unsafe { OwnedFd::from_raw_fd(conn_raw) })
}

/// Open an AF_VSOCK stream to the host's `(VMADDR_CID_HOST, port)`. Cowork
/// architecture: the host listens on AF_HYPERV and the guest dials in.
/// Retries on connection-refused for a short window while Hyper-V sets up
/// the per-VM hvsock plumbing after VM start.
#[cfg(target_os = "linux")]
fn connect_vsock(port: u32) -> Result<OwnedFd, String> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = VsockAddr::new(libc::VMADDR_CID_HOST, port);
    loop {
        let fd = socket(AddressFamily::Vsock, SockType::Stream, SockFlag::SOCK_CLOEXEC, None)
            .map_err(|e| format!("socket(AF_VSOCK): {e}"))?;
        match connect(fd.as_raw_fd(), &addr) {
            Ok(()) => {
                eprintln!("[tokimo-sandbox-init] connected VSOCK CID=HOST port={port}");
                // Set non-blocking AFTER connect succeeds so the mio event
                // loop can poll the socket the same way as the listener
                // path used to.
                unsafe {
                    let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL, 0);
                    if flags >= 0 {
                        libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }
                }
                return Ok(fd);
            }
            Err(e) => {
                drop(fd);
                if Instant::now() >= deadline {
                    return Err(format!("connect VSOCK CID=HOST port {port}: {e}"));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}
