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
use nix::sys::socket::{AddressFamily, Backlog, SockFlag, SockType, UnixAddr, VsockAddr, bind, listen, socket};
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
const ENV_SERIAL_MODE: &str = "TOKIMO_SANDBOX_SERIAL_MODE";

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("[tokimo-sandbox-init] fatal: {e}");
        return ExitCode::from(1);
    }
    ExitCode::from(0)
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

    // Mount essential filesystems (skip if already mounted by initrd script).
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

    // When running under VSOCK or serial mode, mount virtiofs and set up.
    let is_vm_mode = env::var(ENV_VSOCK_PORT).is_ok() || env::var(ENV_SERIAL_MODE).is_ok();
    if is_vm_mode {
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
    let (listener, write_fd, transport) = if env::var(ENV_SERIAL_MODE).is_ok() {
        let (r, w) = bind_serial()?;
        (r, w, server::Transport::Serial)
    } else if let Ok(port_str) = env::var(ENV_VSOCK_PORT) {
        let port: u32 = port_str
            .parse()
            .map_err(|e| format!("{ENV_VSOCK_PORT}={port_str}: {e}"))?;
        (bind_vsock(port)?, None, server::Transport::Vsock)
    } else {
        (bind_unix()?, None, server::Transport::SeqPacket)
    };

    let base_env = server::snapshot_base_env();

    let sigfd_owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(sigfd.as_raw_fd()) };
    std::mem::forget(sigfd);

    eprintln!("[tokimo-sandbox-init] READY");
    server::run_loop(listener, write_fd, sigfd_owned, base_env, transport).map_err(|e| format!("event loop: {e}"))
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

/// Serial mode: use a mailbox file on the virtiofs share for bidirectional
/// communication. The host writes ops to `.tps_host_to_guest` and the guest
/// writes replies to `.tps_guest_to_host`. We poll the control file with a
/// simple file-based loop. No sockets needed — works with any kernel.
#[cfg(target_os = "linux")]
fn bind_serial() -> Result<(OwnedFd, Option<OwnedFd>), String> {
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
    // Find the module directory (e.g. /mnt/work/lib/modules/6.12.74+...)
    // Try initrd first (/lib/modules), then rootfs (/mnt/work/lib/modules).
    let mod_base = if std::fs::metadata("/lib/modules").map(|m| m.is_dir()).unwrap_or(false) {
        "/lib/modules"
    } else if std::fs::metadata("/mnt/work/lib/modules")
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        "/mnt/work/lib/modules"
    } else {
        eprintln!("[tokimo-sandbox-init] no /lib/modules found, skipping vsock modprobe");
        return Ok(());
    };
    let entries = match std::fs::read_dir(mod_base) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[tokimo-sandbox-init] read_dir({mod_base}): {e}");
            return Ok(());
        }
    };
    let mut kernel_dir = None;
    for e in entries.flatten() {
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            kernel_dir = Some(e.path());
            break;
        }
    }
    let Some(kdir) = kernel_dir else {
        eprintln!("[tokimo-sandbox-init] no kernel module dir found");
        return Ok(());
    };

    // Load modules in dependency order.
    let vsock_mods: &[&str] = &[
        "kernel/net/vmw_vsock/vsock.ko.xz",
        "kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko.xz",
        "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko.xz",
    ];
    // Also try uncompressed variants.
    let vsock_mods_alt: &[&str] = &[
        "kernel/net/vmw_vsock/vsock.ko",
        "kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko",
        "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko",
    ];

    for (compressed, uncompressed) in vsock_mods.iter().zip(vsock_mods_alt.iter()) {
        let path = kdir.join(compressed);
        let alt = kdir.join(uncompressed);
        let mod_path = if path.exists() {
            &path
        } else if alt.exists() {
            &alt
        } else {
            continue;
        };
        let path_c =
            std::ffi::CString::new(mod_path.to_string_lossy().as_bytes()).map_err(|e| format!("CString: {e}"))?;
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            eprintln!("[tokimo-sandbox-init] open({}) failed", mod_path.display());
            continue;
        }
        // finit_module syscall (not in libc crate for all targets).
        let rc = unsafe { libc::syscall(libc::SYS_finit_module, fd, c"".as_ptr(), 0usize) };
        unsafe { libc::close(fd) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "[tokimo-sandbox-init] finit_module({}) failed: {err}",
                mod_path.display()
            );
            // Continue — maybe already loaded or not needed.
        } else {
            eprintln!("[tokimo-sandbox-init] loaded {}", mod_path.display());
        }
    }
    Ok(())
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

/// Bind an AF_VSOCK listener on `port`. The socket is non-blocking so it
/// integrates with the mio event loop (same as the Unix path).
#[cfg(target_os = "linux")]
fn bind_vsock(port: u32) -> Result<OwnedFd, String> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|e| format!("socket(AF_VSOCK): {e}"))?;

    // Bind to VMADDR_CID_ANY on the guest side.
    let addr = VsockAddr::new(libc::VMADDR_CID_ANY, port);
    bind(fd.as_raw_fd(), &addr).map_err(|e| format!("bind VSOCK port {port}: {e}"))?;
    listen(&fd, Backlog::new(8).unwrap()).map_err(|e| format!("listen VSOCK: {e}"))?;

    eprintln!("[tokimo-sandbox-init] listening on VSOCK port {port}");
    Ok(fd)
}
