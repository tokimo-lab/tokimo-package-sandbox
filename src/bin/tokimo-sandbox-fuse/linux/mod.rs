//! Linux implementation of the `tokimo-sandbox-fuse` binary.

pub(super) mod bridge;
pub(super) mod dispatcher;
pub(super) mod ops;

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use fuser::{MountOption, Session};

use bridge::FuseBridge;
use dispatcher::Dispatcher;

// ---------- CLI ----------

enum Transport {
    Vsock { port: u32 },
    UnixFd { fd: i32 },
}

struct Args {
    transport: Transport,
    mount_name: String,
    target: PathBuf,
    read_only: bool,
    owner_uid: u32,
    owner_gid: u32,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let mut transport_kind: Option<String> = None;
    let mut port: Option<u32> = None;
    let mut fd: Option<i32> = None;
    let mut mount_name: Option<String> = None;
    let mut target: Option<PathBuf> = None;
    let mut read_only = false;
    // Defaults match the single-user VM model (tokimo uid=1000, gid=1000).
    // Linux bwrap mode passes explicit --owner-uid/--owner-gid because the
    // caller's uid (typically 1001 on CI runners) is the only uid mapped
    // into the user_ns; foreign uids translate to the overflow uid and
    // become unwritable.
    let mut owner_uid: u32 = 1000;
    let mut owner_gid: u32 = 1000;
    while let Some(a) = argv.next() {
        match a.as_str() {
            "--transport" => transport_kind = argv.next(),
            "--port" => port = argv.next().and_then(|s| s.parse().ok()),
            "--fd" => fd = argv.next().and_then(|s| s.parse().ok()),
            "--mount-name" => mount_name = argv.next(),
            "--target" => target = argv.next().map(PathBuf::from),
            "--read-only" => read_only = true,
            "--owner-uid" => {
                owner_uid = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--owner-uid needs u32")?;
            }
            "--owner-gid" => {
                owner_gid = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--owner-gid needs u32")?;
            }
            "--allow-other" => {} // accepted for backward compat, always enabled
            "-h" | "--help" => {
                eprintln!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    let transport = match transport_kind.as_deref() {
        Some("vsock") => {
            let p = port.ok_or("--transport vsock requires --port")?;
            Transport::Vsock { port: p }
        }
        Some("unix-fd") => {
            let f = fd.ok_or("--transport unix-fd requires --fd")?;
            Transport::UnixFd { fd: f }
        }
        Some(other) => return Err(format!("unknown transport: {other}")),
        None => return Err("missing --transport".into()),
    };
    Ok(Args {
        transport,
        mount_name: mount_name.ok_or("missing --mount-name")?,
        target: target.ok_or("missing --target")?,
        read_only,
        owner_uid,
        owner_gid,
    })
}

const USAGE: &str = "tokimo-sandbox-fuse \
    --transport <vsock|unix-fd> \
    [--port N | --fd N] \
    --mount-name <name> --target <path> \
    [--read-only] [--allow-other]";

pub fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[tokimo-fuse] {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    bridge::OWNER_UID.store(args.owner_uid, std::sync::atomic::Ordering::Relaxed);
    bridge::OWNER_GID.store(args.owner_gid, std::sync::atomic::Ordering::Relaxed);

    // Open transport.
    let stream = match open_transport(&args.transport) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[tokimo-fuse] open transport: {e}");
            return ExitCode::from(3);
        }
    };

    // Handshake: bind connection to mount_name.
    let stream_for_handshake = match dup_fd(&stream) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[tokimo-fuse] dup transport: {e}");
            return ExitCode::from(3);
        }
    };
    let bound_id = match handshake(stream, &args.mount_name) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("[tokimo-fuse] handshake: {e}");
            return ExitCode::from(4);
        }
    };
    eprintln!(
        "[tokimo-fuse] connected: mount={:?} bound_id={} target={:?}",
        args.mount_name, bound_id, args.target
    );

    // Spawn dispatcher thread that owns the wire connection.
    let dispatcher = match Dispatcher::new(stream_for_handshake, bound_id) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("[tokimo-fuse] dispatcher init: {e}");
            return ExitCode::from(4);
        }
    };
    let dispatch_handle = dispatcher.clone().spawn_reader();

    // Build FUSE filesystem and mount.
    let fs = FuseBridge {
        dispatcher: dispatcher.clone(),
    };
    let mut opts = vec![
        MountOption::FSName(format!("tokimo-{}", args.mount_name)),
        // `DefaultPermissions` makes the kernel perform DAC against the
        // mode/uid/gid we report via getattr. Without it, the kernel
        // runs a fallback permission check that rejects file creation
        // (mknod/create) over FUSE inside an unprivileged user_ns with
        // EACCES — even when the FUSE server would accept the op. With
        // `DefaultPermissions`, the backing dir's mode (0o777 for the
        // sandbox workspace) is honoured and AF_UNIX `bind()`, FIFO
        // mknod, and regular file creates all succeed end-to-end.
        MountOption::DefaultPermissions,
        MountOption::AllowOther,
        MountOption::NoAtime,
    ];
    if args.read_only {
        opts.push(MountOption::RO);
    } else {
        opts.push(MountOption::RW);
    }

    // Make sure mountpoint exists.
    if let Err(e) = std::fs::create_dir_all(&args.target)
        && e.kind() != io::ErrorKind::AlreadyExists
    {
        eprintln!("[tokimo-fuse] create mountpoint {}: {e}", args.target.display());
        return ExitCode::from(5);
    }

    // We use Session::new (instead of fuser::mount2) so we can
    // configure mount options without leaking the file descriptor.
    let mut session = match Session::new(fs, &args.target, &opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[tokimo-fuse] Session::new: {e}");
            return ExitCode::from(6);
        }
    };

    // Hand the kernel notifier to the dispatcher so host-pushed
    // [`Frame::Notify`] frames can translate into FUSE_NOTIFY_INVAL_*
    // upcalls. Must happen *after* `Session::new` (the notifier needs
    // the live channel fd) and *before* `session.run` (so the reader
    // thread, already running, sees the notifier as soon as the host
    // emits its first invalidation).
    let _inval_handle = dispatcher.install_notifier(session.notifier());

    let run_res = session.run();

    match run_res {
        Ok(()) => {
            eprintln!("[tokimo-fuse] unmounted cleanly");
            let _ = dispatch_handle.join();
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("[tokimo-fuse] session.run: {e}");
            ExitCode::from(6)
        }
    }
}

fn open_transport(t: &Transport) -> io::Result<OwnedFd> {
    match *t {
        Transport::Vsock { port } => tokimo_package_sandbox::vsock_util::connect_host(port),
        Transport::UnixFd { fd } => {
            // The fd was passed via fork+inherit; assume it's a SOCK_STREAM unix socket.
            // Take ownership.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
}

pub(super) fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = fd.as_raw_fd();
    let new = unsafe { libc::dup(raw) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// One-shot Hello/HelloAck handshake on the freshly-opened transport.
/// Consumes its half of the connection — the caller passes in a
/// `dup`'d fd for use by the dispatcher.
fn handshake(fd: OwnedFd, mount_name: &str) -> io::Result<u32> {
    let mut file = File::from(fd);
    let client_name = format!("tokimo-sandbox-fuse pid={}", std::process::id());
    tokimo_package_sandbox::vfs_protocol::handshake::client_handshake(&mut file, mount_name, &client_name)
}
