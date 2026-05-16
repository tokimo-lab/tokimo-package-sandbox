//! `tokimo-sandbox-fuse` — guest-side FUSE → host VfsBackend bridge.
//!
//! Linux-only. Runs inside the sandbox container/VM. One process per
//! mount: `init` spawns this binary with the per-session vsock port,
//! the logical mount name, and the in-guest mountpoint. The process
//! opens an `AF_VSOCK` connection to the host, performs the
//! [`Frame::Hello`] handshake (binding to `mount_name`), then mounts a
//! FUSE filesystem at the target path and translates kernel FUSE ops
//! into wire [`Req`]s.
//!
//! ```text
//!   kernel FUSE  ──fuser callbacks──▶  worker thread  ──postcard──▶  host
//!   /<target>                                                       FuseHost
//! ```
//!
//! ## CLI
//!
//! ```text
//! tokimo-sandbox-fuse \
//!     --transport vsock --port 2223 \
//!     --mount-name work \
//!     --target /mnt/work \
//!     [--read-only] \
//!     [--allow-other]
//! ```
//!
//! Or for tests / Linux bwrap:
//!
//! ```text
//! tokimo-sandbox-fuse --transport unix-fd --fd 4 --mount-name … --target …
//! ```
//!
//! Exit codes: 0 normal unmount, non-zero on protocol or mount error.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tokimo-sandbox-fuse only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fuser::{
        FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
        ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, Session, consts,
    };
    use tokimo_package_sandbox::vfs_protocol::wire::blocking as wire;
    use tokimo_package_sandbox::vfs_protocol::{AttrOut, EntryOut, Frame, NodeKind, Req, Res, StatfsOut, WireError};

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

        OWNER_UID.store(args.owner_uid, std::sync::atomic::Ordering::Relaxed);
        OWNER_GID.store(args.owner_gid, std::sync::atomic::Ordering::Relaxed);

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
            // NOTE: Intentionally NOT using `MountOption::DefaultPermissions`.
            // The kernel's DAC check there compares the caller's fsuid against
            // the inode's i_uid/i_gid in the *fuse superblock's* user_ns.
            // When the fuse mount is performed via setuid `fusermount3`, the
            // superblock's user_ns is `init_user_ns`. From an unprivileged
            // bwrap user_ns the host caller (uid 1001 on CI) appears as nobody
            // (65534), so even mode 0o777 doesn't help — the kernel rejects
            // writes with EACCES. Without `DefaultPermissions` the kernel
            // skips the DAC check and lets the FUSE server enforce policy.
            // Our server is a passthrough that executes ops with the host
            // caller's own credentials (which owns the backing dir), so this
            // is the correct semantics for the sandbox workspace.
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

    // ---------- Wire codec (blocking, std::io) ----------

    fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
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

    // ---------- Dispatcher: serialise wire writes, route responses by req_id ----------

    struct Dispatcher {
        // Two `File`s wrapping `dup`'d fds of the same underlying socket.
        // vsock + unix-stream both support concurrent r/w on the same fd,
        // but separate fds keep the locking rules trivial: writer holds
        // `write_file` lock, reader thread parks in `read(2)` on
        // `read_file` without contention.
        write_file: Mutex<File>,
        read_file: Mutex<Option<File>>,
        next_req_id: AtomicU64,
        pending: Mutex<HashMap<u64, mpsc::Sender<Res>>>,
        bound_mount_id: u32,
    }

    impl Dispatcher {
        fn new(fd: OwnedFd, bound_mount_id: u32) -> io::Result<Self> {
            let read_dup = dup_fd(&fd)?;
            Ok(Self {
                write_file: Mutex::new(File::from(fd)),
                read_file: Mutex::new(Some(File::from(read_dup))),
                next_req_id: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                bound_mount_id,
            })
        }

        /// Spawn the reader thread that demuxes frames from the host.
        fn spawn_reader(self: Arc<Self>) -> thread::JoinHandle<()> {
            let me = self;
            thread::spawn(move || {
                let mut read_file = match me.read_file.lock().unwrap().take() {
                    Some(f) => f,
                    None => {
                        eprintln!("[tokimo-fuse] reader: no read fd");
                        return;
                    }
                };
                let mut read_buf = Vec::with_capacity(8192);
                loop {
                    let frame = match wire::read_frame_into(&mut read_file, &mut read_buf) {
                        Ok(Some(f)) => f,
                        Ok(None) => {
                            eprintln!("[tokimo-fuse] host closed connection");
                            break;
                        }
                        Err(e) => {
                            eprintln!("[tokimo-fuse] reader error: {e}");
                            break;
                        }
                    };
                    match frame {
                        Frame::Response { req_id, result } => {
                            let tx = me.pending.lock().unwrap().remove(&req_id);
                            if let Some(tx) = tx {
                                let _ = tx.send(result);
                            } else {
                                eprintln!("[tokimo-fuse] orphan response req_id={req_id}");
                            }
                        }
                        Frame::Notify(_) => {}
                        other => {
                            eprintln!("[tokimo-fuse] unexpected frame: {other:?}");
                        }
                    }
                }
                // On reader exit, fail any pending requests.
                let pending = std::mem::take(&mut *me.pending.lock().unwrap());
                for (_, tx) in pending {
                    let _ = tx.send(Res::Error(WireError {
                        errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                        message: "host disconnected".into(),
                    }));
                }
            })
        }

        /// Send a request and block waiting for the response.
        fn call(&self, op: Req) -> Res {
            let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel();
            self.pending.lock().unwrap().insert(req_id, tx);
            let frame = Frame::Request {
                req_id,
                mount_id: self.bound_mount_id,
                op,
            };
            {
                let mut guard = self.write_file.lock().unwrap();
                if let Err(e) = wire::write_frame(&mut *guard, &frame) {
                    self.pending.lock().unwrap().remove(&req_id);
                    return Res::Error(WireError {
                        errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                        message: format!("send: {e}"),
                    });
                }
            }
            // Block on response. 30s budget to avoid deadlock if reader died.
            match rx.recv_timeout(Duration::from_secs(30)) {
                Ok(r) => r,
                Err(_) => {
                    self.pending.lock().unwrap().remove(&req_id);
                    Res::Error(WireError {
                        errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                        message: "timeout".into(),
                    })
                }
            }
        }
    }

    // ---------- FUSE → wire bridge ----------

    struct FuseBridge {
        dispatcher: Arc<Dispatcher>,
    }

    fn now_systime_to_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn entry_to_attr(e: &EntryOut) -> FileAttr {
        attr_to_fileattr(&e.attr, e.nodeid)
    }

    /// Owner uid/gid the kernel sees on every inode. Set once at startup
    /// from the `--owner-uid`/`--owner-gid` CLI flags (default 1000/1000).
    /// See the comment in `attr_to_fileattr` for why this exists.
    static OWNER_UID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);
    static OWNER_GID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);

    fn attr_to_fileattr(a: &AttrOut, ino: u64) -> FileAttr {
        let kind = match a.kind {
            NodeKind::File => FileType::RegularFile,
            NodeKind::Dir => FileType::Directory,
            NodeKind::Symlink => FileType::Symlink,
            NodeKind::Socket => FileType::Socket,
            NodeKind::Fifo => FileType::NamedPipe,
            NodeKind::BlockDev => FileType::BlockDevice,
            NodeKind::CharDev => FileType::CharDevice,
        };
        let to_st = |secs: i64| {
            if secs > 0 {
                UNIX_EPOCH + Duration::from_secs(secs as u64)
            } else {
                UNIX_EPOCH
            }
        };
        FileAttr {
            ino,
            size: a.size,
            blocks: a.size.div_ceil(512),
            atime: to_st(a.mtime),
            mtime: to_st(a.mtime),
            ctime: to_st(a.mtime),
            crtime: to_st(a.mtime),
            kind,
            perm: (a.mode & 0o7777) as u16,
            nlink: a.nlink,
            // Single-user sandbox model. Override the on-wire uid/gid so
            // the kernel always sees the sandbox's own caller as owner.
            //  * VM mode (macOS/Windows): tokimo user, uid=1000/gid=1000.
            //  * Linux bwrap mode: the runner's uid (e.g. 1001 on CI),
            //    because that's the only uid mapped into the user_ns —
            //    anything else translates to overflow uid (65534) and
            //    makes the mount unwritable from inside the sandbox.
            uid: OWNER_UID.load(std::sync::atomic::Ordering::Relaxed),
            gid: OWNER_GID.load(std::sync::atomic::Ordering::Relaxed),
            rdev: a.rdev,
            blksize: 4096,
            flags: 0,
        }
    }

    fn errno_of(we: &WireError) -> i32 {
        if we.errno == 0 { libc::EIO } else { we.errno }
    }

    /// Inode/attr cache TTL handed back to the kernel on lookup/getattr
    /// replies. The kernel will satisfy stat/access calls from its own
    /// cache for this long without bothering us. 60 s is conservative —
    /// agentic sandboxes are short-lived and the host filesystem isn't
    /// concurrently mutated by anyone outside this process.
    const TTL: Duration = Duration::from_secs(60);

    impl Filesystem for FuseBridge {
        /// Negotiate kernel-side capabilities. Big wins:
        ///   * `set_max_write(1MB)` — single FUSE write request can carry
        ///     up to 1 MiB instead of the legacy 128 KiB. Cuts our write
        ///     RTTs by 8× for streamed writes.
        ///   * `set_max_readahead(1MB)` — kernel issues 1 MiB read-aheads
        ///     so sequential `read()` is one RTT instead of many.
        ///   * `FUSE_WRITEBACK_CACHE` — kernel buffers small writes in
        ///     the page cache and flushes lazily, so memcpy-sized writes
        ///     don't round-trip on every syscall.
        ///   * `FUSE_AUTO_INVAL_DATA` — kernel can re-read data when our
        ///     attr changes mtime, so it's safe to leave page cache hot.
        ///   * `FUSE_DO_READDIRPLUS` — combines READDIR + LOOKUP per
        ///     entry, halving syscalls when traversing big trees.
        ///   * `set_max_background(64)` — let the kernel issue more
        ///     concurrent requests instead of serialising at 16 inflight.
        fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
            let _ = config.set_max_write(1024 * 1024);
            let _ = config.set_max_readahead(1024 * 1024);
            let _ = config.set_max_background(64);
            let _ = config.add_capabilities(
                consts::FUSE_WRITEBACK_CACHE
                    | consts::FUSE_AUTO_INVAL_DATA
                    | consts::FUSE_DO_READDIRPLUS
                    | consts::FUSE_ASYNC_READ
                    | consts::FUSE_BIG_WRITES,
            );
            Ok(())
        }

        fn lookup(&mut self, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            match self.dispatcher.call(Req::Lookup {
                parent_nodeid: parent,
                name: n,
            }) {
                Res::Entry(e) => {
                    let attr = entry_to_attr(&e);
                    reply.entry(&TTL, &attr, e.generation);
                }
                Res::Error(we) => {
                    let err = errno_of(&we);
                    // For ENOENT we send a successful "negative entry"
                    // reply (nodeid = 0) with entry_timeout = 0 instead
                    // of returning ENOENT. This prevents the kernel
                    // from caching a negative dentry. Negative-dentry
                    // caching is fatally racy for us: sequences like
                    //
                    //     stat("config")          // caches negative
                    //     rename("config.lock","config")
                    //     open("config")          // serves stale neg
                    //
                    // (which `git init` and friends do constantly) fail
                    // with ENOENT despite the file existing. The fix
                    // would otherwise require an inline
                    // FUSE_NOTIFY_INVAL_ENTRY from inside the rename
                    // handler, which deadlocks on the parent dir's
                    // i_rwsem (held by the kernel for the in-flight
                    // FUSE_RENAME). Disabling negative caching here is
                    // the only safe option.
                    if err == libc::ENOENT {
                        let neg = FileAttr {
                            ino: 0,
                            size: 0,
                            blocks: 0,
                            atime: UNIX_EPOCH,
                            mtime: UNIX_EPOCH,
                            ctime: UNIX_EPOCH,
                            crtime: UNIX_EPOCH,
                            kind: FileType::RegularFile,
                            perm: 0,
                            nlink: 0,
                            uid: 0,
                            gid: 0,
                            rdev: 0,
                            blksize: 4096,
                            flags: 0,
                        };
                        reply.entry(&Duration::ZERO, &neg, 0);
                    } else {
                        reply.error(err);
                    }
                }
                _ => reply.error(libc::EIO),
            }
        }

        fn forget(&mut self, _r: &Request, ino: u64, nlookup: u64) {
            // Forget is fire-and-forget — we don't wait for a response.
            let _ = self.dispatcher.call(Req::Forget { nodeid: ino, nlookup });
        }

        fn getattr(&mut self, _r: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
            match self.dispatcher.call(Req::GetAttr { nodeid: ino }) {
                Res::Attr(a) => {
                    let fa = attr_to_fileattr(&a, ino);
                    reply.attr(&TTL, &fa);
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn setattr(
            &mut self,
            _r: &Request,
            ino: u64,
            mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            atime: Option<fuser::TimeOrNow>,
            mtime: Option<fuser::TimeOrNow>,
            _ctime: Option<SystemTime>,
            _fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            let to_secs = |t: fuser::TimeOrNow| match t {
                fuser::TimeOrNow::SpecificTime(s) => {
                    s.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
                }
                fuser::TimeOrNow::Now => now_systime_to_secs(),
            };
            match self.dispatcher.call(Req::SetAttr {
                nodeid: ino,
                mode,
                size,
                atime: atime.map(to_secs),
                mtime: mtime.map(to_secs),
            }) {
                Res::Attr(a) => {
                    let fa = attr_to_fileattr(&a, ino);
                    reply.attr(&TTL, &fa);
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn opendir(&mut self, _r: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
            match self.dispatcher.call(Req::OpenDir { nodeid: ino }) {
                // FOPEN_CACHE_DIR: kernel may cache directory contents
                // across opens, eliding repeated readdir round-trips.
                Res::OpenOk { fh } => reply.opened(fh, consts::FOPEN_CACHE_DIR),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn readdir(&mut self, _r: &Request, _ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectory) {
            match self.dispatcher.call(Req::ReadDir {
                fh,
                offset: offset.max(0) as u64,
            }) {
                Res::DirEntries(entries) => {
                    for e in entries {
                        let kind = match e.kind {
                            NodeKind::Dir => FileType::Directory,
                            NodeKind::Symlink => FileType::Symlink,
                            NodeKind::File => FileType::RegularFile,
                            NodeKind::Socket => FileType::Socket,
                            NodeKind::Fifo => FileType::NamedPipe,
                            NodeKind::BlockDev => FileType::BlockDevice,
                            NodeKind::CharDev => FileType::CharDevice,
                        };
                        // ReplyDirectory::add returns true if buffer full.
                        if reply.add(e.nodeid, e.offset as i64, kind, e.name) {
                            break;
                        }
                    }
                    reply.ok();
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn releasedir(&mut self, _r: &Request, _ino: u64, fh: u64, _flags: i32, reply: ReplyEmpty) {
            match self.dispatcher.call(Req::ReleaseDir { fh }) {
                Res::Ok => reply.ok(),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn readdirplus(&mut self, _r: &Request<'_>, _ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectoryPlus) {
            match self.dispatcher.call(Req::ReadDirPlus {
                fh,
                offset: offset.max(0) as u64,
            }) {
                Res::DirEntriesPlus(entries) => {
                    for e in entries {
                        let attr = entry_to_attr(&e.entry);
                        if reply.add(
                            e.entry.nodeid,
                            e.offset as i64,
                            &e.name,
                            &TTL,
                            &attr,
                            e.entry.generation,
                        ) {
                            break;
                        }
                    }
                    reply.ok();
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn open(&mut self, _r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
            match self.dispatcher.call(Req::Open {
                nodeid: ino,
                flags: flags as u32,
            }) {
                // FOPEN_KEEP_CACHE: kernel keeps page cache across opens
                // — subsequent reads of the same file hit the cache
                // without ever consulting FUSE userspace. Combined with
                // FUSE_AUTO_INVAL_DATA and our 60s entry/attr TTL the
                // cache is safe for sandbox-local FS where no external
                // process mutates files behind our back.
                Res::OpenOk { fh } => reply.opened(fh, consts::FOPEN_KEEP_CACHE),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn read(
            &mut self,
            _r: &Request,
            _ino: u64,
            fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock: Option<u64>,
            reply: ReplyData,
        ) {
            match self.dispatcher.call(Req::Read {
                fh,
                offset: offset.max(0) as u64,
                size,
            }) {
                Res::Bytes(b) => reply.data(&b),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn write(
            &mut self,
            _r: &Request,
            _ino: u64,
            fh: u64,
            offset: i64,
            data: &[u8],
            _wflags: u32,
            _flags: i32,
            _lock: Option<u64>,
            reply: ReplyWrite,
        ) {
            match self.dispatcher.call(Req::Write {
                fh,
                offset: offset.max(0) as u64,
                data: data.to_vec(),
            }) {
                Res::Written { size } => reply.written(size),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn flush(&mut self, _r: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
            match self.dispatcher.call(Req::Flush { fh }) {
                Res::Ok => reply.ok(),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn release(
            &mut self,
            _r: &Request,
            _ino: u64,
            fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            match self.dispatcher.call(Req::Release { fh }) {
                Res::Ok => reply.ok(),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn mkdir(&mut self, _r: &Request, parent: u64, name: &OsStr, mode: u32, _umask: u32, reply: ReplyEntry) {
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            match self.dispatcher.call(Req::Mkdir {
                parent_nodeid: parent,
                name: n,
                mode,
            }) {
                Res::Entry(e) => {
                    let attr = entry_to_attr(&e);
                    reply.entry(&TTL, &attr, e.generation);
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        /// `mknod(2)` — the kernel invokes this for `bind(2)` of AF_UNIX
        /// sockets, `mkfifo(3)`, and device-node creation. The `mode`
        /// argument arrives with `S_IFMT` already encoded so the host
        /// VFS knows which kind of inode to materialise.
        fn mknod(
            &mut self,
            _r: &Request,
            parent: u64,
            name: &OsStr,
            mode: u32,
            _umask: u32,
            rdev: u32,
            reply: ReplyEntry,
        ) {
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            match self.dispatcher.call(Req::Mknod {
                parent_nodeid: parent,
                name: n,
                mode,
                rdev,
            }) {
                Res::Entry(e) => {
                    let attr = entry_to_attr(&e);
                    reply.entry(&TTL, &attr, e.generation);
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn rmdir(&mut self, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            match self.dispatcher.call(Req::Rmdir {
                parent_nodeid: parent,
                name: n,
            }) {
                Res::Ok => reply.ok(),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn unlink(&mut self, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            match self.dispatcher.call(Req::Unlink {
                parent_nodeid: parent,
                name: n,
            }) {
                Res::Ok => reply.ok(),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn rename(
            &mut self,
            _r: &Request,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            _flags: u32,
            reply: ReplyEmpty,
        ) {
            let on = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            let nn = match newname.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            match self.dispatcher.call(Req::Rename {
                old_parent: parent,
                old_name: on.clone(),
                new_parent: newparent,
                new_name: nn.clone(),
            }) {
                // The kernel auto-invalidates the source dentry on a
                // successful FUSE_RENAME. It does NOT invalidate any
                // cached *negative* dentry for the destination name,
                // but that's handled at lookup time — see the comment
                // in `lookup()` for why we disable negative-dentry
                // caching entirely. Sending FUSE_NOTIFY_INVAL_ENTRY
                // from here would deadlock: the kernel holds the
                // parent dir's i_rwsem for the in-flight FUSE_RENAME
                // and inval_entry tries to acquire it on the same
                // fuse worker thread (verified — `fuse_reverse_inval_entry`
                // wedges in D-state on `start_removing_dentry`).
                Res::Ok => reply.ok(),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn symlink(&mut self, _r: &Request, parent: u64, name: &OsStr, link: &Path, reply: ReplyEntry) {
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            // POSIX symlink targets are an opaque byte string. Our
            // wire protocol carries them as String; on Linux paths
            // are virtually always UTF-8, and lossy conversion only
            // affects exotic locale encodings nobody uses today.
            let target = link.to_string_lossy().into_owned();
            match self.dispatcher.call(Req::Symlink {
                parent_nodeid: parent,
                name: n,
                target,
            }) {
                Res::Entry(e) => {
                    let attr = entry_to_attr(&e);
                    reply.entry(&TTL, &attr, e.generation);
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn readlink(&mut self, _r: &Request, ino: u64, reply: ReplyData) {
            match self.dispatcher.call(Req::Readlink { nodeid: ino }) {
                Res::Linkname(s) => reply.data(s.as_bytes()),
                Res::Bytes(b) => reply.data(&b),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }

        fn create(
            &mut self,
            _r: &Request,
            parent: u64,
            name: &OsStr,
            mode: u32,
            _umask: u32,
            flags: i32,
            reply: fuser::ReplyCreate,
        ) {
            // Two-step: lookup-or-create via Mkdir-style? VFS protocol
            // doesn't have a separate `create`; use Mkdir for dirs and
            // for regular files we synthesise:
            //   1. Open the file with O_CREAT semantics — requires the
            //      backend to honour `flags & O_CREAT`. Our protocol's
            //      Open already does this when the mount is writable.
            //   2. After successful Open, the host should have a node
            //      for the new file; do a Lookup to resolve it.
            //
            // For correctness across backends we emulate touch-then-open:
            // this is rare on the hot path.
            let n = match name.to_str() {
                Some(s) => s.to_string(),
                None => return reply.error(libc::EINVAL),
            };
            // First Lookup; if not found, fall through to write a 0-byte
            // file via SetAttr-truncate-after-Open by issuing an Open
            // with the O_CREAT bit set.
            match self.dispatcher.call(Req::Lookup {
                parent_nodeid: parent,
                name: n.clone(),
            }) {
                Res::Entry(e) => {
                    // Already exists; just open.
                    let nodeid = e.nodeid;
                    let attr = entry_to_attr(&e);
                    let gen_ = e.generation;
                    match self.dispatcher.call(Req::Open {
                        nodeid,
                        flags: flags as u32,
                    }) {
                        Res::OpenOk { fh } => reply.created(&TTL, &attr, gen_, fh, 0),
                        Res::Error(we) => reply.error(errno_of(&we)),
                        _ => reply.error(libc::EIO),
                    }
                }
                Res::Error(_) => {
                    // Not found: ask the host to create an empty file,
                    // then open it for the caller.
                    match self.dispatcher.call(Req::Create {
                        parent_nodeid: parent,
                        name: n.clone(),
                        mode,
                    }) {
                        Res::Entry(e) => {
                            let nodeid = e.nodeid;
                            let attr = entry_to_attr(&e);
                            let gen_ = e.generation;
                            match self.dispatcher.call(Req::Open {
                                nodeid,
                                flags: flags as u32,
                            }) {
                                Res::OpenOk { fh } => reply.created(&TTL, &attr, gen_, fh, 0),
                                Res::Error(we) => reply.error(errno_of(&we)),
                                _ => reply.error(libc::EIO),
                            }
                        }
                        Res::Error(we) => reply.error(errno_of(&we)),
                        _ => reply.error(libc::EIO),
                    }
                }
                _ => reply.error(libc::EIO),
            }
        }

        fn statfs(&mut self, _r: &Request, ino: u64, reply: ReplyStatfs) {
            match self.dispatcher.call(Req::Statfs { nodeid: ino }) {
                Res::Statfs(s) => {
                    let StatfsOut {
                        blocks,
                        bfree,
                        bavail,
                        files,
                        ffree,
                        bsize,
                        namelen,
                        frsize,
                    } = s;
                    reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, frsize);
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }
    }
}
