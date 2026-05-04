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
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
        ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    };
    use tokimo_package_sandbox::vfs_protocol::wire::blocking as wire;
    use tokimo_package_sandbox::vfs_protocol::{
        AttrOut, EntryOut, Frame, NodeKind, PROTOCOL_VERSION, Req, Res, StatfsOut, WireError,
    };

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
    }

    fn parse_args() -> Result<Args, String> {
        let mut argv = std::env::args().skip(1);
        let mut transport_kind: Option<String> = None;
        let mut port: Option<u32> = None;
        let mut fd: Option<i32> = None;
        let mut mount_name: Option<String> = None;
        let mut target: Option<PathBuf> = None;
        let mut read_only = false;
        while let Some(a) = argv.next() {
            match a.as_str() {
                "--transport" => transport_kind = argv.next(),
                "--port" => port = argv.next().and_then(|s| s.parse().ok()),
                "--fd" => fd = argv.next().and_then(|s| s.parse().ok()),
                "--mount-name" => mount_name = argv.next(),
                "--target" => target = argv.next().map(PathBuf::from),
                "--read-only" => read_only = true,
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

        match fuser::mount2(fs, &args.target, &opts) {
            Ok(()) => {
                eprintln!("[tokimo-fuse] unmounted cleanly");
                let _ = dispatch_handle.join();
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("[tokimo-fuse] mount2: {e}");
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
        let hello = Frame::Hello {
            proto_version: PROTOCOL_VERSION,
            max_inflight: 64,
            client_name: format!("tokimo-sandbox-fuse pid={}", std::process::id()),
            mount_name: Some(mount_name.to_string()),
        };
        wire::write_frame(&mut file, &hello)?;
        let ack =
            wire::read_frame(&mut file)?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no HelloAck"))?;
        match ack {
            Frame::HelloAck {
                proto_version,
                bound_mount_id,
                ..
            } => {
                if proto_version != PROTOCOL_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("proto mismatch: server={} client={}", proto_version, PROTOCOL_VERSION),
                    ));
                }
                bound_mount_id
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "server did not bind mount_name"))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected HelloAck, got {other:?}"),
            )),
        }
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
                loop {
                    let frame = match wire::read_frame(&mut read_file) {
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

    fn attr_to_fileattr(a: &AttrOut, ino: u64) -> FileAttr {
        let kind = match a.kind {
            NodeKind::File => FileType::RegularFile,
            NodeKind::Dir => FileType::Directory,
            NodeKind::Symlink => FileType::Symlink,
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
            // Single-user sandbox model: all guest processes run as tokimo
            // (uid=1000, gid=1000). vfs_host on Windows/macOS returns uid=0
            // because it can't map host ACLs to a Linux uid, which would make
            // the mount unwritable by tokimo with DefaultPermissions enabled.
            // Override here so guest processes see themselves as the owner.
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn errno_of(we: &WireError) -> i32 {
        if we.errno == 0 { libc::EIO } else { we.errno }
    }

    const TTL: Duration = Duration::from_secs(1);

    impl Filesystem for FuseBridge {
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
                Res::Error(we) => reply.error(errno_of(&we)),
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
                Res::OpenOk { fh } => reply.opened(fh, 0),
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

        fn open(&mut self, _r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
            match self.dispatcher.call(Req::Open {
                nodeid: ino,
                flags: flags as u32,
            }) {
                Res::OpenOk { fh } => reply.opened(fh, 0),
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
                old_name: on,
                new_parent: newparent,
                new_name: nn,
            }) {
                Res::Ok => reply.ok(),
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
