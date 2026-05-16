//! Wire protocol for the host ↔ guest VFS-FUSE bridge.
//!
//! - Transport: a duplex byte stream (vsock on macOS/Windows, unix
//!   `SOCK_STREAM` on Linux/bwrap). Framing is independent of transport.
//! - Frame: `u32 LE length-prefix` (length excludes the 4-byte prefix) +
//!   `postcard`-encoded [`Frame`] payload.
//! - Postcard chosen over JSON / bincode for compactness, no_std-friendly
//!   deserialisation, and stable serde-driven schema evolution. Both ends
//!   compile from the same workspace, so a Rust-native binary format is
//!   the natural fit.
//!
//! See [`plan/cross-platform-fuse-vfs.md`](../../plan/cross-platform-fuse-vfs.md)
//! for the design rationale and op table.

pub mod handshake;
pub mod wire;

use serde::{Deserialize, Serialize};

use crate::vfs_backend::VfsError;

/// Bumped on any breaking shape change. Both sides validate this in the
/// `Hello` exchange.
///
/// v2 (added in tokimo-sandbox 0.x):
///   - [`Req::Mknod`] op for AF_UNIX socket / FIFO / device-node creation.
///   - [`NodeKind`] extended with `Socket`, `Fifo`, `BlockDev`, `CharDev`.
///   - [`AttrOut::rdev`] field for char/block devices.
///
/// v3 (added in tokimo-sandbox 0.x):
///   - [`Req::Link`] / [`Req::Fsync`] / [`Req::Fsyncdir`] / [`Req::Access`]
///   - [`Req::Setxattr`] / [`Req::Getxattr`] / [`Req::Listxattr`] /
///     [`Req::Removexattr`] (and responses [`Res::XattrSize`] /
///     [`Res::XattrList`]).
///   - [`Req::Fallocate`] / [`Req::CopyFileRange`] / [`Req::Lseek`] /
///     [`Req::Bmap`] / [`Req::Ioctl`] / [`Req::Poll`].
///   - [`Req::Getlk`] / [`Req::Setlk`] plus [`LockSpec`] / [`LockType`].
///   - [`Errno`] extended with `Enxio`, `Erange`, `Enodata`, `Enotsup`.
///   - [`VfsError`] extended with `NotSupported`, `OutOfRange`, `NoData`,
///     `NoSuchDeviceOrAddress`.
pub const PROTOCOL_VERSION: u32 = 3;

/// Maximum payload size (excluding the 4-byte length prefix). Sized to
/// hold a 1 MiB read with metadata overhead.
pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// Maximum bytes per single read/write op. FUSE kernel default `max_read`
/// is 128 KiB; we permit up to 1 MiB which fuser may negotiate up to.
pub const MAX_IO_CHUNK: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Top-level frame
// ---------------------------------------------------------------------------

/// One wire message. The connection lifecycle is:
///
/// 1. Client sends [`Frame::Hello`].
/// 2. Server replies [`Frame::HelloAck`] (or closes the connection on
///    version mismatch).
/// 3. Steady state: client streams [`Frame::Request`], server replies
///    [`Frame::Response`] (`req_id` matched). Server may also push
///    [`Frame::Notify`] at any time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    Hello {
        proto_version: u32,
        max_inflight: u32,
        client_name: String,
        /// If `Some`, the server binds this connection to the named
        /// mount and returns its `mount_id` in `HelloAck.bound_mount_id`.
        /// If `None`, the client must include `mount_id` in every
        /// `Request` (multi-mount mode).
        #[serde(default)]
        mount_name: Option<String>,
    },
    HelloAck {
        proto_version: u32,
        max_inflight: u32,
        /// Set when `Hello.mount_name` resolved successfully.
        #[serde(default)]
        bound_mount_id: Option<u32>,
    },
    Request {
        req_id: u64,
        mount_id: u32,
        op: Req,
    },
    Response {
        req_id: u64,
        result: Res,
    },
    Notify(Inval),
}

// ---------------------------------------------------------------------------
// Requests (guest → host)
// ---------------------------------------------------------------------------

/// One request op. Mirrors the FUSE kernel op table, but uses `nodeid`/`fh`
/// allocated by the host (never raw inode numbers from the host FS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Req {
    /// Resolve a name in a directory. Returns an entry + nodeid the
    /// client may then use for further ops. Increments lookup count by 1.
    Lookup {
        parent_nodeid: u64,
        name: String,
    },

    /// Drop `nlookup` references to `nodeid`. Host may release the
    /// IdTable slot once refcount hits 0. No response.
    Forget {
        nodeid: u64,
        nlookup: u64,
    },

    /// Stat by nodeid.
    GetAttr {
        nodeid: u64,
    },

    /// Truncate / set times / set mode (subset). Unsupported attrs return
    /// `ENOSYS`.
    SetAttr {
        nodeid: u64,
        mode: Option<u32>,
        size: Option<u64>,
        atime: Option<i64>, // unix seconds; -1 = UTIME_NOW (rare)
        mtime: Option<i64>,
    },

    /// Open a directory handle. Host snapshots [`VfsReader::list`]
    /// results into a server-side [`DirHandle`] keyed by `fh`.
    OpenDir {
        nodeid: u64,
    },

    /// Read entries starting at `offset` (cookie). End-of-stream is
    /// signalled by an empty `entries` vec.
    ReadDir {
        fh: u64,
        offset: u64,
    },

    /// Like [`ReadDir`](Self::ReadDir) but each entry carries its full
    /// `EntryOut`, letting the guest kernel populate dentry + inode
    /// caches in a single round-trip (FUSE READDIRPLUS). The host
    /// increments lookup count once per entry returned (the kernel will
    /// `Forget` them later).
    ReadDirPlus {
        fh: u64,
        offset: u64,
    },

    /// Release the directory handle.
    ReleaseDir {
        fh: u64,
    },

    /// Open a file handle. `flags` is a subset of POSIX `O_*` (we only
    /// look at the access mode and `O_TRUNC`).
    Open {
        nodeid: u64,
        flags: u32,
    },

    /// Read `size` bytes at `offset`. `size` ≤ [`MAX_IO_CHUNK`].
    Read {
        fh: u64,
        offset: u64,
        size: u32,
    },

    /// Write `data` at `offset`. The host accumulates writes in a
    /// per-fh staging buffer and flushes on `Flush`/`Release`.
    Write {
        fh: u64,
        offset: u64,
        data: Vec<u8>,
    },

    /// Flush staged writes to the backend.
    Flush {
        fh: u64,
    },

    /// Release the file handle (drains staged writes, then drops fh).
    Release {
        fh: u64,
    },

    Mkdir {
        parent_nodeid: u64,
        name: String,
        mode: u32,
    },
    /// Create a non-regular, non-directory inode (Unix domain socket,
    /// FIFO, or device node). The `mode` includes the S_IFMT bits
    /// (S_IFSOCK / S_IFIFO / S_IFCHR / S_IFBLK) which the host inspects
    /// to pick the right creation primitive. `rdev` is meaningful only
    /// for `S_IFCHR` / `S_IFBLK` (ignored for socket/fifo). Hosts that
    /// can't create the requested type respond with `Errno::Enosys` or
    /// `Errno::Eperm` (e.g. char/block devs without `CAP_MKNOD`).
    ///
    /// Added in protocol v2. The most common driver is AF_UNIX
    /// `bind(2)` on a FUSE-backed path, which the kernel translates
    /// into `FUSE_MKNOD` with `mode = S_IFSOCK | <perm>`.
    Mknod {
        parent_nodeid: u64,
        name: String,
        mode: u32,
        rdev: u32,
    },
    /// Create an empty regular file. Returns an entry the guest can
    /// immediately Open. Added in protocol v1.1 — host stubs that don't
    /// support it should respond with `Errno::Enosys` so the kernel
    /// falls back to `mknod` (which we don't implement).
    Create {
        parent_nodeid: u64,
        name: String,
        mode: u32,
    },
    Rmdir {
        parent_nodeid: u64,
        name: String,
    },
    Unlink {
        parent_nodeid: u64,
        name: String,
    },
    /// `Rename` covers both same-parent rename and cross-parent move; the
    /// host picks `as_rename()` vs `as_move()` based on equality of
    /// parents.
    Rename {
        old_parent: u64,
        old_name: String,
        new_parent: u64,
        new_name: String,
    },

    /// Filesystem stats (block size, free space). Host returns canned
    /// values; backends rarely have a real answer.
    Statfs {
        nodeid: u64,
    },

    /// Create a symbolic link `name` under `parent_nodeid` whose
    /// contents are `target` (raw, unresolved — POSIX semantics).
    /// Response: [`Res::Entry`] for the new link.
    Symlink {
        parent_nodeid: u64,
        name: String,
        target: String,
    },

    /// Read the raw target of an existing symlink. Response:
    /// [`Res::Linkname`]. Returns ENOSYS when the backend doesn't
    /// implement readlink (the kernel will then surface EINVAL to
    /// userspace, matching the behaviour of a regular file's readlink).
    Readlink {
        nodeid: u64,
    },

    // ---- v3 ----
    /// Create a hard link `new_name` under `new_parent` pointing at
    /// the same inode as `nodeid`. Response: [`Res::Entry`]. Backends
    /// without hard-link support reply `Errno::Enosys`. Cross-mount
    /// links return `Errno::Exdev`-equivalent (`Einval`).
    Link {
        nodeid: u64,
        new_parent: u64,
        new_name: String,
    },

    /// Flush in-flight data for an open file. `datasync = true` ⇒ data
    /// only (POSIX `fdatasync`); `false` ⇒ data + metadata. Backends
    /// that have no concept of dirty data reply `Res::Ok` directly.
    Fsync {
        fh: u64,
        datasync: bool,
    },

    /// Like [`Req::Fsync`] but for an open directory handle.
    Fsyncdir {
        fh: u64,
        datasync: bool,
    },

    /// Set an extended attribute. `flags` follows Linux `setxattr(2)`
    /// (`XATTR_CREATE`/`XATTR_REPLACE`). Response: [`Res::Ok`].
    Setxattr {
        nodeid: u64,
        name: String,
        value: Vec<u8>,
        flags: u32,
    },

    /// Get an extended attribute. If `size == 0` the host replies with
    /// [`Res::XattrSize`] reporting the required buffer size. Otherwise
    /// the host replies with [`Res::Bytes`] containing the value (or
    /// `Errno::Erange` if `size` is too small).
    Getxattr {
        nodeid: u64,
        name: String,
        size: u32,
    },

    /// List extended attribute names. Same size/probe protocol as
    /// [`Req::Getxattr`]: `size == 0` ⇒ [`Res::XattrSize`]; otherwise
    /// [`Res::XattrList`] with NUL-separated names.
    Listxattr {
        nodeid: u64,
        size: u32,
    },

    Removexattr {
        nodeid: u64,
        name: String,
    },

    /// Permission probe (`access(2)`). `mask` is a bitmask of `R_OK`,
    /// `W_OK`, `X_OK`. Response: [`Res::Ok`] when access is permitted,
    /// [`Res::Error`] otherwise.
    Access {
        nodeid: u64,
        mask: u32,
    },

    /// Preallocate or punch a hole in an open file. `mode` follows
    /// `fallocate(2)` (`FALLOC_FL_KEEP_SIZE`, `FALLOC_FL_PUNCH_HOLE`,
    /// ...). Linux-only; other platforms reply `Errno::Enotsup`.
    Fallocate {
        fh: u64,
        offset: i64,
        length: i64,
        mode: u32,
    },

    /// Server-side range copy between two open files of the same mount.
    /// On Linux this maps to `copy_file_range(2)`; other platforms reply
    /// `Errno::Enotsup`. Response: [`Res::Written`].
    CopyFileRange {
        fh_in: u64,
        off_in: i64,
        fh_out: u64,
        off_out: i64,
        len: u64,
        flags: u32,
    },

    /// Probe for a conflicting lock. Response: [`Res::Lock`] echoing
    /// the existing conflict (or `LockType::Unlock` when the range is
    /// free).
    Getlk {
        fh: u64,
        owner: u64,
        lk: LockSpec,
    },

    /// Acquire / release a lock on the open file. `sleep == true` ⇒
    /// blocking variant (`F_OFD_SETLKW`); otherwise non-blocking
    /// (`F_OFD_SETLK`). Response: [`Res::Ok`] or [`Res::Error`]
    /// (`Eagain`/`Eintr`/`Edeadlk`).
    Setlk {
        fh: u64,
        owner: u64,
        lk: LockSpec,
        sleep: bool,
    },

    /// `lseek(2)` SEEK_DATA / SEEK_HOLE on a sparse file. `whence`
    /// follows the kernel constants (`SEEK_SET=0`, `SEEK_CUR=1`,
    /// `SEEK_END=2`, `SEEK_DATA=3`, `SEEK_HOLE=4`). Response:
    /// [`Res::Offset`].
    Lseek {
        fh: u64,
        offset: i64,
        whence: u32,
    },

    /// Block map (block-device backed filesystems). Almost always
    /// `Errno::Enosys` — our FUSE mounts are never `blkdev`.
    Bmap {
        nodeid: u64,
        blocksize: u32,
        idx: u64,
    },

    /// Pass-through ioctl on an open file. Almost always
    /// `Errno::Enotsup` — we don't trust arbitrary host ioctls.
    Ioctl {
        fh: u64,
        cmd: u32,
        arg: u64,
        in_data: Vec<u8>,
        out_size: u32,
        flags: u32,
    },

    /// Poll an open file for readiness. Almost always `Errno::Enosys`
    /// — FUSE clients fall back to local polling.
    Poll {
        fh: u64,
        events: u32,
        flags: u32,
    },
}

// ---------------------------------------------------------------------------
// Responses (host → guest)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Res {
    Ok,
    Error(WireError),
    Entry(EntryOut),
    Attr(AttrOut),
    OpenOk {
        fh: u64,
    },
    DirEntries(Vec<DirEntry>),
    DirEntriesPlus(Vec<DirEntryPlus>),
    Bytes(Vec<u8>),
    Written {
        size: u32,
    },
    Statfs(StatfsOut),
    /// Symlink target string (response to [`Req::Readlink`]).
    Linkname(String),

    // ---- v3 ----
    /// Size probe reply for [`Req::Getxattr`] / [`Req::Listxattr`] with
    /// `size == 0`.
    XattrSize(u32),
    /// NUL-separated xattr names (response to [`Req::Listxattr`] with
    /// `size > 0`).
    XattrList(Vec<u8>),
    /// Lock probe reply (response to [`Req::Getlk`]).
    Lock(LockSpec),
    /// File offset reply (response to [`Req::Lseek`]).
    Offset(i64),
    /// Block-map reply (response to [`Req::Bmap`]).
    BmapBlock(u64),
    /// Ioctl reply: `result` is the integer return value, `data` is the
    /// out buffer (may be empty).
    Ioctl {
        result: i32,
        data: Vec<u8>,
    },
    /// Poll reply (response to [`Req::Poll`]).
    Poll {
        revents: u32,
    },
}

/// Lock range / type used by [`Req::Getlk`] / [`Req::Setlk`] /
/// [`Res::Lock`]. `whence` is informational and follows POSIX
/// (`SEEK_SET = 0`). On the host we always serialise to absolute
/// offsets before any syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockSpec {
    pub typ: LockType,
    pub whence: u32,
    pub start: u64,
    pub end: u64,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockType {
    Read,
    Write,
    Unlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub attr: AttrOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttrOut {
    pub size: u64,
    pub blocks: u64,
    pub mtime: i64, // unix seconds
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub kind: NodeKind,
    /// Device id for char/block device nodes. `0` for every other kind.
    /// Added in protocol v2.
    #[serde(default)]
    pub rdev: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
    /// AF_UNIX socket on-disk inode (S_IFSOCK).
    Socket,
    /// Named pipe / FIFO (S_IFIFO).
    Fifo,
    /// Block device node (S_IFBLK).
    BlockDev,
    /// Character device node (S_IFCHR).
    CharDev,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub nodeid: u64,
    pub offset: u64,
    pub kind: NodeKind,
    pub name: String,
}

/// READDIRPLUS entry: same as [`DirEntry`] but with full attrs so the
/// kernel can satisfy subsequent `getattr`/`lookup` from cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntryPlus {
    pub offset: u64,
    pub name: String,
    pub entry: EntryOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatfsOut {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Wire-level error. `errno` is the POSIX errno the guest will hand to
/// the FUSE kernel; `message` is for host-side logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub errno: i32,
    pub message: String,
}

impl WireError {
    pub fn new(errno: Errno, msg: impl Into<String>) -> Self {
        Self {
            errno: errno as i32,
            message: msg.into(),
        }
    }
}

/// Subset of POSIX errno values used at the FUSE boundary. Numeric values
/// match Linux libc — guests are always Linux.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    Eperm = 1,
    Enoent = 2,
    Eio = 5,
    Enxio = 6,
    Eacces = 13,
    Eexist = 17,
    Enotdir = 20,
    Eisdir = 21,
    Einval = 22,
    Erofs = 30,
    Enosys = 38,
    Etimedout = 110,
    Enotempty = 39,
    /// `ERANGE` — passed buffer too small (getxattr/listxattr probe).
    Erange = 34,
    /// `ENODATA` — xattr not present.
    Enodata = 61,
    /// `ENOTSUP` — operation not supported on this backend / platform.
    Enotsup = 95,
}

/// Map a [`VfsError`] to the wire error.
pub fn errno_for(err: &VfsError) -> WireError {
    let (errno, msg) = match err {
        VfsError::NotFound => (Errno::Enoent, err.to_string()),
        VfsError::AlreadyExists => (Errno::Eexist, err.to_string()),
        VfsError::PermissionDenied | VfsError::Unauthorized => (Errno::Eacces, err.to_string()),
        VfsError::NotImplemented(_) => (Errno::Enosys, err.to_string()),
        VfsError::NotSupported(_) => (Errno::Enotsup, err.to_string()),
        VfsError::OutOfRange(_) => (Errno::Erange, err.to_string()),
        VfsError::NoData(_) => (Errno::Enodata, err.to_string()),
        VfsError::NoSuchDeviceOrAddress(_) => (Errno::Enxio, err.to_string()),
        VfsError::IsDir => (Errno::Eisdir, err.to_string()),
        VfsError::NotDir => (Errno::Enotdir, err.to_string()),
        VfsError::InvalidArgument(_) => (Errno::Einval, err.to_string()),
        VfsError::Timeout => (Errno::Etimedout, err.to_string()),
        VfsError::Io(_) | VfsError::Other(_) => (Errno::Eio, err.to_string()),
    };
    WireError {
        errno: errno as i32,
        message: msg,
    }
}

// ---------------------------------------------------------------------------
// Server-pushed invalidations (reserved for v2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Inval {
    Entry { parent_nodeid: u64, name: String },
    Inode { nodeid: u64, off: i64, len: i64 },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hello() {
        let frame = Frame::Hello {
            proto_version: PROTOCOL_VERSION,
            max_inflight: 64,
            client_name: "tokimo-sandbox-fuse".into(),
            mount_name: Some("work".into()),
        };
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let back: Frame = postcard::from_bytes(&bytes).unwrap();
        match back {
            Frame::Hello {
                proto_version,
                max_inflight,
                client_name,
                mount_name,
            } => {
                assert_eq!(proto_version, PROTOCOL_VERSION);
                assert_eq!(max_inflight, 64);
                assert_eq!(client_name, "tokimo-sandbox-fuse");
                assert_eq!(mount_name.as_deref(), Some("work"));
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn roundtrip_request_response() {
        let frame = Frame::Request {
            req_id: 42,
            mount_id: 7,
            op: Req::Lookup {
                parent_nodeid: 1,
                name: "hello.txt".into(),
            },
        };
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let back: Frame = postcard::from_bytes(&bytes).unwrap();
        if let Frame::Request {
            req_id,
            mount_id,
            op: Req::Lookup { parent_nodeid, name },
        } = back
        {
            assert_eq!(req_id, 42);
            assert_eq!(mount_id, 7);
            assert_eq!(parent_nodeid, 1);
            assert_eq!(name, "hello.txt");
        } else {
            panic!("wrong variant");
        }

        let resp = Frame::Response {
            req_id: 42,
            result: Res::Entry(EntryOut {
                nodeid: 99,
                generation: 1,
                attr: AttrOut {
                    size: 5,
                    blocks: 1,
                    mtime: 0,
                    mode: 0o644,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    kind: NodeKind::File,
                    rdev: 0,
                },
            }),
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let _back: Frame = postcard::from_bytes(&bytes).unwrap();
    }

    #[test]
    fn errno_mapping_covers_all_variants() {
        for v in [
            VfsError::NotFound,
            VfsError::AlreadyExists,
            VfsError::PermissionDenied,
            VfsError::NotImplemented("x".into()),
            VfsError::IsDir,
            VfsError::NotDir,
            VfsError::InvalidArgument("y".into()),
            VfsError::Io("z".into()),
            VfsError::Unauthorized,
            VfsError::Timeout,
            VfsError::Other("o".into()),
            VfsError::NotSupported("ns".into()),
            VfsError::OutOfRange("r".into()),
            VfsError::NoData("nd".into()),
            VfsError::NoSuchDeviceOrAddress("nx".into()),
        ] {
            let we = errno_for(&v);
            assert!(we.errno > 0, "{:?} → 0", v);
        }
    }

    #[test]
    fn frame_size_under_cap() {
        // 1 MiB chunk + small metadata stays well under MAX_FRAME_BYTES
        let payload = vec![0u8; MAX_IO_CHUNK];
        let frame = Frame::Response {
            req_id: 1,
            result: Res::Bytes(payload),
        };
        let bytes = postcard::to_allocvec(&frame).unwrap();
        assert!(bytes.len() < MAX_FRAME_BYTES as usize);
        // postcard varint length encoding adds <8 bytes overhead
        assert!(bytes.len() < MAX_IO_CHUNK + 64);
    }

    #[test]
    fn v3_req_res_roundtrip() {
        let reqs = [
            Req::Link {
                nodeid: 7,
                new_parent: 1,
                new_name: "h".into(),
            },
            Req::Fsync { fh: 9, datasync: true },
            Req::Setxattr {
                nodeid: 1,
                name: "user.foo".into(),
                value: b"bar".to_vec(),
                flags: 0,
            },
            Req::Getxattr {
                nodeid: 1,
                name: "user.foo".into(),
                size: 0,
            },
            Req::Fallocate {
                fh: 1,
                offset: 0,
                length: 4096,
                mode: 0,
            },
            Req::Lseek {
                fh: 1,
                offset: 0,
                whence: 3,
            },
        ];
        for r in reqs {
            let f = Frame::Request {
                req_id: 1,
                mount_id: 0,
                op: r.clone(),
            };
            let bytes = postcard::to_allocvec(&f).unwrap();
            let back: Frame = postcard::from_bytes(&bytes).unwrap();
            match back {
                Frame::Request { op, .. } => {
                    // Just confirm same discriminant via Debug.
                    assert_eq!(format!("{:?}", op), format!("{:?}", r));
                }
                _ => panic!("expected request frame"),
            }
        }

        let resps = [
            Res::XattrSize(42),
            Res::XattrList(b"user.a\0user.b\0".to_vec()),
            Res::Lock(LockSpec {
                typ: LockType::Read,
                whence: 0,
                start: 0,
                end: 100,
                pid: 1,
            }),
            Res::Offset(4096),
            Res::BmapBlock(0),
            Res::Ioctl {
                result: 0,
                data: vec![1, 2, 3],
            },
            Res::Poll { revents: 0 },
        ];
        for r in resps {
            let f = Frame::Response {
                req_id: 1,
                result: r.clone(),
            };
            let bytes = postcard::to_allocvec(&f).unwrap();
            let back: Frame = postcard::from_bytes(&bytes).unwrap();
            assert!(matches!(back, Frame::Response { .. }));
        }
    }
}
