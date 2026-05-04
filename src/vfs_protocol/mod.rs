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
pub const PROTOCOL_VERSION: u32 = 1;

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
    OpenOk { fh: u64 },
    DirEntries(Vec<DirEntry>),
    Bytes(Vec<u8>),
    Written { size: u32 },
    Statfs(StatfsOut),
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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub nodeid: u64,
    pub offset: u64,
    pub kind: NodeKind,
    pub name: String,
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
    Eacces = 13,
    Eexist = 17,
    Enotdir = 20,
    Eisdir = 21,
    Einval = 22,
    Erofs = 30,
    Enosys = 38,
    Etimedout = 110,
    Enotempty = 39,
}

/// Map a [`VfsError`] to the wire error.
pub fn errno_for(err: &VfsError) -> WireError {
    let (errno, msg) = match err {
        VfsError::NotFound => (Errno::Enoent, err.to_string()),
        VfsError::AlreadyExists => (Errno::Eexist, err.to_string()),
        VfsError::PermissionDenied | VfsError::Unauthorized => (Errno::Eacces, err.to_string()),
        VfsError::NotImplemented(_) => (Errno::Enosys, err.to_string()),
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
}
