//! Host-side VFS backend trait — interface contract for FUSE-over-vsock
//! dynamic mounts.
//!
//! Shape and naming are deliberately a 1:1 mirror of the
//! `tokimo-package-vfs` crate's `Driver` trait family (Reader / Mkdir /
//! DeleteFile / DeleteDir / Rename / MoveFile / CopyFile / PutFile /
//! PutStream / ResolveLocal). We do **not** depend on `tokimo-package-vfs`
//! as a Cargo dependency — users who want to expose a `tokimo-vfs::Driver`
//! to the sandbox write a thin (~30 LoC) adapter that re-implements
//! [`VfsBackend`] in terms of their `Driver`.
//!
//! # Why mirror, not depend
//!
//! - Sandbox is a security primitive. Pulling in 30+ transitive crates
//!   from the VFS ecosystem (cloud SDKs, SMB stack, NTLMv2, etc.) is the
//!   wrong supply-chain trade-off for everyone who only needs a local
//!   directory mount.
//! - Trait shape is small and stable; an adapter is trivial to maintain.
//!
//! # Capability degradation
//!
//! Like the upstream design, the only mandatory capability is read.
//! Writes / mutations are opt-in via `as_*()` downcasts. The FUSE bridge
//! maps `as_put().is_none()` to `EROFS` for `O_WRONLY`/`O_RDWR` opens,
//! and `as_mkdir().is_none()` to `ENOSYS` for `mkdir(2)`, etc. — see
//! [`crate::vfs_protocol`] for the full op → errno table.
//!
//! # Async story
//!
//! All trait methods are `async`. Users plug their `tokio` runtime into
//! the host (the `vfs_host` module assumes a multi-threaded tokio runtime
//! is already running on the calling thread).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors a [`VfsBackend`] may return. Maps cleanly to a small `errno` set
/// at the FUSE boundary (see [`crate::vfs_protocol::errno_for`]).
#[derive(Debug, Clone, thiserror::Error)]
pub enum VfsError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("permission denied")]
    PermissionDenied,
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("is a directory")]
    IsDir,
    #[error("not a directory")]
    NotDir,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
    /// Operation not supported by this backend on this platform.
    /// Maps to `ENOTSUP` (95) on the wire.
    #[error("not supported: {0}")]
    NotSupported(String),
    /// Provided buffer too small (e.g. `getxattr` probe).
    /// Maps to `ERANGE` (34).
    #[error("out of range: {0}")]
    OutOfRange(String),
    /// Attribute / data not present (e.g. xattr name missing).
    /// Maps to `ENODATA` (61).
    #[error("no data: {0}")]
    NoData(String),
    /// No such device or address (e.g. `SEEK_DATA` past EOF).
    /// Maps to `ENXIO` (6).
    #[error("no such device or address: {0}")]
    NoSuchDeviceOrAddress(String),
}

impl From<std::io::Error> for VfsError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::NotFound => VfsError::NotFound,
            ErrorKind::AlreadyExists => VfsError::AlreadyExists,
            ErrorKind::PermissionDenied => VfsError::PermissionDenied,
            ErrorKind::TimedOut => VfsError::Timeout,
            ErrorKind::Unsupported => VfsError::NotSupported(err.to_string()),
            ErrorKind::InvalidInput | ErrorKind::InvalidData => VfsError::InvalidArgument(err.to_string()),
            _ => VfsError::Io(err.to_string()),
        }
    }
}

pub type VfsResult<T> = Result<T, VfsError>;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// File / directory metadata returned by [`VfsReader::stat`] and
/// [`VfsReader::list`].
///
/// `name` is the leaf name (no path separators). For the export root the
/// FUSE bridge synthesises `name = ""`.
///
/// `is_dir` and `is_symlink` are mutually exclusive (a symlink to a dir
/// is reported as `is_symlink: true, is_dir: false` — i.e. lstat semantics).
/// The bridge picks `NodeKind::Symlink` over `Dir`/`File` when
/// `is_symlink == true`.
#[derive(Debug, Clone)]
pub struct VfsFileInfo {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// `true` if this entry IS a symlink itself (lstat semantics, the
    /// link is NOT followed). Backends that don't support symlinks
    /// can ignore this and leave it `false`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub is_symlink: bool,
    /// `true` if this entry is an AF_UNIX socket on-disk inode
    /// (`S_IFSOCK`). Created via [`VfsMknod`]. The flag is mutually
    /// exclusive with `is_dir` / `is_symlink` / `is_fifo` / `is_*_device`.
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    pub is_socket: bool,
    /// `true` if this entry is a named pipe / FIFO (`S_IFIFO`).
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    pub is_fifo: bool,
    /// `true` if this entry is a block device node (`S_IFBLK`).
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    pub is_block_device: bool,
    /// `true` if this entry is a character device node (`S_IFCHR`).
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    pub is_char_device: bool,
    pub modified: Option<SystemTime>,
    /// POSIX mode bits (lower 12). `None` → bridge picks 0o755 (dir) or
    /// 0o644 (file).
    pub mode: Option<u32>,
    /// `st_rdev` for char/block device nodes. `0` for everything else.
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    pub rdev: u32,
    /// Hard-link count (`st_nlink`). Defaults to 1. Backends that don't
    /// track links (in-memory, etc.) can leave the default; passthrough
    /// backends read this from host metadata so `stat -c %h` reports the
    /// correct count after `link(2)`.
    pub nlink: u32,
    /// Underlying filesystem inode number (`st_ino`). `0` means
    /// "unknown / not exposed" — the FUSE host falls back to path-only
    /// nodeid keying for such entries and cannot dedup hard links.
    /// Passthrough backends (`LocalDirVfs`) populate this from host
    /// metadata so that two paths pointing at the same inode resolve to
    /// the same nodeid.
    pub ino: u64,
    /// Underlying filesystem device id (`st_dev`). Pairs with [`ino`](Self::ino)
    /// to form the inode-dedup key. `0` for backends that don't expose it.
    pub dev: u64,
}

impl VfsFileInfo {
    /// Construct a default `VfsFileInfo` carrying just the common fields
    /// (`name`/`size`/`is_dir`/`mode`/`modified`). All special-inode
    /// flags default to `false` / `0`. Intended for in-memory backends
    /// where socket/FIFO/device nodes don't apply.
    pub fn basic(name: String, size: u64, is_dir: bool, mode: Option<u32>, modified: Option<SystemTime>) -> Self {
        Self {
            name,
            size,
            is_dir,
            is_symlink: false,
            is_socket: false,
            is_fifo: false,
            is_block_device: false,
            is_char_device: false,
            modified,
            mode,
            rdev: 0,
            nlink: 1,
            ino: 0,
            dev: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Mandatory: read
// ---------------------------------------------------------------------------

/// Mandatory read capability. Every `VfsBackend` must implement this.
///
/// Paths are absolute, slash-separated, and rooted at the mount export
/// (i.e. `/` is the directory the user mounted). The FUSE bridge
/// guarantees no `..` or symlink traversal escapes `/`.
#[async_trait]
pub trait VfsReader: Send + Sync + 'static {
    async fn list(&self, path: &Path) -> VfsResult<Vec<VfsFileInfo>>;

    async fn stat(&self, path: &Path) -> VfsResult<VfsFileInfo>;

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> VfsResult<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Optional capabilities
// ---------------------------------------------------------------------------

#[async_trait]
pub trait VfsMkdir: Send + Sync + 'static {
    async fn mkdir(&self, path: &Path) -> VfsResult<()>;
}

#[async_trait]
pub trait VfsDeleteFile: Send + Sync + 'static {
    async fn delete_file(&self, path: &Path) -> VfsResult<()>;
}

#[async_trait]
pub trait VfsDeleteDir: Send + Sync + 'static {
    async fn delete_dir(&self, path: &Path) -> VfsResult<()>;
}

#[async_trait]
pub trait VfsRename: Send + Sync + 'static {
    async fn rename(&self, from: &Path, to: &Path) -> VfsResult<()>;
}

/// Create a symbolic link `link_path` whose contents (raw target string)
/// are exactly `target`. POSIX semantics: `target` is stored verbatim
/// — no path resolution, no existence check. Dangling links are valid.
///
/// On Windows hosts the implementation has to pick "file" vs "directory"
/// symlink type at creation time (NTFS quirk; POSIX does not have this
/// concept). The recommended strategy is documented on the impl: probe
/// the resolved target relative to `link_path`'s parent and pick
/// `symlink_dir` only when that probe lands on an existing directory;
/// fall back to `symlink_file` otherwise (this matches how `tar -x`,
/// `git clone`, and Cygwin/WSL all behave on Windows).
#[async_trait]
pub trait VfsSymlink: Send + Sync + 'static {
    async fn symlink(&self, target: &str, link_path: &Path) -> VfsResult<()>;
}

/// Read the raw target string of an existing symlink. Returns the
/// target verbatim (NOT resolved against the link's parent); callers
/// that want a resolved path must do that themselves.
#[async_trait]
pub trait VfsReadlink: Send + Sync + 'static {
    async fn readlink(&self, link_path: &Path) -> VfsResult<String>;
}

/// Create a non-regular, non-directory inode (Unix domain socket, FIFO,
/// or device node). `mode` includes the `S_IFMT` bits — the
/// implementation inspects them to choose the right creation primitive
/// (`mknod(2)` on Unix; an empty file with `$LXMOD` EA on Windows for
/// sockets/FIFOs since NTFS has no native S_IFSOCK/S_IFIFO inode type).
///
/// `rdev` is meaningful only when `mode & S_IFMT` is `S_IFCHR` or
/// `S_IFBLK`. Implementations that cannot create the requested kind
/// return `VfsError::NotImplemented` (mapped to `ENOSYS` on the wire).
/// Block/char-device creation typically requires `CAP_MKNOD` and will
/// return `PermissionDenied` (→ `EPERM`) when the host runs unprivileged.
#[async_trait]
pub trait VfsMknod: Send + Sync + 'static {
    async fn mknod(&self, path: &Path, mode: u32, rdev: u32) -> VfsResult<()>;
}

#[async_trait]
pub trait VfsMove: Send + Sync + 'static {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> VfsResult<()>;
}

#[async_trait]
pub trait VfsCopy: Send + Sync + 'static {
    async fn copy(&self, from: &Path, to: &Path) -> VfsResult<()>;
}

#[async_trait]
pub trait VfsPut: Send + Sync + 'static {
    async fn put(&self, path: &Path, data: Vec<u8>) -> VfsResult<()>;
}

/// Streaming upload. Receives chunks via a tokio mpsc channel; avoids
/// buffering the entire file in host memory. The bridge prefers this
/// over [`VfsPut`] when the staged write is larger than a small threshold.
#[async_trait]
pub trait VfsPutStream: Send + Sync + 'static {
    async fn put_stream(&self, path: &Path, size: u64, rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> VfsResult<()>;
}

/// If the backend is a real local directory, expose the underlying host
/// path. The bridge can use this to short-circuit large reads/writes by
/// opening the host path directly (avoiding the staging tempfile dance).
pub trait VfsResolveLocal: Send + Sync + 'static {
    fn resolve_real_path(&self, path: &Path) -> Option<PathBuf>;
}

/// Hard-link an existing path to a new path. Both paths must live under
/// the same mount; cross-mount links return `InvalidArgument` (mapped to
/// `EXDEV`-equivalent `EINVAL`).
#[async_trait]
pub trait VfsLink: Send + Sync + 'static {
    async fn hard_link(&self, src: &Path, dst: &Path) -> VfsResult<()>;
}

/// Extended attribute capability (`*xattr(2)` family). All names are
/// arbitrary opaque strings (the kernel pre-validates namespace prefixes
/// on Linux).
#[async_trait]
pub trait VfsXattr: Send + Sync + 'static {
    async fn get_xattr(&self, path: &Path, name: &str) -> VfsResult<Vec<u8>>;
    async fn set_xattr(&self, path: &Path, name: &str, value: &[u8], flags: u32) -> VfsResult<()>;
    async fn list_xattr(&self, path: &Path) -> VfsResult<Vec<u8>>;
    async fn remove_xattr(&self, path: &Path, name: &str) -> VfsResult<()>;
}

/// `access(2)` permission probe. Implementations may consult the host
/// kernel or the backend's own ACL model. `mask` is a bitmask of POSIX
/// `R_OK = 4`, `W_OK = 2`, `X_OK = 1`, `F_OK = 0`.
#[async_trait]
pub trait VfsAccess: Send + Sync + 'static {
    async fn access(&self, path: &Path, mask: u32) -> VfsResult<()>;
}

// ---------------------------------------------------------------------------
// The umbrella trait
// ---------------------------------------------------------------------------

/// The single trait an `Arc<dyn VfsBackend>` must satisfy. Required:
/// [`VfsReader`]. All other capabilities are opt-in via `as_*()`
/// downcasts.
pub trait VfsBackend: VfsReader {
    fn as_mkdir(&self) -> Option<&dyn VfsMkdir> {
        None
    }
    fn as_delete_file(&self) -> Option<&dyn VfsDeleteFile> {
        None
    }
    fn as_delete_dir(&self) -> Option<&dyn VfsDeleteDir> {
        None
    }
    fn as_rename(&self) -> Option<&dyn VfsRename> {
        None
    }
    fn as_symlink(&self) -> Option<&dyn VfsSymlink> {
        None
    }
    fn as_readlink(&self) -> Option<&dyn VfsReadlink> {
        None
    }
    fn as_mknod(&self) -> Option<&dyn VfsMknod> {
        None
    }
    fn as_move(&self) -> Option<&dyn VfsMove> {
        None
    }
    fn as_copy(&self) -> Option<&dyn VfsCopy> {
        None
    }
    fn as_put(&self) -> Option<&dyn VfsPut> {
        None
    }
    fn as_put_stream(&self) -> Option<&dyn VfsPutStream> {
        None
    }
    fn as_resolve_local(&self) -> Option<&dyn VfsResolveLocal> {
        None
    }
    fn as_link(&self) -> Option<&dyn VfsLink> {
        None
    }
    fn as_xattr(&self) -> Option<&dyn VfsXattr> {
        None
    }
    fn as_access(&self) -> Option<&dyn VfsAccess> {
        None
    }

    /// If this backend mirrors a single on-host directory whose contents
    /// may be mutated by processes outside the FUSE session, return that
    /// directory. The host will spawn a filesystem watcher (inotify /
    /// FSEvents / ReadDirectoryChangesW) on this path and translate
    /// external mutations into `FUSE_NOTIFY_INVAL_ENTRY` /
    /// `FUSE_NOTIFY_INVAL_INODE` frames so the guest kernel caches
    /// never go stale inside our 60 s entry/attr TTL.
    ///
    /// Defaults to `None`. In-memory or fully-mediated backends (where
    /// every mutation already flows through this `FuseHost`) should
    /// keep the default.
    fn watch_root(&self) -> Option<std::path::PathBuf> {
        None
    }
}

/// Convenience alias used by the Sandbox API.
pub type SharedVfsBackend = Arc<dyn VfsBackend>;
