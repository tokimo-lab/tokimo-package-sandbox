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
}

impl From<std::io::Error> for VfsError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::NotFound => VfsError::NotFound,
            ErrorKind::AlreadyExists => VfsError::AlreadyExists,
            ErrorKind::PermissionDenied => VfsError::PermissionDenied,
            ErrorKind::TimedOut => VfsError::Timeout,
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
#[derive(Debug, Clone)]
pub struct VfsFileInfo {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: Option<SystemTime>,
    /// POSIX mode bits (lower 12). `None` → bridge picks 0o755 (dir) or
    /// 0o644 (file).
    pub mode: Option<u32>,
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
}

/// Convenience alias used by the Sandbox API.
pub type SharedVfsBackend = Arc<dyn VfsBackend>;
