//! Built-in [`VfsBackend`] implementations.
//!
//! - [`LocalDirVfs`] — host directory passthrough, equivalent to the old
//!   `Mount.host_path` semantics. Used by `Mount::local_dir(...)`.
//! - [`MemFsVfs`] — in-memory filesystem, tests / fixtures.
//!
//! Both are deliberately straightforward: the FUSE bridge handles caching,
//! handle bookkeeping, and write staging — backends only have to translate
//! one logical operation per trait method.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::vfs_backend::{
    VfsBackend, VfsCopy, VfsDeleteDir, VfsDeleteFile, VfsError, VfsFileInfo, VfsMkdir, VfsMknod, VfsMove, VfsPut,
    VfsReader, VfsReadlink, VfsRename, VfsResolveLocal, VfsResult, VfsSymlink,
};

// ---------------------------------------------------------------------------
// Path sanitisation
// ---------------------------------------------------------------------------

/// Reject `..`, absolute roots after the leading `/`, and any non-Normal
/// components. The bridge already guarantees this at the protocol layer,
/// but defence-in-depth: backends do their own check.
fn sanitize(path: &Path) -> VfsResult<&Path> {
    for c in path.components() {
        match c {
            Component::RootDir | Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(VfsError::InvalidArgument(format!(
                    "path contains ..: {}",
                    path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(VfsError::InvalidArgument(format!(
                    "path has prefix: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(path)
}

/// Strip a leading `/` so we can join under a host root.
fn relative_under(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

fn local_stat_error(err: std::io::Error) -> VfsError {
    #[cfg(windows)]
    if err.raw_os_error() == Some(123) {
        return VfsError::NotFound;
    }
    VfsError::from(err)
}

// ===========================================================================
// LocalDirVfs
// ===========================================================================

/// Maps the export root to a real host directory. All ops are forwarded to
/// `tokio::fs` / `std::fs`. Implements every optional capability.
#[derive(Debug)]
pub struct LocalDirVfs {
    root: PathBuf,
}

impl LocalDirVfs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn arc(root: impl Into<PathBuf>) -> Arc<dyn VfsBackend> {
        Arc::new(Self::new(root))
    }

    fn host_join(&self, path: &Path) -> VfsResult<PathBuf> {
        sanitize(path)?;
        Ok(self.root.join(relative_under(path)))
    }
}

#[async_trait]
impl VfsReader for LocalDirVfs {
    async fn list(&self, path: &Path) -> VfsResult<Vec<VfsFileInfo>> {
        let host = self.host_join(path)?;
        let mut rd = tokio::fs::read_dir(&host).await?;
        let mut out = Vec::new();
        while let Some(entry) = rd.next_entry().await? {
            // symlink_metadata: don't follow links, so symlink-typed
            // entries surface as symlinks rather than their target.
            // tokio::fs::DirEntry::metadata follows links, hence the
            // explicit symlink_metadata call here.
            let md = match tokio::fs::symlink_metadata(entry.path()).await {
                Ok(m) => m,
                Err(_) => continue, // skip racing-deleted entries
            };
            out.push(meta_to_info(
                entry.file_name().to_string_lossy().into_owned(),
                &entry.path(),
                md,
            ));
        }
        Ok(out)
    }

    async fn stat(&self, path: &Path) -> VfsResult<VfsFileInfo> {
        let host = self.host_join(path)?;
        // symlink_metadata gives lstat semantics — a symlink at `path`
        // is reported as a symlink, not its target. FUSE getattr/lookup
        // expect lstat (the kernel handles symlink traversal itself
        // by reading the link target via FUSE_READLINK).
        // Inline syscall for the same reason as before: avoids the
        // ~50µs spawn_blocking hop on the hot lookup path.
        let md = std::fs::symlink_metadata(&host).map_err(local_stat_error)?;
        let name = host
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(meta_to_info(name, &host, md))
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> VfsResult<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let host = self.host_join(path)?;
        let mut f = tokio::fs::File::open(&host).await?;
        if offset > 0 {
            f.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        let mut buf = match limit {
            Some(l) => Vec::with_capacity(l.min(1024 * 1024) as usize),
            None => Vec::new(),
        };
        match limit {
            Some(l) => {
                let mut take = f.take(l);
                take.read_to_end(&mut buf).await?;
            }
            None => {
                f.read_to_end(&mut buf).await?;
            }
        }
        Ok(buf)
    }
}

#[async_trait]
impl VfsMkdir for LocalDirVfs {
    async fn mkdir(&self, path: &Path) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::create_dir(&host).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsDeleteFile for LocalDirVfs {
    async fn delete_file(&self, path: &Path) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::remove_file(&host).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsDeleteDir for LocalDirVfs {
    async fn delete_dir(&self, path: &Path) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::remove_dir(&host).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsRename for LocalDirVfs {
    async fn rename(&self, from: &Path, to: &Path) -> VfsResult<()> {
        let f = self.host_join(from)?;
        let t = self.host_join(to)?;
        tokio::fs::rename(&f, &t).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsSymlink for LocalDirVfs {
    async fn symlink(&self, target: &str, link_path: &Path) -> VfsResult<()> {
        let host_link = self.host_join(link_path)?;
        // POSIX semantics: store `target` verbatim. No path resolution
        // — dangling links are valid, relative targets are resolved at
        // *read* time relative to the link's parent directory.
        #[cfg(unix)]
        {
            let target = target.to_string();
            let res = tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(&target, &host_link))
                .await
                .map_err(|e| VfsError::Io(e.to_string()))?;
            res?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let parent_host = host_link
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let probe = parent_host.join(target);
            let target_owned = target.to_string();
            let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                let is_dir = std::fs::metadata(&probe).map(|m| m.is_dir()).unwrap_or(false);
                if is_dir {
                    std::os::windows::fs::symlink_dir(&target_owned, &host_link)
                } else {
                    std::os::windows::fs::symlink_file(&target_owned, &host_link)
                }
            })
            .await
            .map_err(|e| VfsError::Io(e.to_string()))?;
            res?;
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, host_link);
            Err(VfsError::NotImplemented("symlink".into()))
        }
    }
}

#[async_trait]
impl VfsReadlink for LocalDirVfs {
    async fn readlink(&self, link_path: &Path) -> VfsResult<String> {
        let host = self.host_join(link_path)?;
        let target = tokio::fs::read_link(&host).await?;
        // POSIX symlink contents are an opaque byte string. Our wire
        // protocol carries them as String; on Unix paths are typically
        // UTF-8, on Windows always so. lossy conversion is acceptable
        // — non-UTF8 link targets are exceedingly rare and the FUSE
        // bridge already round-trips names through String elsewhere.
        Ok(target.to_string_lossy().into_owned())
    }
}

#[async_trait]
impl VfsMove for LocalDirVfs {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> VfsResult<()> {
        let f = self.host_join(from)?;
        let t_dir = self.host_join(to_dir)?;
        let name = f
            .file_name()
            .ok_or_else(|| VfsError::InvalidArgument("from has no file name".into()))?;
        tokio::fs::rename(&f, t_dir.join(name)).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsCopy for LocalDirVfs {
    async fn copy(&self, from: &Path, to: &Path) -> VfsResult<()> {
        let f = self.host_join(from)?;
        let t = self.host_join(to)?;
        tokio::fs::copy(&f, &t).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsPut for LocalDirVfs {
    async fn put(&self, path: &Path, data: Vec<u8>) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::write(&host, data).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsMknod for LocalDirVfs {
    async fn mknod(&self, path: &Path, mode: u32, rdev: u32) -> VfsResult<()> {
        let host = self.host_join(path)?;
        let kind_bits = mode & 0o170000;
        let perm_bits = mode & 0o7777;
        #[cfg(unix)]
        {
            use nix::sys::stat::{Mode, SFlag, mknod as nix_mknod};
            // Map S_IFMT → nix::SFlag. Reject unsupported kinds explicitly.
            let sflag = match kind_bits {
                0o140000 => SFlag::S_IFSOCK,
                0o010000 => SFlag::S_IFIFO,
                0o060000 => SFlag::S_IFBLK,
                0o020000 => SFlag::S_IFCHR,
                // Regular file (S_IFREG=0o100000) — fall through to a normal create.
                0o100000 | 0 => {
                    let _ = (rdev, perm_bits);
                    tokio::fs::write(&host, &[] as &[u8]).await?;
                    return Ok(());
                }
                _ => {
                    return Err(VfsError::InvalidArgument(format!(
                        "mknod: unsupported S_IFMT bits 0o{:o}",
                        kind_bits
                    )));
                }
            };
            // mknod(2) is blocking; offload to spawn_blocking.
            let host_cl = host.clone();
            let res = tokio::task::spawn_blocking(move || -> nix::Result<()> {
                let m = Mode::from_bits_truncate(perm_bits as nix::libc::mode_t);
                nix_mknod(&host_cl, sflag, m, rdev as nix::libc::dev_t)
            })
            .await
            .map_err(|e| VfsError::Io(e.to_string()))?;
            match res {
                Ok(()) => Ok(()),
                Err(nix::errno::Errno::EPERM) => Err(VfsError::PermissionDenied),
                Err(nix::errno::Errno::EEXIST) => Err(VfsError::AlreadyExists),
                Err(nix::errno::Errno::ENOENT) => Err(VfsError::NotFound),
                Err(e) => Err(VfsError::Io(format!("mknod: {e}"))),
            }
        }
        #[cfg(windows)]
        {
            use crate::windows::ntfs_mode::{FileKind, volume_supports_ea, write_mode_ea};
            // NTFS has no native socket/fifo/dev inode type. For sockets
            // and FIFOs we create an empty regular file and persist the
            // S_IFMT bits in the `$LXMOD` EA so subsequent stat()s
            // continue to report the right NodeKind. Without the EA
            // (non-NTFS volume), or for block/char devices, return
            // ENOSYS — guest code that needs real device nodes has no
            // sensible Windows fallback anyway.
            let host_cl = host.clone();
            let kind = match kind_bits {
                0o140000 => FileKind::Socket,
                0o010000 => FileKind::Fifo,
                0o100000 | 0 => {
                    // Plain regular file.
                    tokio::fs::write(&host, &[] as &[u8]).await?;
                    return Ok(());
                }
                0o060000 | 0o020000 => return Err(VfsError::PermissionDenied),
                _ => {
                    return Err(VfsError::InvalidArgument(format!(
                        "mknod: unsupported S_IFMT bits 0o{:o}",
                        kind_bits
                    )));
                }
            };
            // Create the placeholder file (must not exist yet).
            tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&host)
                .await?;
            // Persist the type + perm bits via $LXMOD EA. Without EA
            // support the inode silently degrades to a regular file —
            // surface that as ENOSYS so callers know AF_UNIX won't work.
            if !volume_supports_ea(&host_cl) {
                let _ = tokio::fs::remove_file(&host).await;
                return Err(VfsError::NotImplemented(
                    "mknod: volume does not support extended attributes".into(),
                ));
            }
            let _ = rdev;
            let host_for_blocking = host.clone();
            tokio::task::spawn_blocking(move || write_mode_ea(&host_for_blocking, perm_bits, kind))
                .await
                .map_err(|e| VfsError::Io(e.to_string()))?
                .map_err(|e| VfsError::Io(format!("write_mode_ea: {e}")))?;
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (host, mode, rdev, kind_bits, perm_bits);
            Err(VfsError::NotImplemented("mknod".into()))
        }
    }
}

impl VfsResolveLocal for LocalDirVfs {
    fn resolve_real_path(&self, path: &Path) -> Option<PathBuf> {
        sanitize(path).ok()?;
        Some(self.root.join(relative_under(path)))
    }
}

impl VfsBackend for LocalDirVfs {
    fn as_mkdir(&self) -> Option<&dyn VfsMkdir> {
        Some(self)
    }
    fn as_delete_file(&self) -> Option<&dyn VfsDeleteFile> {
        Some(self)
    }
    fn as_delete_dir(&self) -> Option<&dyn VfsDeleteDir> {
        Some(self)
    }
    fn as_rename(&self) -> Option<&dyn VfsRename> {
        Some(self)
    }
    fn as_symlink(&self) -> Option<&dyn VfsSymlink> {
        Some(self)
    }
    fn as_readlink(&self) -> Option<&dyn VfsReadlink> {
        Some(self)
    }
    fn as_move(&self) -> Option<&dyn VfsMove> {
        Some(self)
    }
    fn as_copy(&self) -> Option<&dyn VfsCopy> {
        Some(self)
    }
    fn as_put(&self) -> Option<&dyn VfsPut> {
        Some(self)
    }
    fn as_mknod(&self) -> Option<&dyn VfsMknod> {
        Some(self)
    }
    fn as_resolve_local(&self) -> Option<&dyn VfsResolveLocal> {
        Some(self)
    }
}

/// Converts raw filesystem metadata into [`VfsFileInfo`].
///
/// **Unix**: reads `st_mode` directly via `PermissionsExt::mode()`.
///
/// **Windows**: reads the `$LXMOD` NTFS Extended Attribute (4-byte LE u32,
/// WSL2 DrvFs `metadata` format).  `$LXUID` / `$LXGID` are intentionally
/// NOT read — uid/gid are always derived from the calling process token.
///
/// Fallback ladder when `$LXMOD` EA is absent or the volume does not support EA:
///
/// | Scenario                               | Returned mode      |
/// |----------------------------------------|--------------------|
/// | NTFS + `$LXMOD` EA present             | EA value           |
/// | NTFS + no EA + regular file            | 0o644              |
/// | NTFS + no EA + directory               | 0o755              |
/// | NTFS + no EA + symlink                 | 0o777              |
/// | non-NTFS (FAT32/exFAT/network) + file  | 0o755 (keep +x)    |
/// | non-NTFS + directory                   | 0o755              |
/// | non-NTFS + symlink                     | 0o777              |
///
/// On the fallback path (EA missing or non-NTFS volume) the NTFS readonly
/// attribute is checked: if the file is read-only, `0o222` (write bits) is
/// cleared from the fallback mode. EA-hit paths are not affected by the
/// readonly bit — `$LXMOD` EA is the authoritative source.
#[cfg_attr(not(windows), allow(unused_variables))]
fn meta_to_info(name: String, path: &std::path::Path, md: std::fs::Metadata) -> VfsFileInfo {
    // Unix: inspect the real file_type bits for socket/fifo/dev nodes.
    // Windows: derive the "logical" Unix type from `$LXMOD` EA so that
    // FUSE_MKNOD'd S_IFSOCK / S_IFIFO files round-trip across stat()
    // calls. Without this, an AF_UNIX socket bound on the host shows up
    // as a regular file on the next lookup and `connect()` fails with
    // ENOTSOCK in the guest.
    let (kind_mode, kind_rdev) = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let ft = md.file_type();
            let mut k = 0u32;
            if ft.is_socket() {
                k = 0o140000;
            } else if ft.is_fifo() {
                k = 0o010000;
            } else if ft.is_block_device() {
                k = 0o060000;
            } else if ft.is_char_device() {
                k = 0o020000;
            }
            (k, md.rdev() as u32)
        }
        #[cfg(windows)]
        {
            use crate::windows::ntfs_mode::{read_mode_ea_full, volume_supports_ea};
            let raw = if volume_supports_ea(path) {
                read_mode_ea_full(path).unwrap_or(0)
            } else {
                0
            };
            // S_IFMT = 0o170000
            let t = raw & 0o170000;
            (t, 0u32)
        }
        #[cfg(not(any(unix, windows)))]
        {
            (0u32, 0u32)
        }
    };
    let is_socket = kind_mode == 0o140000; // S_IFSOCK
    let is_fifo = kind_mode == 0o010000; // S_IFIFO
    let is_block_device = kind_mode == 0o060000; // S_IFBLK
    let is_char_device = kind_mode == 0o020000; // S_IFCHR

    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(md.permissions().mode() & 0o7777)
        }
        #[cfg(windows)]
        {
            use crate::windows::ntfs_mode::{read_mode_ea, volume_supports_ea};
            let ft_local = md.file_type();
            let writable = !md.permissions().readonly();
            // NTFS/ReFS volume: attempt to read $LXMOD EA; fall back to 0o644/0o755/0o777.
            let mode = if volume_supports_ea(path) {
                read_mode_ea(path).unwrap_or_else(|| {
                    let base = if md.is_dir() {
                        0o755
                    } else if ft_local.is_symlink() {
                        0o777
                    } else {
                        0o644
                    };
                    if writable { base } else { base & !0o222 }
                })
            // Non-NTFS volume (FAT32/exFAT/network): EA unavailable; keep +x for scripts.
            } else {
                let base = if md.is_dir() {
                    0o755
                } else if ft_local.is_symlink() {
                    0o777
                } else {
                    0o755
                };
                if writable { base } else { base & !0o222 }
            };
            Some(mode)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            None
        }
    };
    let ft = md.file_type();
    let is_symlink = ft.is_symlink();
    // is_dir takes precedence only for *real* directories — special
    // inodes (socket/fifo/dev) are not directories even though the
    // host metadata's "is_dir" can never be true for them anyway.
    let is_special = is_socket || is_fifo || is_block_device || is_char_device;
    VfsFileInfo {
        name,
        size: md.len(),
        is_dir: !is_symlink && !is_special && md.is_dir(),
        is_symlink,
        is_socket,
        is_fifo,
        is_block_device,
        is_char_device,
        modified: md.modified().ok(),
        mode,
        rdev: kind_rdev,
    }
}

// ===========================================================================
// MemFsVfs (test fixture, also useful for "synthetic mount" use cases)
// ===========================================================================

/// In-memory filesystem keyed by absolute path. Implements the full
/// trait suite. **Not** intended for production data — locking is coarse
/// and there's no eviction.
#[derive(Debug, Default)]
pub struct MemFsVfs {
    inner: Mutex<MemFsInner>,
}

#[derive(Debug)]
struct MemFsInner {
    /// Map of absolute (canonical, leading-slash) path → entry.
    /// `/` is always present and is a directory.
    entries: HashMap<PathBuf, MemEntry>,
}

#[derive(Debug, Clone)]
enum MemEntry {
    Dir { modified: SystemTime },
    File { data: Vec<u8>, modified: SystemTime },
}

impl Default for MemFsInner {
    fn default() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            PathBuf::from("/"),
            MemEntry::Dir {
                modified: SystemTime::now(),
            },
        );
        Self { entries }
    }
}

impl MemFsVfs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arc() -> Arc<dyn VfsBackend> {
        Arc::new(Self::new())
    }

    fn key(path: &Path) -> VfsResult<PathBuf> {
        sanitize(path)?;
        let mut p = PathBuf::from("/");
        for c in path.components() {
            if let Component::Normal(n) = c {
                p.push(n);
            }
        }
        Ok(p)
    }

    fn parent_must_exist(inner: &MemFsInner, key: &Path) -> VfsResult<()> {
        let parent = key
            .parent()
            .ok_or_else(|| VfsError::InvalidArgument("no parent".into()))?;
        match inner.entries.get(parent) {
            Some(MemEntry::Dir { .. }) => Ok(()),
            Some(MemEntry::File { .. }) => Err(VfsError::NotDir),
            None => Err(VfsError::NotFound),
        }
    }
}

#[async_trait]
impl VfsReader for MemFsVfs {
    async fn list(&self, path: &Path) -> VfsResult<Vec<VfsFileInfo>> {
        let k = Self::key(path)?;
        let inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::Dir { .. }) => {}
            Some(MemEntry::File { .. }) => return Err(VfsError::NotDir),
            None => return Err(VfsError::NotFound),
        }
        let mut out = Vec::new();
        for (p, e) in inner.entries.iter() {
            if p.parent() == Some(&k) && p != &k {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push(entry_to_info(name, e));
            }
        }
        Ok(out)
    }

    async fn stat(&self, path: &Path) -> VfsResult<VfsFileInfo> {
        let k = Self::key(path)?;
        let inner = self.inner.lock().await;
        let e = inner.entries.get(&k).ok_or(VfsError::NotFound)?;
        let name = if k == Path::new("/") {
            String::new()
        } else {
            k.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        Ok(entry_to_info(name, e))
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> VfsResult<Vec<u8>> {
        let k = Self::key(path)?;
        let inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::File { data, .. }) => {
                let start = (offset as usize).min(data.len());
                let end = match limit {
                    Some(l) => (start + l as usize).min(data.len()),
                    None => data.len(),
                };
                Ok(data[start..end].to_vec())
            }
            Some(MemEntry::Dir { .. }) => Err(VfsError::IsDir),
            None => Err(VfsError::NotFound),
        }
    }
}

#[async_trait]
impl VfsMkdir for MemFsVfs {
    async fn mkdir(&self, path: &Path) -> VfsResult<()> {
        let k = Self::key(path)?;
        let mut inner = self.inner.lock().await;
        if inner.entries.contains_key(&k) {
            return Err(VfsError::AlreadyExists);
        }
        Self::parent_must_exist(&inner, &k)?;
        inner.entries.insert(
            k,
            MemEntry::Dir {
                modified: SystemTime::now(),
            },
        );
        Ok(())
    }
}

#[async_trait]
impl VfsDeleteFile for MemFsVfs {
    async fn delete_file(&self, path: &Path) -> VfsResult<()> {
        let k = Self::key(path)?;
        let mut inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::File { .. }) => {
                inner.entries.remove(&k);
                Ok(())
            }
            Some(MemEntry::Dir { .. }) => Err(VfsError::IsDir),
            None => Err(VfsError::NotFound),
        }
    }
}

#[async_trait]
impl VfsDeleteDir for MemFsVfs {
    async fn delete_dir(&self, path: &Path) -> VfsResult<()> {
        let k = Self::key(path)?;
        if k == Path::new("/") {
            return Err(VfsError::PermissionDenied);
        }
        let mut inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::Dir { .. }) => {}
            Some(MemEntry::File { .. }) => return Err(VfsError::NotDir),
            None => return Err(VfsError::NotFound),
        }
        // dir must be empty
        let has_child = inner.entries.keys().any(|p| p.parent() == Some(&k) && p != &k);
        if has_child {
            return Err(VfsError::Other("directory not empty".into()));
        }
        inner.entries.remove(&k);
        Ok(())
    }
}

#[async_trait]
impl VfsRename for MemFsVfs {
    async fn rename(&self, from: &Path, to: &Path) -> VfsResult<()> {
        let kf = Self::key(from)?;
        let kt = Self::key(to)?;
        let mut inner = self.inner.lock().await;
        let entry = inner.entries.remove(&kf).ok_or(VfsError::NotFound)?;
        Self::parent_must_exist(&inner, &kt)?;
        inner.entries.insert(kt, entry);
        Ok(())
    }
}

#[async_trait]
impl VfsPut for MemFsVfs {
    async fn put(&self, path: &Path, data: Vec<u8>) -> VfsResult<()> {
        let k = Self::key(path)?;
        let mut inner = self.inner.lock().await;
        Self::parent_must_exist(&inner, &k)?;
        if let Some(MemEntry::Dir { .. }) = inner.entries.get(&k) {
            return Err(VfsError::IsDir);
        }
        inner.entries.insert(
            k,
            MemEntry::File {
                data,
                modified: SystemTime::now(),
            },
        );
        Ok(())
    }
}

impl VfsBackend for MemFsVfs {
    fn as_mkdir(&self) -> Option<&dyn VfsMkdir> {
        Some(self)
    }
    fn as_delete_file(&self) -> Option<&dyn VfsDeleteFile> {
        Some(self)
    }
    fn as_delete_dir(&self) -> Option<&dyn VfsDeleteDir> {
        Some(self)
    }
    fn as_rename(&self) -> Option<&dyn VfsRename> {
        Some(self)
    }
    fn as_put(&self) -> Option<&dyn VfsPut> {
        Some(self)
    }
}

fn entry_to_info(name: String, entry: &MemEntry) -> VfsFileInfo {
    match entry {
        MemEntry::Dir { modified } => VfsFileInfo::basic(name, 0, true, Some(0o755), Some(*modified)),
        MemEntry::File { data, modified } => {
            VfsFileInfo::basic(name, data.len() as u64, false, Some(0o644), Some(*modified))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // -- LocalDirVfs ---------------------------------------------------------

    #[tokio::test]
    async fn local_list_stat_read() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"world").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let vfs = LocalDirVfs::new(dir.path());

        let mut entries = vfs.list(Path::new("/")).await.unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "hello.txt");
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].size, 5);
        assert_eq!(entries[1].name, "sub");
        assert!(entries[1].is_dir);

        let s = vfs.stat(Path::new("/hello.txt")).await.unwrap();
        assert_eq!(s.name, "hello.txt");
        assert_eq!(s.size, 5);

        let bytes = vfs.read_bytes(Path::new("/hello.txt"), 0, None).await.unwrap();
        assert_eq!(bytes, b"world");

        let bytes = vfs.read_bytes(Path::new("/hello.txt"), 1, Some(3)).await.unwrap();
        assert_eq!(bytes, b"orl");
    }

    #[tokio::test]
    async fn local_write_path() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        vfs.as_put()
            .unwrap()
            .put(Path::new("/a.txt"), b"hi".to_vec())
            .await
            .unwrap();
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"hi");

        vfs.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        assert!(dir.path().join("d").is_dir());

        vfs.as_rename()
            .unwrap()
            .rename(Path::new("/a.txt"), Path::new("/b.txt"))
            .await
            .unwrap();
        assert!(dir.path().join("b.txt").exists());

        vfs.as_delete_file()
            .unwrap()
            .delete_file(Path::new("/b.txt"))
            .await
            .unwrap();
        assert!(!dir.path().join("b.txt").exists());

        vfs.as_delete_dir().unwrap().delete_dir(Path::new("/d")).await.unwrap();
    }

    #[tokio::test]
    async fn local_rejects_dotdot() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        let err = vfs.stat(Path::new("/../../etc/passwd")).await.unwrap_err();
        assert!(matches!(err, VfsError::InvalidArgument(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_invalid_windows_lookup_name_is_not_found() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        let err = vfs.stat(Path::new("/slide-*.jpg")).await.unwrap_err();
        assert!(matches!(err, VfsError::NotFound));
    }

    #[tokio::test]
    async fn local_resolve_real() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        let p = vfs.as_resolve_local().unwrap().resolve_real_path(Path::new("/foo/bar"));
        assert_eq!(p, Some(dir.path().join("foo/bar")));
    }

    // -- MemFsVfs ------------------------------------------------------------

    #[tokio::test]
    async fn mem_basic_lifecycle() {
        let vfs = MemFsVfs::new();

        // empty root
        let entries = vfs.list(Path::new("/")).await.unwrap();
        assert!(entries.is_empty());

        // mkdir + put
        vfs.as_mkdir().unwrap().mkdir(Path::new("/sub")).await.unwrap();
        vfs.as_put()
            .unwrap()
            .put(Path::new("/sub/a"), b"hello".to_vec())
            .await
            .unwrap();

        // read back
        let bytes = vfs.read_bytes(Path::new("/sub/a"), 0, None).await.unwrap();
        assert_eq!(bytes, b"hello");

        // partial read
        let bytes = vfs.read_bytes(Path::new("/sub/a"), 1, Some(3)).await.unwrap();
        assert_eq!(bytes, b"ell");

        // list
        let entries = vfs.list(Path::new("/sub")).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[0].size, 5);

        // rename
        vfs.as_rename()
            .unwrap()
            .rename(Path::new("/sub/a"), Path::new("/sub/b"))
            .await
            .unwrap();
        assert!(matches!(vfs.stat(Path::new("/sub/a")).await, Err(VfsError::NotFound)));

        // delete
        vfs.as_delete_file()
            .unwrap()
            .delete_file(Path::new("/sub/b"))
            .await
            .unwrap();
        vfs.as_delete_dir()
            .unwrap()
            .delete_dir(Path::new("/sub"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mem_dir_not_empty() {
        let vfs = MemFsVfs::new();
        vfs.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        vfs.as_put()
            .unwrap()
            .put(Path::new("/d/x"), b"x".to_vec())
            .await
            .unwrap();
        let err = vfs
            .as_delete_dir()
            .unwrap()
            .delete_dir(Path::new("/d"))
            .await
            .unwrap_err();
        assert!(matches!(err, VfsError::Other(_)));
    }

    #[tokio::test]
    async fn mem_isdir_notdir() {
        let vfs = MemFsVfs::new();
        vfs.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        assert!(matches!(
            vfs.read_bytes(Path::new("/d"), 0, None).await,
            Err(VfsError::IsDir)
        ));

        vfs.as_put().unwrap().put(Path::new("/f"), b"x".to_vec()).await.unwrap();
        assert!(matches!(vfs.list(Path::new("/f")).await, Err(VfsError::NotDir)));
    }

    /// Verify that LocalDirVfs::mknod creates a real AF_UNIX socket
    /// inode and that meta_to_info reports it back as `is_socket=true`.
    /// This is the unit-level analogue of `bind(2)` succeeding inside a
    /// FUSE mount: without `mknod` returning Ok and `stat` round-tripping
    /// the S_IFSOCK bits, AF_UNIX bind/connect on a FUSE-backed path
    /// fails with ENOSYS or ENOTSOCK.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_mknod_socket_roundtrip() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        let mk = vfs.as_mknod().expect("LocalDirVfs supports mknod");
        // S_IFSOCK | 0666
        mk.mknod(Path::new("/foo.sock"), 0o140666, 0).await.unwrap();

        let info = vfs.stat(Path::new("/foo.sock")).await.unwrap();
        assert!(info.is_socket, "expected is_socket=true, got {info:?}");
        assert!(!info.is_dir);
        assert!(!info.is_fifo);
    }

    /// Same as above but for FIFOs.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_mknod_fifo_roundtrip() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        let mk = vfs.as_mknod().unwrap();
        // S_IFIFO | 0644
        mk.mknod(Path::new("/p"), 0o010644, 0).await.unwrap();

        let info = vfs.stat(Path::new("/p")).await.unwrap();
        assert!(info.is_fifo, "expected is_fifo=true, got {info:?}");
        assert!(!info.is_socket);
    }

    /// Unprivileged callers cannot create device nodes; mknod should
    /// surface EPERM (mapped to PermissionDenied) rather than silently
    /// creating a regular file.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_mknod_blockdev_returns_eperm() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        let mk = vfs.as_mknod().unwrap();
        // S_IFBLK | 0600
        let err = mk
            .mknod(Path::new("/blk"), 0o060600, 0)
            .await
            .expect_err("block dev mknod must fail unprivileged");
        assert!(
            matches!(err, VfsError::PermissionDenied | VfsError::Io(_)),
            "unexpected err: {err:?}"
        );
    }
}
