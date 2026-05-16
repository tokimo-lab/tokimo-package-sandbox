//! [`LocalDirVfs`] — host directory passthrough.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

use crate::vfs_backend::{
    VfsBackend, VfsCopy, VfsDeleteDir, VfsDeleteFile, VfsError, VfsFileInfo, VfsMkdir, VfsMknod, VfsMove, VfsPut,
    VfsReader, VfsReadlink, VfsRename, VfsResolveLocal, VfsResult, VfsSymlink,
};

use super::meta::meta_to_info;
use super::sanitize::{local_stat_error, relative_under, sanitize};

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
                // macOS requires root for mknod(2) of ANY type, including
                // S_IFSOCK and S_IFIFO. Fall back to a regular file +
                // `com.tokimo.kind` xattr so AF_UNIX bind/connect still
                // round-trips correctly via the FUSE bridge.
                #[cfg(target_os = "macos")]
                Err(nix::errno::Errno::EPERM) if matches!(sflag, SFlag::S_IFSOCK | SFlag::S_IFIFO) => {
                    let kind_byte = if sflag == SFlag::S_IFSOCK {
                        super::macos_xattr::KIND_SOCKET
                    } else {
                        super::macos_xattr::KIND_FIFO
                    };
                    tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&host)
                        .await?;
                    let host_for_xattr = host.clone();
                    tokio::task::spawn_blocking(move || super::macos_xattr::set(&host_for_xattr, kind_byte))
                        .await
                        .map_err(|e| VfsError::Io(e.to_string()))?
                        .map_err(|e| {
                            let _ = std::fs::remove_file(&host);
                            VfsError::Io(format!("setxattr: {e}"))
                        })?;
                    Ok(())
                }
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
