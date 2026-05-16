//! File ops: open, read, write, flush, release, create.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::vfs_backend::{VfsError, VfsResult};
use crate::vfs_protocol::{EntryOut, Res, errno_for};

use super::super::FuseHost;
#[cfg(windows)]
use super::super::helpers::apply_host_mode;
use super::super::helpers::{attr_from, drain_staging_to_backend};
use super::super::id_table::{FhEntry, StagingFile};

impl FuseHost {
    pub(in crate::vfs::host) async fn op_open(self: Arc<Self>, mount_id: u32, nodeid: u64, flags: u32) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };

        const O_ACCMODE: u32 = 0o3;
        const O_WRONLY: u32 = 0o1;
        const O_RDWR: u32 = 0o2;
        const O_TRUNC: u32 = 0o1000;
        let access = flags & O_ACCMODE;
        let needs_write = access == O_WRONLY || access == O_RDWR;

        if needs_write {
            if mount.read_only {
                return Res::Error(errno_for(&VfsError::PermissionDenied));
            }
            if mount.backend.as_put().is_none()
                && mount.backend.as_put_stream().is_none()
                && mount.backend.as_resolve_local().is_none()
            {
                return Res::Error(crate::vfs_protocol::WireError {
                    errno: crate::vfs_protocol::Errno::Erofs as i32,
                    message: "backend has no write capability".into(),
                });
            }
        }

        // Fastpath: backend exposes a real local path → open the host
        // file once and let op_read/op_write do direct pread/pwrite.
        let host_file = if let Some(resolver) = mount.backend.as_resolve_local() {
            if let Some(real) = resolver.resolve_real_path(&path) {
                let mut opts = std::fs::OpenOptions::new();
                opts.read(true);
                if needs_write {
                    opts.write(true);
                    if (flags & O_TRUNC) != 0 {
                        opts.truncate(true);
                    }
                }
                match tokio::task::spawn_blocking(move || opts.open(&real)).await {
                    Ok(Ok(f)) => Some(Arc::new(f)),
                    Ok(Err(e)) => return Res::Error(errno_for(&VfsError::from(e))),
                    Err(e) => return Res::Error(errno_for(&VfsError::Io(e.to_string()))),
                }
            } else {
                None
            }
        } else {
            None
        };

        // Slow path: just verify the file exists.
        if host_file.is_none()
            && !needs_write
            && let Err(e) = mount.backend.stat(&path).await
        {
            return Res::Error(errno_for(&e));
        }

        let fh = self.id_table.alloc_fh(FhEntry::File {
            mount_id,
            nodeid,
            flags,
            staging: None,
            host_file,
        });
        Res::OpenOk { fh }
    }

    pub(in crate::vfs::host) async fn op_read(&self, fh: u64, offset: u64, size: u32) -> Res {
        let info = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File {
                mount_id,
                nodeid,
                host_file,
                ..
            } => Some((*mount_id, *nodeid, host_file.clone())),
            _ => None,
        });
        let Some(Some((mount_id, nodeid, host_file))) = info else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };

        // Fastpath: pread directly from the local host file.
        if let Some(file) = host_file {
            let want = size as usize;
            let res = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileExt;
                    let mut buf = vec![0u8; want];
                    let mut filled = 0;
                    while filled < want {
                        match file.read_at(&mut buf[filled..], offset + filled as u64)? {
                            0 => break,
                            n => filled += n,
                        }
                    }
                    buf.truncate(filled);
                    Ok(buf)
                }
                #[cfg(not(unix))]
                {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = (*file).try_clone()?;
                    f.seek(SeekFrom::Start(offset))?;
                    let mut buf = Vec::with_capacity(want);
                    f.take(want as u64).read_to_end(&mut buf)?;
                    Ok(buf)
                }
            })
            .await;
            return match res {
                Ok(Ok(bytes)) => Res::Bytes(bytes),
                Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
                Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
            };
        }

        // Slow path: backend does its own thing.
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        match mount.backend.read_bytes(&path, offset, Some(size as u64)).await {
            Ok(b) => Res::Bytes(b),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_write(&self, fh: u64, offset: u64, data: Vec<u8>) -> Res {
        let written = data.len() as u32;

        // Fastpath: pwrite directly to the local host file.
        let host_file = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File { host_file, .. } => host_file.clone(),
            _ => None,
        });
        if let Some(Some(file)) = host_file {
            let res = tokio::task::spawn_blocking(move || -> io::Result<()> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileExt;
                    let mut written_off = 0;
                    while written_off < data.len() {
                        match file.write_at(&data[written_off..], offset + written_off as u64)? {
                            0 => {
                                return Err(io::Error::new(io::ErrorKind::WriteZero, "pwrite returned 0"));
                            }
                            n => written_off += n,
                        }
                    }
                    Ok(())
                }
                #[cfg(not(unix))]
                {
                    use std::io::{Seek, SeekFrom, Write as _};
                    let mut f = (*file).try_clone()?;
                    f.seek(SeekFrom::Start(offset))?;
                    f.write_all(&data)?;
                    Ok(())
                }
            })
            .await;
            return match res {
                Ok(Ok(())) => Res::Written { size: written },
                Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
                Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
            };
        }

        // Slow path: stage into a tempfile, drain on Flush/Release.
        use std::io::{Seek, SeekFrom, Write as _};

        let staging_path: PathBuf = match self.id_table.with_fh_mut(fh, |entry| -> VfsResult<PathBuf> {
            let FhEntry::File { staging, .. } = entry else {
                return Err(VfsError::InvalidArgument("bad fh".into()));
            };
            if staging.is_none() {
                let tmp = tempfile::Builder::new()
                    .prefix("tokimo-fuse-")
                    .tempfile()
                    .map_err(VfsError::from)?;
                let (file, path) = tmp.keep().map_err(|e| VfsError::Io(e.to_string()))?;
                *staging = Some(StagingFile {
                    path: path.clone(),
                    file,
                    max_offset: 0,
                    dirty: true,
                });
                Ok(path)
            } else {
                Ok(staging.as_ref().unwrap().path.clone())
            }
        }) {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Res::Error(errno_for(&e)),
            None => return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into()))),
        };

        let res = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).open(&staging_path)?;
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(&data)?;
            Ok(())
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Res::Error(errno_for(&VfsError::from(e))),
            Err(e) => return Res::Error(errno_for(&VfsError::Io(e.to_string()))),
        }

        self.id_table.with_fh_mut(fh, |entry| {
            if let FhEntry::File { staging: Some(s), .. } = entry {
                s.max_offset = s.max_offset.max(offset + written as u64);
                s.dirty = true;
            }
        });

        Res::Written { size: written }
    }

    pub(in crate::vfs::host) async fn op_flush(&self, fh: u64) -> Res {
        // Snapshot fh state without taking ownership.
        let fh_state = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File {
                mount_id,
                nodeid,
                staging,
                host_file,
                ..
            } => {
                // Direct-IO fh: nothing to flush; the kernel already
                // pushed bytes into the file via pwrite.
                if host_file.is_some() {
                    return Some((*mount_id, *nodeid, None));
                }
                let staging_info = staging
                    .as_ref()
                    .filter(|s| s.dirty)
                    .map(|s| (s.path.clone(), s.max_offset));
                Some((*mount_id, *nodeid, staging_info))
            }
            _ => None,
        });
        let Some(Some((mount_id, nodeid, staging))) = fh_state else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        let Some((staging_path, size)) = staging else {
            return Res::Ok; // no dirty data
        };

        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };

        if let Err(e) = drain_staging_to_backend(&mount, &path, &staging_path, size).await {
            return Res::Error(errno_for(&e));
        }

        // Mark clean.
        self.id_table.with_fh_mut(fh, |entry| {
            if let FhEntry::File { staging: Some(s), .. } = entry {
                s.dirty = false;
            }
        });

        Res::Ok
    }

    pub(in crate::vfs::host) async fn op_release(&self, fh: u64) -> Res {
        let Some(entry) = self.id_table.take_fh(fh) else {
            return Res::Ok; // tolerate double-release
        };
        let FhEntry::File {
            mount_id,
            nodeid,
            staging,
            host_file,
            ..
        } = entry
        else {
            return Res::Ok;
        };
        // Direct-IO fh: just drop the file; bytes are already on disk.
        if host_file.is_some() {
            drop(host_file);
            return Res::Ok;
        }
        if let Some(s) = staging {
            if s.dirty {
                let path = match self.resolve_path(mount_id, nodeid) {
                    Ok(p) => p,
                    Err(r) => return r,
                };
                let Some(mount) = self.get_mount(mount_id) else {
                    return Res::Error(errno_for(&VfsError::NotFound));
                };
                if let Err(e) = drain_staging_to_backend(&mount, &path, &s.path, s.max_offset).await {
                    let _ = std::fs::remove_file(&s.path);
                    return Res::Error(errno_for(&e));
                }
            }
            let _ = std::fs::remove_file(&s.path);
        }
        Res::Ok
    }

    #[cfg_attr(not(windows), allow(unused_variables))]
    pub(in crate::vfs::host) async fn op_create(
        &self,
        mount_id: u32,
        parent_nodeid: u64,
        name: &str,
        mode: u32,
    ) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(put) = mount.backend.as_put() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("create".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = put.put(&path, Vec::new()).await {
            return Res::Error(errno_for(&e));
        }
        // On Windows, persist mode via NTFS EA (and mirror readonly bit).
        // On Unix the OS create syscall already honours the mode via umask,
        // so applying an additional chmod here is unnecessary and breaks
        // workflows like `git clone` where objects are created read-only
        // (0o444) before being renamed into place.
        #[cfg(windows)]
        if let Some(resolver) = mount.backend.as_resolve_local()
            && let Some(host_path) = resolver.resolve_real_path(&path)
        {
            apply_host_mode(&host_path, mode);
        }
        match mount.backend.stat(&path).await {
            Ok(info) => {
                let (nodeid, _) = self.id_table.intern(mount_id, path);
                Res::Entry(EntryOut {
                    nodeid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }
}
