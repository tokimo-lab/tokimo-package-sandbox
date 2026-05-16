//! Metadata ops: lookup, getattr, setattr, readlink.

use std::sync::Arc;

use crate::vfs_backend::VfsError;
use crate::vfs_protocol::{EntryOut, Res, errno_for};

use super::super::FuseHost;
use super::super::helpers::{apply_host_mode, attr_from};

impl FuseHost {
    pub(in crate::vfs::host) async fn op_lookup(self: Arc<Self>, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let path = Self::child_path(&parent, name);
        match mount.backend.stat(&path).await {
            Ok(info) => {
                let (nodeid, _) = self.id_table.intern_with_inode(mount_id, path, info.dev, info.ino);
                Res::Entry(EntryOut {
                    nodeid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_getattr(&self, mount_id: u32, nodeid: u64) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        match mount.backend.stat(&path).await {
            Ok(info) => Res::Attr(attr_from(&info)),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_setattr(
        &self,
        mount_id: u32,
        nodeid: u64,
        mode: Option<u32>,
        size: Option<u64>,
        _atime: Option<i64>,
        _mtime: Option<i64>,
    ) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }

        // Only `size` truncation and local-backend `mode` changes are
        // honoured for now (matches what most callers do via `O_TRUNC` at
        // open time).
        if let Some(sz) = size {
            // Try resolve_local + std::fs truncate; otherwise read-modify-put.
            if let Some(resolver) = mount.backend.as_resolve_local() {
                if let Some(host_path) = resolver.resolve_real_path(&path) {
                    if let Err(e) = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&host_path)
                        .and_then(|f| f.set_len(sz))
                    {
                        return Res::Error(errno_for(&VfsError::from(e)));
                    }
                } else if let Some(put) = mount.backend.as_put() {
                    let data = match mount.backend.read_bytes(&path, 0, Some(sz)).await {
                        Ok(d) => d,
                        Err(e) => return Res::Error(errno_for(&e)),
                    };
                    let mut data = data;
                    data.resize(sz as usize, 0);
                    if let Err(e) = put.put(&path, data).await {
                        return Res::Error(errno_for(&e));
                    }
                } else {
                    return Res::Error(errno_for(&VfsError::NotImplemented("truncate".into())));
                }
            } else if let Some(put) = mount.backend.as_put() {
                let data = match mount.backend.read_bytes(&path, 0, Some(sz)).await {
                    Ok(d) => d,
                    Err(e) => return Res::Error(errno_for(&e)),
                };
                let mut data = data;
                data.resize(sz as usize, 0);
                if let Err(e) = put.put(&path, data).await {
                    return Res::Error(errno_for(&e));
                }
            } else {
                return Res::Error(errno_for(&VfsError::NotImplemented("truncate".into())));
            }
        }

        if let Some(m) = mode
            && let Some(resolver) = mount.backend.as_resolve_local()
            && let Some(host_path) = resolver.resolve_real_path(&path)
        {
            apply_host_mode(&host_path, m);
        }
        // Non-local backends: chmod is a no-op, but not an error.

        // Re-stat for fresh attrs.
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        match mount.backend.stat(&path).await {
            Ok(info) => {
                // Size changes (truncate via SetAttr.size) on a multi-
                // alias inode leave the kernel page cache of any sister
                // nodeid stale. notify_inode is a no-op when not aliased.
                if size.is_some() {
                    self.notify_inode(mount_id, info.dev, info.ino);
                }
                Res::Attr(attr_from(&info))
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_readlink(&self, mount_id: u32, nodeid: u64) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let Some(r) = mount.backend.as_readlink() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("readlink".into())));
        };
        match r.readlink(&path).await {
            Ok(target) => Res::Linkname(target),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }
}
