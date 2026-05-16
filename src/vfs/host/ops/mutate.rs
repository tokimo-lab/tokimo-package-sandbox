//! Namespace-mutating ops: mknod, unlink, rename, symlink.

use crate::vfs_backend::VfsError;
use crate::vfs_protocol::{EntryOut, Res, errno_for};

use super::super::FuseHost;
use super::super::helpers::attr_from;

impl FuseHost {
    /// Create a non-regular non-directory inode (AF_UNIX socket, FIFO,
    /// or device node). The kernel invokes `FUSE_MKNOD` here when an
    /// application calls `bind(2)` on an AF_UNIX socket whose path
    /// resides on this FUSE mount.
    pub(in crate::vfs::host) async fn op_mknod(
        &self,
        mount_id: u32,
        parent_nodeid: u64,
        name: &str,
        mode: u32,
        rdev: u32,
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
        let Some(mk) = mount.backend.as_mknod() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("mknod".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = mk.mknod(&path, mode, rdev).await {
            return Res::Error(errno_for(&e));
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

    pub(in crate::vfs::host) async fn op_unlink(&self, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
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
        let Some(d) = mount.backend.as_delete_file() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("unlink".into())));
        };
        let path = Self::child_path(&parent, name);
        match d.delete_file(&path).await {
            Ok(()) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_rename(
        &self,
        mount_id: u32,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Res {
        let op = match self.resolve_path(mount_id, old_parent) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let np = match self.resolve_path(mount_id, new_parent) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let from = Self::child_path(&op, old_name);
        let to = Self::child_path(&np, new_name);

        if old_parent == new_parent
            && let Some(r) = mount.backend.as_rename()
        {
            return match r.rename(&from, &to).await {
                Ok(()) => {
                    self.id_table.rename_path(mount_id, &from, &to);
                    Res::Ok
                }
                Err(e) => Res::Error(errno_for(&e)),
            };
        }
        if let Some(m) = mount.backend.as_move() {
            // VfsMove takes a target directory + keeps the leaf name; if
            // the user asked for a new leaf name we have to fall back to
            // copy + delete via Rename. Many drivers offer both.
            if old_name == new_name {
                return match m.move_file(&from, &np).await {
                    Ok(()) => {
                        self.id_table.rename_path(mount_id, &from, &to);
                        Res::Ok
                    }
                    Err(e) => Res::Error(errno_for(&e)),
                };
            }
        }
        if let Some(r) = mount.backend.as_rename() {
            return match r.rename(&from, &to).await {
                Ok(()) => {
                    self.id_table.rename_path(mount_id, &from, &to);
                    Res::Ok
                }
                Err(e) => Res::Error(errno_for(&e)),
            };
        }
        Res::Error(errno_for(&VfsError::NotImplemented("rename".into())))
    }

    pub(in crate::vfs::host) async fn op_symlink(
        &self,
        mount_id: u32,
        parent_nodeid: u64,
        name: &str,
        target: &str,
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
        let Some(s) = mount.backend.as_symlink() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("symlink".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = s.symlink(target, &path).await {
            return Res::Error(errno_for(&e));
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
