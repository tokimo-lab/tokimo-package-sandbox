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
            Ok(()) => {
                // Drop just this path alias; the underlying inode (and
                // therefore the nodeid) may still be reachable via
                // other hard-linked names. `unbind_path` releases the
                // nodeid only if both `paths` is empty and refcount is
                // zero.
                self.id_table.unbind_path(mount_id, &path);
                Res::Ok
            }
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
                    // Source dentry now points at a vanished name.
                    // Kick the guest kernel's dcache so a subsequent
                    // `ls old_name` doesn't return a cached hit. The
                    // destination side carries fresh EntryOut via the
                    // rename reply path, so no notify_entry needed there.
                    if old_name != new_name {
                        self.notify_entry(mount_id, old_parent, old_name);
                    }
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
                        if old_parent != new_parent {
                            self.notify_entry(mount_id, old_parent, old_name);
                        }
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
                    self.notify_entry(mount_id, old_parent, old_name);
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

    /// Hard-link an existing inode (`nodeid`) into `new_parent`/`new_name`.
    /// Both paths must live under the same mount.
    pub(in crate::vfs::host) async fn op_link(
        &self,
        mount_id: u32,
        nodeid: u64,
        new_parent: u64,
        new_name: &str,
    ) -> Res {
        let src = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let parent = match self.resolve_path(mount_id, new_parent) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(link) = mount.backend.as_link() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("link".into())));
        };
        let dst = Self::child_path(&parent, new_name);
        if let Err(e) = link.hard_link(&src, &dst).await {
            return Res::Error(errno_for(&e));
        }
        match mount.backend.stat(&dst).await {
            Ok(info) => {
                // Inode-aware intern: `dst` now points at the same
                // inode as `src`, so this collapses onto the existing
                // nodeid via `by_inode` rather than allocating a fresh
                // one. The kernel sees one nodeid + one page cache for
                // both names (matching the bare-host hard-link
                // semantics that `stat -c %i a == stat -c %i b`).
                let (nid, _) = self.id_table.intern_with_inode(mount_id, dst, info.dev, info.ino);
                // Link bumps the inode's nlink and ctime. If any prior
                // path-only-interned alias of this inode is still alive
                // (dedup couldn't collapse it onto `nid` because its
                // inode_key was unknown at intern time), its kernel
                // attr cache is now stale. Fire the cross-alias
                // invalidate unconditionally — `notify_inode` is a
                // no-op when there's only one nodeid for this inode.
                self.notify_inode(mount_id, info.dev, info.ino);
                Res::Entry(EntryOut {
                    nodeid: nid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    /// `access(2)`. With `default_permissions` enabled on the FUSE mount
    /// the kernel does its own checks based on `getattr`, so this op is
    /// rarely invoked — but implement it anyway for correctness.
    pub(in crate::vfs::host) async fn op_access(&self, mount_id: u32, nodeid: u64, mask: u32) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if let Some(a) = mount.backend.as_access() {
            return match a.access(&path, mask).await {
                Ok(()) => Res::Ok,
                Err(e) => Res::Error(errno_for(&e)),
            };
        }
        // Fallback: existence check via stat.
        match mount.backend.stat(&path).await {
            Ok(_) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }
}
