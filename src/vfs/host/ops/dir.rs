//! Directory ops: opendir, readdir, readdirplus, mkdir, rmdir.

use std::path::Path;
use std::sync::Arc;

use crate::vfs_backend::VfsError;
use crate::vfs_protocol::{
    AttrOut, DirEntry as WireDirEntry, DirEntryPlus as WireDirEntryPlus, EntryOut, NodeKind, Res, errno_for,
};

#[cfg(windows)]
use super::super::helpers::apply_host_mode;
use super::super::helpers::attr_from;
use super::super::id_table::FhEntry;
use super::super::{DirSnapshot, FuseHost};

impl FuseHost {
    pub(in crate::vfs::host) async fn op_opendir(self: Arc<Self>, mount_id: u32, nodeid: u64) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let entries = match mount.backend.list(&path).await {
            Ok(e) => e,
            Err(e) => return Res::Error(errno_for(&e)),
        };
        let snapshot: Vec<(String, DirSnapshot)> = entries
            .into_iter()
            .map(|info| {
                let attr = attr_from(&info);
                let snap = DirSnapshot {
                    kind: attr.kind,
                    size: attr.size,
                    mode: attr.mode,
                    mtime: attr.mtime,
                    rdev: attr.rdev,
                };
                (info.name, snap)
            })
            .collect();
        let fh = self.id_table.alloc_fh(FhEntry::Dir {
            mount_id,
            nodeid,
            entries: snapshot,
        });
        Res::OpenOk { fh }
    }

    pub(in crate::vfs::host) async fn op_readdir(&self, fh: u64, offset: u64) -> Res {
        // Snapshot under the lock, then build the response.
        let snap = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::Dir {
                mount_id,
                nodeid,
                entries,
            } => Some((*mount_id, *nodeid, entries.clone())),
            _ => None,
        });
        let Some(Some((mount_id, dir_nodeid, entries))) = snap else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        let dir_path = match self.resolve_path(mount_id, dir_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let parent_nodeid = if dir_path == Path::new("/") {
            1
        } else {
            let parent_path = dir_path.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
            let (nodeid, _) = self.id_table.intern_peek(mount_id, parent_path);
            nodeid
        };

        let off = offset as usize;
        let mut out = Vec::new();
        if off == 0 {
            out.push(WireDirEntry {
                nodeid: dir_nodeid,
                offset: 1,
                kind: NodeKind::Dir,
                name: ".".into(),
            });
        }
        if off <= 1 {
            out.push(WireDirEntry {
                nodeid: parent_nodeid,
                offset: 2,
                kind: NodeKind::Dir,
                name: "..".into(),
            });
        }
        for (i, (name, snap)) in entries.into_iter().enumerate().skip(off.saturating_sub(2)) {
            let child = Self::child_path(&dir_path, &name);
            let (nodeid, _) = self.id_table.intern_peek(mount_id, child);
            out.push(WireDirEntry {
                nodeid,
                offset: (i + 3) as u64,
                kind: snap.kind,
                name,
            });
        }
        Res::DirEntries(out)
    }

    /// FUSE READDIRPLUS: same iteration as [`op_readdir`](Self::op_readdir)
    /// but each entry carries full attrs and bumps the lookup count
    /// (kernel will [`Forget`](crate::vfs_protocol::Req::Forget) when evicting from cache).
    pub(in crate::vfs::host) async fn op_readdirplus(&self, fh: u64, offset: u64) -> Res {
        let snap = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::Dir {
                mount_id,
                nodeid,
                entries,
            } => Some((*mount_id, *nodeid, entries.clone())),
            _ => None,
        });
        let Some(Some((mount_id, dir_nodeid, entries))) = snap else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        let dir_path = match self.resolve_path(mount_id, dir_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let parent_nodeid = if dir_path == Path::new("/") {
            1
        } else {
            let parent_path = dir_path.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
            let (nodeid, _) = self.id_table.intern_peek(mount_id, parent_path);
            nodeid
        };

        let off = offset as usize;
        let mut out = Vec::new();
        let generation = self.id_table.generation();

        // "." and ".." get nodeid=0/0 attrs from a stat-on-demand cost we
        // skip — the kernel only uses these for completeness, not for
        // attr caching. We still must include them with valid attrs or
        // some kernels reject the entry. Use a synthetic dir attr.
        let synthetic_dir_attr = AttrOut {
            size: 0,
            blocks: 0,
            mtime: 0,
            mode: 0o755,
            nlink: 2,
            #[cfg(target_os = "linux")]
            uid: unsafe { libc::getuid() },
            #[cfg(target_os = "linux")]
            gid: unsafe { libc::getgid() },
            #[cfg(not(target_os = "linux"))]
            uid: 0,
            #[cfg(not(target_os = "linux"))]
            gid: 0,
            kind: NodeKind::Dir,
            rdev: 0,
        };
        if off == 0 {
            out.push(WireDirEntryPlus {
                offset: 1,
                name: ".".into(),
                entry: EntryOut {
                    nodeid: dir_nodeid,
                    generation,
                    attr: synthetic_dir_attr.clone(),
                },
            });
        }
        if off <= 1 {
            out.push(WireDirEntryPlus {
                offset: 2,
                name: "..".into(),
                entry: EntryOut {
                    nodeid: parent_nodeid,
                    generation,
                    attr: synthetic_dir_attr,
                },
            });
        }

        #[cfg(target_os = "linux")]
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        #[cfg(not(target_os = "linux"))]
        let (uid, gid) = (0u32, 0u32);

        for (i, (name, snap)) in entries.into_iter().enumerate().skip(off.saturating_sub(2)) {
            let child = Self::child_path(&dir_path, &name);
            // intern() bumps lookup count — required for READDIRPLUS so
            // the kernel's Forget pairs balance out.
            let (nodeid, _) = self.id_table.intern(mount_id, child);
            out.push(WireDirEntryPlus {
                offset: (i + 3) as u64,
                name,
                entry: EntryOut {
                    nodeid,
                    generation,
                    attr: AttrOut {
                        size: snap.size,
                        blocks: snap.size.div_ceil(512),
                        mtime: snap.mtime,
                        mode: snap.mode,
                        nlink: 1,
                        uid,
                        gid,
                        kind: snap.kind,
                        rdev: snap.rdev,
                    },
                },
            });
        }
        Res::DirEntriesPlus(out)
    }

    #[cfg_attr(not(windows), allow(unused_variables))]
    pub(in crate::vfs::host) async fn op_mkdir(&self, mount_id: u32, parent_nodeid: u64, name: &str, mode: u32) -> Res {
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
        let Some(mk) = mount.backend.as_mkdir() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("mkdir".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = mk.mkdir(&path).await {
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

    pub(in crate::vfs::host) async fn op_rmdir(&self, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
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
        let Some(d) = mount.backend.as_delete_dir() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("rmdir".into())));
        };
        let path = Self::child_path(&parent, name);
        match d.delete_dir(&path).await {
            Ok(()) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }
}
