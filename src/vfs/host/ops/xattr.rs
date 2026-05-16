//! Extended-attribute ops: get/set/list/remove.
//!
//! All four follow the same shape:
//!   1. Resolve nodeid → path.
//!   2. Look up the optional [`VfsXattr`] capability; otherwise `ENOTSUP`.
//!   3. Delegate to the backend; map errors via [`errno_for`].
//!
//! `getxattr` and `listxattr` implement the FUSE size-probe protocol: the
//! kernel first calls with `size == 0` to learn the byte length, then
//! re-issues with a sufficiently-large buffer. We mirror that on the
//! wire — `size == 0` ⇒ [`Res::XattrSize`]; otherwise return the value
//! (or [`Errno::Erange`] when too small).

use crate::vfs_backend::VfsError;
use crate::vfs_protocol::{Errno, Res, WireError, errno_for};

use super::super::FuseHost;

impl FuseHost {
    pub(in crate::vfs::host) async fn op_setxattr(
        &self,
        mount_id: u32,
        nodeid: u64,
        name: &str,
        value: Vec<u8>,
        flags: u32,
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
        let Some(x) = mount.backend.as_xattr() else {
            return Res::Error(errno_for(&VfsError::NotSupported("xattr".into())));
        };
        match x.set_xattr(&path, name, &value, flags).await {
            Ok(()) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_getxattr(&self, mount_id: u32, nodeid: u64, name: &str, size: u32) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let Some(x) = mount.backend.as_xattr() else {
            return Res::Error(errno_for(&VfsError::NotSupported("xattr".into())));
        };
        match x.get_xattr(&path, name).await {
            Ok(value) => {
                if size == 0 {
                    return Res::XattrSize(value.len() as u32);
                }
                if (value.len() as u32) > size {
                    return Res::Error(WireError::new(Errno::Erange, "xattr buffer too small"));
                }
                Res::Bytes(value)
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_listxattr(&self, mount_id: u32, nodeid: u64, size: u32) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let Some(x) = mount.backend.as_xattr() else {
            return Res::Error(errno_for(&VfsError::NotSupported("xattr".into())));
        };
        match x.list_xattr(&path).await {
            Ok(buf) => {
                if size == 0 {
                    return Res::XattrSize(buf.len() as u32);
                }
                if (buf.len() as u32) > size {
                    return Res::Error(WireError::new(Errno::Erange, "xattr list buffer too small"));
                }
                Res::XattrList(buf)
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    pub(in crate::vfs::host) async fn op_removexattr(&self, mount_id: u32, nodeid: u64, name: &str) -> Res {
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
        let Some(x) = mount.backend.as_xattr() else {
            return Res::Error(errno_for(&VfsError::NotSupported("xattr".into())));
        };
        match x.remove_xattr(&path, name).await {
            Ok(()) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }
}
