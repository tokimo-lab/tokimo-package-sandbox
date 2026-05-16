//! Mutating ops: mknod, unlink, symlink, rename.

use std::ffi::OsStr;
use std::path::Path;

use fuser::{ReplyEmpty, ReplyEntry, Request};
use tokimo_package_sandbox::vfs_protocol::{Req, Res};

use super::super::bridge::{FuseBridge, TTL, entry_to_attr, errno_of};

pub(crate) fn mknod(
    b: &mut FuseBridge,
    _r: &Request,
    parent: u64,
    name: &OsStr,
    mode: u32,
    _umask: u32,
    rdev: u32,
    reply: ReplyEntry,
) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    match b.dispatcher.call(Req::Mknod {
        parent_nodeid: parent,
        name: n,
        mode,
        rdev,
    }) {
        Res::Entry(e) => {
            let attr = entry_to_attr(&e);
            reply.entry(&TTL, &attr, e.generation);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn unlink(b: &mut FuseBridge, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    match b.dispatcher.call(Req::Unlink {
        parent_nodeid: parent,
        name: n,
    }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn rename(
    b: &mut FuseBridge,
    _r: &Request,
    parent: u64,
    name: &OsStr,
    newparent: u64,
    newname: &OsStr,
    _flags: u32,
    reply: ReplyEmpty,
) {
    let on = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    let nn = match newname.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    match b.dispatcher.call(Req::Rename {
        old_parent: parent,
        old_name: on.clone(),
        new_parent: newparent,
        new_name: nn.clone(),
    }) {
        // The kernel auto-invalidates the source dentry on a
        // successful FUSE_RENAME. It does NOT invalidate any
        // cached *negative* dentry for the destination name,
        // but that's handled at lookup time — see the comment
        // in `lookup()` for why we disable negative-dentry
        // caching entirely. Sending FUSE_NOTIFY_INVAL_ENTRY
        // from here would deadlock: the kernel holds the
        // parent dir's i_rwsem for the in-flight FUSE_RENAME
        // and inval_entry tries to acquire it on the same
        // fuse worker thread (verified — `fuse_reverse_inval_entry`
        // wedges in D-state on `start_removing_dentry`).
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn symlink(b: &mut FuseBridge, _r: &Request, parent: u64, name: &OsStr, link: &Path, reply: ReplyEntry) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    // POSIX symlink targets are an opaque byte string. Our
    // wire protocol carries them as String; on Linux paths
    // are virtually always UTF-8, and lossy conversion only
    // affects exotic locale encodings nobody uses today.
    let target = link.to_string_lossy().into_owned();
    match b.dispatcher.call(Req::Symlink {
        parent_nodeid: parent,
        name: n,
        target,
    }) {
        Res::Entry(e) => {
            let attr = entry_to_attr(&e);
            reply.entry(&TTL, &attr, e.generation);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn link(b: &mut FuseBridge, _r: &Request, ino: u64, newparent: u64, newname: &OsStr, reply: ReplyEntry) {
    let n = match newname.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    match b.dispatcher.call(Req::Link {
        nodeid: ino,
        new_parent: newparent,
        new_name: n,
    }) {
        Res::Entry(e) => {
            let attr = entry_to_attr(&e);
            reply.entry(&TTL, &attr, e.generation);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn access(b: &mut FuseBridge, _r: &Request, ino: u64, mask: i32, reply: ReplyEmpty) {
    match b.dispatcher.call(Req::Access {
        nodeid: ino,
        mask: mask as u32,
    }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}
