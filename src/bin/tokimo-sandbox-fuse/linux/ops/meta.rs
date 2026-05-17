//! Meta ops: init, lookup, forget, getattr, setattr, readlink, statfs.

use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, KernelConfig, ReplyAttr, ReplyData, ReplyEntry, ReplyStatfs, Request, TimeOrNow, consts,
};
use tokimo_package_sandbox::vfs_protocol::{Req, Res, StatfsOut};

use super::super::bridge::{FuseBridge, TTL, attr_to_fileattr, entry_to_attr, errno_of, now_systime_to_secs};

pub(crate) fn init(_b: &mut FuseBridge, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
    let _ = config.set_max_write(1024 * 1024);
    let _ = config.set_max_readahead(1024 * 1024);
    let _ = config.set_max_background(64);
    let _ = config.add_capabilities(
        consts::FUSE_WRITEBACK_CACHE
            | consts::FUSE_AUTO_INVAL_DATA
            | consts::FUSE_DO_READDIRPLUS
            | consts::FUSE_ASYNC_READ
            | consts::FUSE_BIG_WRITES,
    );
    Ok(())
}

pub(crate) fn lookup(b: &mut FuseBridge, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    b.dispatcher.call_async(Req::Lookup {
        parent_nodeid: parent,
        name: n,
    }, move |__res| match __res {
        Res::Entry(e) => {
            let attr = entry_to_attr(&e);
            reply.entry(&TTL, &attr, e.generation);
        }
        Res::Error(we) => {
            let err = errno_of(&we);
            // For ENOENT we send a successful "negative entry"
            // reply (nodeid = 0) with entry_timeout = 0 instead
            // of returning ENOENT. This prevents the kernel
            // from caching a negative dentry. Negative-dentry
            // caching is fatally racy for us: sequences like
            //
            //     stat("config")          // caches negative
            //     rename("config.lock","config")
            //     open("config")          // serves stale neg
            //
            // (which `git init` and friends do constantly) fail
            // with ENOENT despite the file existing. The fix
            // would otherwise require an inline
            // FUSE_NOTIFY_INVAL_ENTRY from inside the rename
            // handler, which deadlocks on the parent dir's
            // i_rwsem (held by the kernel for the in-flight
            // FUSE_RENAME). Disabling negative caching here is
            // the only safe option.
            if err == libc::ENOENT {
                let neg = FileAttr {
                    ino: 0,
                    size: 0,
                    blocks: 0,
                    atime: UNIX_EPOCH,
                    mtime: UNIX_EPOCH,
                    ctime: UNIX_EPOCH,
                    crtime: UNIX_EPOCH,
                    kind: FileType::RegularFile,
                    perm: 0,
                    nlink: 0,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                };
                reply.entry(&Duration::ZERO, &neg, 0);
            } else {
                reply.error(err);
            }
        }
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn forget(b: &mut FuseBridge, _r: &Request, ino: u64, nlookup: u64) {
    // Forget is fire-and-forget — we don't wait for a response.
    b.dispatcher.call_async(Req::Forget { nodeid: ino, nlookup }, |_| {});
}

pub(crate) fn getattr(b: &mut FuseBridge, _r: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
    b.dispatcher.call_async(Req::GetAttr { nodeid: ino }, move |__res| match __res {
        Res::Attr(a) => {
            let fa = attr_to_fileattr(&a, ino);
            reply.attr(&TTL, &fa);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn setattr(
    b: &mut FuseBridge,
    _r: &Request,
    ino: u64,
    mode: Option<u32>,
    _uid: Option<u32>,
    _gid: Option<u32>,
    size: Option<u64>,
    atime: Option<TimeOrNow>,
    mtime: Option<TimeOrNow>,
    _ctime: Option<SystemTime>,
    _fh: Option<u64>,
    _crtime: Option<SystemTime>,
    _chgtime: Option<SystemTime>,
    _bkuptime: Option<SystemTime>,
    _flags: Option<u32>,
    reply: ReplyAttr,
) {
    let to_secs = |t: TimeOrNow| match t {
        TimeOrNow::SpecificTime(s) => s.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
        TimeOrNow::Now => now_systime_to_secs(),
    };
    b.dispatcher.call_async(Req::SetAttr {
        nodeid: ino,
        mode,
        size,
        atime: atime.map(to_secs),
        mtime: mtime.map(to_secs),
    }, move |__res| match __res {
        Res::Attr(a) => {
            let fa = attr_to_fileattr(&a, ino);
            reply.attr(&TTL, &fa);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn readlink(b: &mut FuseBridge, _r: &Request, ino: u64, reply: ReplyData) {
    b.dispatcher.call_async(Req::Readlink { nodeid: ino }, move |__res| match __res {
        Res::Linkname(s) => reply.data(s.as_bytes()),
        Res::Bytes(bytes) => reply.data(&bytes),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn statfs(b: &mut FuseBridge, _r: &Request, ino: u64, reply: ReplyStatfs) {
    b.dispatcher.call_async(Req::Statfs { nodeid: ino }, move |__res| match __res {
        Res::Statfs(s) => {
            let StatfsOut {
                blocks,
                bfree,
                bavail,
                files,
                ffree,
                bsize,
                namelen,
                frsize,
            } = s;
            reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, frsize);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

// ---------------------------------------------------------------------------
// v3 ops: fsyncdir, xattrs, bmap
// ---------------------------------------------------------------------------

pub(crate) fn fsyncdir(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, datasync: bool, reply: fuser::ReplyEmpty) {
    b.dispatcher.call_async(Req::Fsyncdir { fh, datasync }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn setxattr(
    b: &mut FuseBridge,
    _r: &Request,
    ino: u64,
    name: &OsStr,
    value: &[u8],
    flags: i32,
    _position: u32,
    reply: fuser::ReplyEmpty,
) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    b.dispatcher.call_async(Req::Setxattr {
        nodeid: ino,
        name: n,
        value: value.to_vec(),
        flags: flags as u32,
    }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn getxattr(b: &mut FuseBridge, _r: &Request, ino: u64, name: &OsStr, size: u32, reply: fuser::ReplyXattr) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    b.dispatcher.call_async(Req::Getxattr {
        nodeid: ino,
        name: n,
        size,
    }, move |__res| match __res {
        Res::XattrSize(sz) => reply.size(sz),
        Res::Bytes(data) => reply.data(&data),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn listxattr(b: &mut FuseBridge, _r: &Request, ino: u64, size: u32, reply: fuser::ReplyXattr) {
    b.dispatcher.call_async(Req::Listxattr { nodeid: ino, size }, move |__res| match __res {
        Res::XattrSize(sz) => reply.size(sz),
        Res::XattrList(data) => reply.data(&data),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn removexattr(b: &mut FuseBridge, _r: &Request, ino: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    b.dispatcher.call_async(Req::Removexattr { nodeid: ino, name: n }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn bmap(b: &mut FuseBridge, _r: &Request, ino: u64, blocksize: u32, idx: u64, reply: fuser::ReplyBmap) {
    b.dispatcher.call_async(Req::Bmap {
        nodeid: ino,
        blocksize,
        idx,
    }, move |__res| match __res {
        Res::BmapBlock(block) => reply.bmap(block),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}
