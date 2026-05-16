//! File ops: open, read, write, flush, release, create.

use std::ffi::OsStr;

use fuser::{ReplyCreate, ReplyData, ReplyEmpty, ReplyOpen, ReplyWrite, Request, consts};
use tokimo_package_sandbox::vfs_protocol::{Req, Res};

use super::super::bridge::{FuseBridge, TTL, entry_to_attr, errno_of};

pub(crate) fn open(b: &mut FuseBridge, _r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
    match b.dispatcher.call(Req::Open {
        nodeid: ino,
        flags: flags as u32,
    }) {
        // FOPEN_KEEP_CACHE: kernel keeps page cache across opens
        // — subsequent reads of the same file hit the cache
        // without ever consulting FUSE userspace. Combined with
        // FUSE_AUTO_INVAL_DATA and our 60s entry/attr TTL the
        // cache is safe for sandbox-local FS where no external
        // process mutates files behind our back.
        Res::OpenOk { fh } => reply.opened(fh, consts::FOPEN_KEEP_CACHE),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn read(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    offset: i64,
    size: u32,
    _flags: i32,
    _lock: Option<u64>,
    reply: ReplyData,
) {
    match b.dispatcher.call(Req::Read {
        fh,
        offset: offset.max(0) as u64,
        size,
    }) {
        Res::Bytes(bytes) => reply.data(&bytes),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    offset: i64,
    data: &[u8],
    _wflags: u32,
    _flags: i32,
    _lock: Option<u64>,
    reply: ReplyWrite,
) {
    match b.dispatcher.call(Req::Write {
        fh,
        offset: offset.max(0) as u64,
        data: data.to_vec(),
    }) {
        Res::Written { size } => reply.written(size),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn flush(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
    match b.dispatcher.call(Req::Flush { fh }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn release(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    _flags: i32,
    _lock_owner: Option<u64>,
    _flush: bool,
    reply: ReplyEmpty,
) {
    match b.dispatcher.call(Req::Release { fh }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn create(
    b: &mut FuseBridge,
    _r: &Request,
    parent: u64,
    name: &OsStr,
    mode: u32,
    _umask: u32,
    flags: i32,
    reply: ReplyCreate,
) {
    // Two-step: lookup-or-create via Mkdir-style? VFS protocol
    // doesn't have a separate `create`; use Mkdir for dirs and
    // for regular files we synthesise:
    //   1. Open the file with O_CREAT semantics — requires the
    //      backend to honour `flags & O_CREAT`. Our protocol's
    //      Open already does this when the mount is writable.
    //   2. After successful Open, the host should have a node
    //      for the new file; do a Lookup to resolve it.
    //
    // For correctness across backends we emulate touch-then-open:
    // this is rare on the hot path.
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    // First Lookup; if not found, fall through to write a 0-byte
    // file via SetAttr-truncate-after-Open by issuing an Open
    // with the O_CREAT bit set.
    match b.dispatcher.call(Req::Lookup {
        parent_nodeid: parent,
        name: n.clone(),
    }) {
        Res::Entry(e) => {
            // Already exists; just open.
            let nodeid = e.nodeid;
            let attr = entry_to_attr(&e);
            let gen_ = e.generation;
            match b.dispatcher.call(Req::Open {
                nodeid,
                flags: flags as u32,
            }) {
                Res::OpenOk { fh } => reply.created(&TTL, &attr, gen_, fh, 0),
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }
        Res::Error(_) => {
            // Not found: ask the host to create an empty file,
            // then open it for the caller.
            match b.dispatcher.call(Req::Create {
                parent_nodeid: parent,
                name: n.clone(),
                mode,
            }) {
                Res::Entry(e) => {
                    let nodeid = e.nodeid;
                    let attr = entry_to_attr(&e);
                    let gen_ = e.generation;
                    match b.dispatcher.call(Req::Open {
                        nodeid,
                        flags: flags as u32,
                    }) {
                        Res::OpenOk { fh } => reply.created(&TTL, &attr, gen_, fh, 0),
                        Res::Error(we) => reply.error(errno_of(&we)),
                        _ => reply.error(libc::EIO),
                    }
                }
                Res::Error(we) => reply.error(errno_of(&we)),
                _ => reply.error(libc::EIO),
            }
        }
        _ => reply.error(libc::EIO),
    }
}
