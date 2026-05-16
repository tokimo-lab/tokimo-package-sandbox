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

// ---------------------------------------------------------------------------
// v3 fh-based ops
// ---------------------------------------------------------------------------

pub(crate) fn fsync(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
    match b.dispatcher.call(Req::Fsync { fh, datasync }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fallocate(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    offset: i64,
    length: i64,
    mode: i32,
    reply: ReplyEmpty,
) {
    match b.dispatcher.call(Req::Fallocate {
        fh,
        offset,
        length,
        mode: mode as u32,
    }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_file_range(
    b: &mut FuseBridge,
    _r: &Request,
    _ino_in: u64,
    fh_in: u64,
    off_in: i64,
    _ino_out: u64,
    fh_out: u64,
    off_out: i64,
    len: u64,
    flags: u32,
    reply: fuser::ReplyWrite,
) {
    match b.dispatcher.call(Req::CopyFileRange {
        fh_in,
        off_in,
        fh_out,
        off_out,
        len,
        flags,
    }) {
        Res::Written { size } => reply.written(size),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

pub(crate) fn lseek(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    offset: i64,
    whence: i32,
    reply: fuser::ReplyLseek,
) {
    match b.dispatcher.call(Req::Lseek {
        fh,
        offset,
        whence: whence as u32,
    }) {
        Res::Offset(o) => reply.offset(o),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn getlk(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    owner: u64,
    start: u64,
    end: u64,
    typ: i32,
    pid: u32,
    reply: fuser::ReplyLock,
) {
    use tokimo_package_sandbox::vfs_protocol::{LockSpec, LockType};
    let lt = match typ {
        x if x == libc::F_RDLCK => LockType::Read,
        x if x == libc::F_WRLCK => LockType::Write,
        _ => LockType::Unlock,
    };
    match b.dispatcher.call(Req::Getlk {
        fh,
        owner,
        lk: LockSpec {
            typ: lt,
            whence: 0,
            start,
            end,
            pid,
        },
    }) {
        Res::Lock(s) => {
            let t = match s.typ {
                LockType::Read => libc::F_RDLCK,
                LockType::Write => libc::F_WRLCK,
                LockType::Unlock => libc::F_UNLCK,
            };
            reply.locked(s.start, s.end, t, s.pid);
        }
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn setlk(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    owner: u64,
    start: u64,
    end: u64,
    typ: i32,
    pid: u32,
    sleep: bool,
    reply: ReplyEmpty,
) {
    use tokimo_package_sandbox::vfs_protocol::{LockSpec, LockType};
    let lt = match typ {
        x if x == libc::F_RDLCK => LockType::Read,
        x if x == libc::F_WRLCK => LockType::Write,
        _ => LockType::Unlock,
    };
    match b.dispatcher.call(Req::Setlk {
        fh,
        owner,
        lk: LockSpec {
            typ: lt,
            whence: 0,
            start,
            end,
            pid,
        },
        sleep,
    }) {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ioctl(
    b: &mut FuseBridge,
    _r: &Request,
    _ino: u64,
    fh: u64,
    flags: u32,
    cmd: u32,
    in_data: &[u8],
    out_size: u32,
    reply: fuser::ReplyIoctl,
) {
    match b.dispatcher.call(Req::Ioctl {
        fh,
        cmd,
        arg: 0,
        in_data: in_data.to_vec(),
        out_size,
        flags,
    }) {
        Res::Ioctl { result, data } => reply.ioctl(result, &data),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    }
}
