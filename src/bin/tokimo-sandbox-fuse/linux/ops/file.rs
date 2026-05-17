//! File ops: open, read, write, flush, release, create.

use std::ffi::OsStr;

use fuser::{ReplyCreate, ReplyData, ReplyEmpty, ReplyOpen, ReplyWrite, Request, consts};
use tokimo_package_sandbox::vfs_protocol::{Req, Res};

use super::super::bridge::{FuseBridge, TTL, entry_to_attr, errno_of};

pub(crate) fn open(b: &mut FuseBridge, _r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
    b.dispatcher.call_async(Req::Open {
        nodeid: ino,
        flags: flags as u32,
    }, move |__res| match __res {
        // FOPEN_KEEP_CACHE: kernel keeps page cache across opens
        // — subsequent reads of the same file hit the cache
        // without ever consulting FUSE userspace. Combined with
        // FUSE_AUTO_INVAL_DATA and our 60s entry/attr TTL the
        // cache is safe for sandbox-local FS where no external
        // process mutates files behind our back.
        Res::OpenOk { fh } => reply.opened(fh, consts::FOPEN_KEEP_CACHE),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Read {
        fh,
        offset: offset.max(0) as u64,
        size,
    }, move |__res| match __res {
        Res::Bytes(bytes) => reply.data(&bytes),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Write {
        fh,
        offset: offset.max(0) as u64,
        data: data.to_vec(),
    }, move |__res| match __res {
        Res::Written { size } => reply.written(size),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}

pub(crate) fn flush(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
    b.dispatcher.call_async(Req::Flush { fh }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Release { fh }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    // Lookup → if found Open; else Create then Open. Each step
    // hops through call_async so the FUSE reader loop never
    // blocks waiting on the wire.
    fn do_open(
        disp: std::sync::Arc<super::super::dispatcher::Dispatcher>,
        e: tokimo_package_sandbox::vfs_protocol::EntryOut,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let nodeid = e.nodeid;
        let attr = entry_to_attr(&e);
        let gen_ = e.generation;
        disp.call_async(Req::Open { nodeid, flags: flags as u32 }, move |__res| match __res {
            Res::OpenOk { fh } => reply.created(&TTL, &attr, gen_, fh, 0),
            Res::Error(we) => reply.error(errno_of(&we)),
            _ => reply.error(libc::EIO),
        });
    }
    let disp = b.dispatcher.clone();
    let n2 = n.clone();
    let disp_for_create = disp.clone();
    disp.call_async(Req::Lookup { parent_nodeid: parent, name: n }, move |__res| match __res {
        Res::Entry(e) => do_open(disp_for_create, e, flags, reply),
        Res::Error(_) => {
            let disp_again = disp_for_create.clone();
            disp_for_create.call_async(
                Req::Create { parent_nodeid: parent, name: n2, mode },
                move |__res| match __res {
                    Res::Entry(e) => do_open(disp_again, e, flags, reply),
                    Res::Error(we) => reply.error(errno_of(&we)),
                    _ => reply.error(libc::EIO),
                },
            );
        }
        _ => reply.error(libc::EIO),
    });
}

// ---------------------------------------------------------------------------
// v3 fh-based ops
// ---------------------------------------------------------------------------

pub(crate) fn fsync(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
    b.dispatcher.call_async(Req::Fsync { fh, datasync }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Fallocate {
        fh,
        offset,
        length,
        mode: mode as u32,
    }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::CopyFileRange {
        fh_in,
        off_in,
        fh_out,
        off_out,
        len,
        flags,
    }, move |__res| match __res {
        Res::Written { size } => reply.written(size),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Lseek {
        fh,
        offset,
        whence: whence as u32,
    }, move |__res| match __res {
        Res::Offset(o) => reply.offset(o),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Getlk {
        fh,
        owner,
        lk: LockSpec {
            typ: lt,
            whence: 0,
            start,
            end,
            pid,
        },
    }, move |__res| match __res {
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
    });
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
    b.dispatcher.call_async(Req::Setlk {
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
    }, move |__res| match __res {
        Res::Ok => reply.ok(),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
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
    b.dispatcher.call_async(Req::Ioctl {
        fh,
        cmd,
        arg: 0,
        in_data: in_data.to_vec(),
        out_size,
        flags,
    }, move |__res| match __res {
        Res::Ioctl { result, data } => reply.ioctl(result, &data),
        Res::Error(we) => reply.error(errno_of(&we)),
        _ => reply.error(libc::EIO),
    });
}
