//! Directory ops: opendir, readdir, readdirplus, releasedir, mkdir, rmdir.

use std::ffi::OsStr;

use fuser::{FileType, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, Request, consts};
use tokimo_package_sandbox::vfs_protocol::{NodeKind, Req, Res};

use super::super::bridge::{FuseBridge, TTL, entry_to_attr, errno_of};

pub(crate) fn opendir(b: &mut FuseBridge, _r: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
    b.dispatcher
        .call_async(Req::OpenDir { nodeid: ino }, move |__res| match __res {
            // FOPEN_CACHE_DIR: kernel may cache directory contents
            // across opens, eliding repeated readdir round-trips.
            Res::OpenOk { fh } => reply.opened(fh, consts::FOPEN_CACHE_DIR),
            Res::Error(we) => reply.error(errno_of(&we)),
            _ => reply.error(libc::EIO),
        });
}

pub(crate) fn readdir(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectory) {
    b.dispatcher.call_async(
        Req::ReadDir {
            fh,
            offset: offset.max(0) as u64,
        },
        move |__res| match __res {
            Res::DirEntries(entries) => {
                for e in entries {
                    let kind = match e.kind {
                        NodeKind::Dir => FileType::Directory,
                        NodeKind::Symlink => FileType::Symlink,
                        NodeKind::File => FileType::RegularFile,
                        NodeKind::Socket => FileType::Socket,
                        NodeKind::Fifo => FileType::NamedPipe,
                        NodeKind::BlockDev => FileType::BlockDevice,
                        NodeKind::CharDev => FileType::CharDevice,
                    };
                    // ReplyDirectory::add returns true if buffer full.
                    if reply.add(e.nodeid, e.offset as i64, kind, e.name) {
                        break;
                    }
                }
                reply.ok();
            }
            Res::Error(we) => reply.error(errno_of(&we)),
            _ => reply.error(libc::EIO),
        },
    );
}

pub(crate) fn releasedir(b: &mut FuseBridge, _r: &Request, _ino: u64, fh: u64, _flags: i32, reply: ReplyEmpty) {
    // Same reasoning as `release` — the kernel does not propagate
    // the result to userspace. Fire-and-forget saves one RTT per
    // directory close.
    b.dispatcher.call_async(Req::ReleaseDir { fh }, |_| {});
    reply.ok();
}

pub(crate) fn readdirplus(
    b: &mut FuseBridge,
    _r: &Request<'_>,
    _ino: u64,
    fh: u64,
    offset: i64,
    mut reply: ReplyDirectoryPlus,
) {
    b.dispatcher.call_async(
        Req::ReadDirPlus {
            fh,
            offset: offset.max(0) as u64,
        },
        move |__res| match __res {
            Res::DirEntriesPlus(entries) => {
                for e in entries {
                    let attr = entry_to_attr(&e.entry);
                    if reply.add(
                        e.entry.nodeid,
                        e.offset as i64,
                        &e.name,
                        &TTL,
                        &attr,
                        e.entry.generation,
                    ) {
                        break;
                    }
                }
                reply.ok();
            }
            Res::Error(we) => reply.error(errno_of(&we)),
            _ => reply.error(libc::EIO),
        },
    );
}

pub(crate) fn mkdir(
    b: &mut FuseBridge,
    _r: &Request,
    parent: u64,
    name: &OsStr,
    mode: u32,
    _umask: u32,
    reply: ReplyEntry,
) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    b.dispatcher.call_async(
        Req::Mkdir {
            parent_nodeid: parent,
            name: n,
            mode,
        },
        move |__res| match __res {
            Res::Entry(e) => {
                let attr = entry_to_attr(&e);
                reply.entry(&TTL, &attr, e.generation);
            }
            Res::Error(we) => reply.error(errno_of(&we)),
            _ => reply.error(libc::EIO),
        },
    );
}

pub(crate) fn rmdir(b: &mut FuseBridge, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
    let n = match name.to_str() {
        Some(s) => s.to_string(),
        None => return reply.error(libc::EINVAL),
    };
    b.dispatcher.call_async(
        Req::Rmdir {
            parent_nodeid: parent,
            name: n,
        },
        move |__res| match __res {
            Res::Ok => reply.ok(),
            Res::Error(we) => reply.error(errno_of(&we)),
            _ => reply.error(libc::EIO),
        },
    );
}
