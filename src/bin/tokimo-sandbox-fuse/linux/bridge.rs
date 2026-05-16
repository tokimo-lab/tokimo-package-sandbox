//! FUSE → wire bridge: `FuseBridge` struct + `impl Filesystem` (delegating).

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
};
use tokimo_package_sandbox::vfs_protocol::{AttrOut, EntryOut, NodeKind, WireError};

use super::dispatcher::Dispatcher;
use super::ops;

pub(crate) struct FuseBridge {
    pub(crate) dispatcher: Arc<Dispatcher>,
}

pub(crate) fn now_systime_to_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn entry_to_attr(e: &EntryOut) -> FileAttr {
    attr_to_fileattr(&e.attr, e.nodeid)
}

/// Owner uid/gid the kernel sees on every inode. Set once at startup
/// from the `--owner-uid`/`--owner-gid` CLI flags (default 1000/1000).
/// See the comment in `attr_to_fileattr` for why this exists.
pub(crate) static OWNER_UID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);
pub(crate) static OWNER_GID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);

pub(crate) fn attr_to_fileattr(a: &AttrOut, ino: u64) -> FileAttr {
    let kind = match a.kind {
        NodeKind::File => FileType::RegularFile,
        NodeKind::Dir => FileType::Directory,
        NodeKind::Symlink => FileType::Symlink,
        NodeKind::Socket => FileType::Socket,
        NodeKind::Fifo => FileType::NamedPipe,
        NodeKind::BlockDev => FileType::BlockDevice,
        NodeKind::CharDev => FileType::CharDevice,
    };
    let to_st = |secs: i64| {
        if secs > 0 {
            UNIX_EPOCH + Duration::from_secs(secs as u64)
        } else {
            UNIX_EPOCH
        }
    };
    FileAttr {
        ino,
        size: a.size,
        blocks: a.size.div_ceil(512),
        atime: to_st(a.mtime),
        mtime: to_st(a.mtime),
        ctime: to_st(a.mtime),
        crtime: to_st(a.mtime),
        kind,
        perm: (a.mode & 0o7777) as u16,
        nlink: a.nlink,
        // Single-user sandbox model. Override the on-wire uid/gid so
        // the kernel always sees the sandbox's own caller as owner.
        //  * VM mode (macOS/Windows): tokimo user, uid=1000/gid=1000.
        //  * Linux bwrap mode: the runner's uid (e.g. 1001 on CI),
        //    because that's the only uid mapped into the user_ns —
        //    anything else translates to overflow uid (65534) and
        //    makes the mount unwritable from inside the sandbox.
        uid: OWNER_UID.load(std::sync::atomic::Ordering::Relaxed),
        gid: OWNER_GID.load(std::sync::atomic::Ordering::Relaxed),
        rdev: a.rdev,
        blksize: 4096,
        flags: 0,
    }
}

pub(crate) fn errno_of(we: &WireError) -> i32 {
    if we.errno == 0 { libc::EIO } else { we.errno }
}

/// Inode/attr cache TTL handed back to the kernel on lookup/getattr
/// replies. The kernel will satisfy stat/access calls from its own
/// cache for this long without bothering us. 60 s is conservative —
/// agentic sandboxes are short-lived and the host filesystem isn't
/// concurrently mutated by anyone outside this process.
pub(crate) const TTL: Duration = Duration::from_secs(60);

impl Filesystem for FuseBridge {
    /// Negotiate kernel-side capabilities. Big wins:
    ///   * `set_max_write(1MB)` — single FUSE write request can carry
    ///     up to 1 MiB instead of the legacy 128 KiB. Cuts our write
    ///     RTTs by 8× for streamed writes.
    ///   * `set_max_readahead(1MB)` — kernel issues 1 MiB read-aheads
    ///     so sequential `read()` is one RTT instead of many.
    ///   * `FUSE_WRITEBACK_CACHE` — kernel buffers small writes in
    ///     the page cache and flushes lazily, so memcpy-sized writes
    ///     don't round-trip on every syscall.
    ///   * `FUSE_AUTO_INVAL_DATA` — kernel can re-read data when our
    ///     attr changes mtime, so it's safe to leave page cache hot.
    ///   * `FUSE_DO_READDIRPLUS` — combines READDIR + LOOKUP per
    ///     entry, halving syscalls when traversing big trees.
    ///   * `set_max_background(64)` — let the kernel issue more
    ///     concurrent requests instead of serialising at 16 inflight.
    fn init(&mut self, r: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        ops::meta::init(self, r, config)
    }

    fn lookup(&mut self, r: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        ops::meta::lookup(self, r, parent, name, reply)
    }

    fn forget(&mut self, r: &Request, ino: u64, nlookup: u64) {
        ops::meta::forget(self, r, ino, nlookup)
    }

    fn getattr(&mut self, r: &Request, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        ops::meta::getattr(self, r, ino, fh, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        r: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        ops::meta::setattr(
            self, r, ino, mode, uid, gid, size, atime, mtime, ctime, fh, crtime, chgtime, bkuptime, flags, reply,
        )
    }

    fn opendir(&mut self, r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        ops::dir::opendir(self, r, ino, flags, reply)
    }

    fn readdir(&mut self, r: &Request, ino: u64, fh: u64, offset: i64, reply: ReplyDirectory) {
        ops::dir::readdir(self, r, ino, fh, offset, reply)
    }

    fn releasedir(&mut self, r: &Request, ino: u64, fh: u64, flags: i32, reply: ReplyEmpty) {
        ops::dir::releasedir(self, r, ino, fh, flags, reply)
    }

    fn readdirplus(&mut self, r: &Request<'_>, ino: u64, fh: u64, offset: i64, reply: ReplyDirectoryPlus) {
        ops::dir::readdirplus(self, r, ino, fh, offset, reply)
    }

    fn open(&mut self, r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        ops::file::open(self, r, ino, flags, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock: Option<u64>,
        reply: ReplyData,
    ) {
        ops::file::read(self, r, ino, fh, offset, size, flags, lock, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        wflags: u32,
        flags: i32,
        lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        ops::file::write(self, r, ino, fh, offset, data, wflags, flags, lock, reply)
    }

    fn flush(&mut self, r: &Request, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        ops::file::flush(self, r, ino, fh, lock_owner, reply)
    }

    fn release(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        ops::file::release(self, r, ino, fh, flags, lock_owner, flush, reply)
    }

    fn mkdir(&mut self, r: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
        ops::dir::mkdir(self, r, parent, name, mode, umask, reply)
    }

    /// `mknod(2)` — the kernel invokes this for `bind(2)` of AF_UNIX
    /// sockets, `mkfifo(3)`, and device-node creation. The `mode`
    /// argument arrives with `S_IFMT` already encoded so the host
    /// VFS knows which kind of inode to materialise.
    fn mknod(&mut self, r: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, rdev: u32, reply: ReplyEntry) {
        ops::mutate::mknod(self, r, parent, name, mode, umask, rdev, reply)
    }

    fn rmdir(&mut self, r: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        ops::dir::rmdir(self, r, parent, name, reply)
    }

    fn unlink(&mut self, r: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        ops::mutate::unlink(self, r, parent, name, reply)
    }

    fn rename(
        &mut self,
        r: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        ops::mutate::rename(self, r, parent, name, newparent, newname, flags, reply)
    }

    fn symlink(&mut self, r: &Request, parent: u64, name: &OsStr, link: &Path, reply: ReplyEntry) {
        ops::mutate::symlink(self, r, parent, name, link, reply)
    }

    fn readlink(&mut self, r: &Request, ino: u64, reply: ReplyData) {
        ops::meta::readlink(self, r, ino, reply)
    }

    fn create(
        &mut self,
        r: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        ops::file::create(self, r, parent, name, mode, umask, flags, reply)
    }

    fn statfs(&mut self, r: &Request, ino: u64, reply: ReplyStatfs) {
        ops::meta::statfs(self, r, ino, reply)
    }

    // ----- v3 ops -----

    fn link(&mut self, r: &Request, ino: u64, newparent: u64, newname: &OsStr, reply: ReplyEntry) {
        ops::mutate::link(self, r, ino, newparent, newname, reply)
    }

    fn access(&mut self, r: &Request, ino: u64, mask: i32, reply: ReplyEmpty) {
        ops::mutate::access(self, r, ino, mask, reply)
    }

    fn fsync(&mut self, r: &Request, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        ops::file::fsync(self, r, ino, fh, datasync, reply)
    }

    fn fsyncdir(&mut self, r: &Request, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        ops::meta::fsyncdir(self, r, ino, fh, datasync, reply)
    }

    fn setxattr(
        &mut self,
        r: &Request,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        ops::meta::setxattr(self, r, ino, name, value, flags, position, reply)
    }

    fn getxattr(&mut self, r: &Request, ino: u64, name: &OsStr, size: u32, reply: fuser::ReplyXattr) {
        ops::meta::getxattr(self, r, ino, name, size, reply)
    }

    fn listxattr(&mut self, r: &Request, ino: u64, size: u32, reply: fuser::ReplyXattr) {
        ops::meta::listxattr(self, r, ino, size, reply)
    }

    fn removexattr(&mut self, r: &Request, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        ops::meta::removexattr(self, r, ino, name, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn fallocate(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        ops::file::fallocate(self, r, ino, fh, offset, length, mode, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_file_range(
        &mut self,
        r: &Request,
        ino_in: u64,
        fh_in: u64,
        off_in: i64,
        ino_out: u64,
        fh_out: u64,
        off_out: i64,
        len: u64,
        flags: u32,
        reply: ReplyWrite,
    ) {
        ops::file::copy_file_range(self, r, ino_in, fh_in, off_in, ino_out, fh_out, off_out, len, flags, reply)
    }

    fn lseek(&mut self, r: &Request, ino: u64, fh: u64, offset: i64, whence: i32, reply: fuser::ReplyLseek) {
        ops::file::lseek(self, r, ino, fh, offset, whence, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn getlk(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: fuser::ReplyLock,
    ) {
        ops::file::getlk(self, r, ino, fh, owner, start, end, typ, pid, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn setlk(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        ops::file::setlk(self, r, ino, fh, owner, start, end, typ, pid, sleep, reply)
    }

    fn bmap(&mut self, r: &Request, ino: u64, blocksize: u32, idx: u64, reply: fuser::ReplyBmap) {
        ops::meta::bmap(self, r, ino, blocksize, idx, reply)
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &mut self,
        r: &Request,
        ino: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {
        ops::file::ioctl(self, r, ino, fh, flags, cmd, in_data, out_size, reply)
    }
}
