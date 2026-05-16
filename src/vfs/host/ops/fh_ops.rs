//! File-handle ops added in protocol v3: fsync, fsyncdir, fallocate,
//! copy_file_range, lseek, getlk, setlk, bmap, ioctl, poll.
//!
//! These all operate on an already-opened `fh`. When the backend exposes
//! `as_resolve_local()` the bridge's `op_open` stores the real
//! `Arc<std::fs::File>` in [`FhEntry::File::host_file`]; the syscall
//! fastpath uses that directly. When `host_file` is `None` (e.g. for
//! [`MemFsVfs`] or any backend without a real file descriptor) we
//! degrade gracefully:
//!
//! - `fsync` / `fsyncdir` → no-op (`Res::Ok`): no host-resident dirty
//!   data exists, the FUSE bridge will have already drained any staged
//!   writes via `Flush`/`Release`.
//! - everything else → `ENOTSUP`.

#![allow(unused_variables, dead_code)]

use std::sync::Arc;

use crate::vfs_backend::VfsError;
use crate::vfs_protocol::{Errno, LockSpec, LockType, Res, WireError, errno_for};

use super::super::FuseHost;
use super::super::id_table::FhEntry;

impl FuseHost {
    /// Extract the host file handle for an open fh, if any.
    fn host_file(&self, fh: u64) -> Option<Arc<std::fs::File>> {
        self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File { host_file, .. } => host_file.clone(),
            _ => None,
        })?
    }

    pub(in crate::vfs::host) async fn op_fsync(&self, fh: u64, datasync: bool) -> Res {
        let Some(f) = self.host_file(fh) else {
            // No host-resident state — nothing to sync.
            return Res::Ok;
        };
        let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            if datasync {
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    let rc = unsafe { libc::fdatasync(f.as_raw_fd()) };
                    if rc != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    return Ok(());
                }
                #[cfg(not(target_os = "linux"))]
                {
                    f.sync_data()
                }
            } else {
                f.sync_all()
            }
        })
        .await;
        match res {
            Ok(Ok(())) => Res::Ok,
            Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
            Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
        }
    }

    pub(in crate::vfs::host) async fn op_fsyncdir(&self, _fh: u64, _datasync: bool) -> Res {
        // We snapshot directory entries at OpenDir; nothing to flush.
        Res::Ok
    }

    pub(in crate::vfs::host) async fn op_fallocate(
        &self,
        fh: u64,
        offset: i64,
        length: i64,
        mode: u32,
    ) -> Res {
        let Some(f) = self.host_file(fh) else {
            return Res::Error(errno_for(&VfsError::NotSupported("fallocate without host file".into())));
        };
        if length <= 0 || offset < 0 {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad range".into())));
        }
        let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let rc = unsafe { libc::fallocate(f.as_raw_fd(), mode as i32, offset, length) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }
            #[cfg(target_os = "macos")]
            {
                // Best-effort: F_PREALLOCATE (contiguous, then any).
                use std::os::fd::AsRawFd;
                let mut store = libc::fstore_t {
                    fst_flags: libc::F_ALLOCATECONTIG,
                    fst_posmode: libc::F_PEOFPOSMODE,
                    fst_offset: 0,
                    fst_length: offset + length,
                    fst_bytesalloc: 0,
                };
                let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
                if rc == -1 {
                    store.fst_flags = libc::F_ALLOCATEALL;
                    let rc2 = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
                    if rc2 == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // Optionally extend file length too if mode bit 0 (KEEP_SIZE) is unset.
                const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
                if (mode & FALLOC_FL_KEEP_SIZE) == 0 {
                    let target = (offset + length) as u64;
                    let cur = f.metadata()?.len();
                    if target > cur {
                        f.set_len(target)?;
                    }
                }
                Ok(())
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "fallocate"))
            }
        })
        .await;
        match res {
            Ok(Ok(())) => Res::Ok,
            Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
            Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
        }
    }

    pub(in crate::vfs::host) async fn op_copy_file_range(
        &self,
        fh_in: u64,
        off_in: i64,
        fh_out: u64,
        off_out: i64,
        len: u64,
        _flags: u32,
    ) -> Res {
        let f_in = self.host_file(fh_in);
        let f_out = self.host_file(fh_out);
        let (Some(f_in), Some(f_out)) = (f_in, f_out) else {
            return Res::Error(errno_for(&VfsError::NotSupported(
                "copy_file_range without host files".into(),
            )));
        };
        let res = tokio::task::spawn_blocking(move || -> std::io::Result<u32> {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let mut off_i = off_in;
                let mut off_o = off_out;
                let rc = unsafe {
                    libc::copy_file_range(
                        f_in.as_raw_fd(),
                        &mut off_i as *mut _,
                        f_out.as_raw_fd(),
                        &mut off_o as *mut _,
                        len as usize,
                        0,
                    )
                };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(rc as u32)
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Userland fallback: read-then-write up to MAX_IO_CHUNK to
                // give callers *something*.
                use std::os::unix::fs::FileExt;
                let to_copy = len.min(1 << 20) as usize;
                let mut buf = vec![0u8; to_copy];
                let n = f_in.read_at(&mut buf, off_in as u64)?;
                if n == 0 {
                    return Ok(0);
                }
                f_out.write_at(&buf[..n], off_out as u64)?;
                Ok(n as u32)
            }
        })
        .await;
        match res {
            Ok(Ok(n)) => Res::Written { size: n },
            Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
            Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
        }
    }

    pub(in crate::vfs::host) async fn op_lseek(&self, fh: u64, offset: i64, whence: u32) -> Res {
        let Some(f) = self.host_file(fh) else {
            return Res::Error(errno_for(&VfsError::NotSupported("lseek without host file".into())));
        };
        let res = tokio::task::spawn_blocking(move || -> std::io::Result<i64> {
            use std::os::fd::AsRawFd;
            let rc = unsafe { libc::lseek(f.as_raw_fd(), offset as libc::off_t, whence as i32) };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(rc as i64)
        })
        .await;
        match res {
            Ok(Ok(off)) => Res::Offset(off),
            Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
            Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
        }
    }

    pub(in crate::vfs::host) async fn op_getlk(&self, fh: u64, _owner: u64, lk: LockSpec) -> Res {
        let Some(f) = self.host_file(fh) else {
            return Res::Error(errno_for(&VfsError::NotSupported("getlk without host file".into())));
        };
        #[cfg(target_os = "linux")]
        {
            let res = tokio::task::spawn_blocking(move || -> std::io::Result<LockSpec> {
                use std::os::fd::AsRawFd;
                let l_type: libc::c_short = match lk.typ {
                    LockType::Read => libc::F_RDLCK as libc::c_short,
                    LockType::Write => libc::F_WRLCK as libc::c_short,
                    LockType::Unlock => libc::F_UNLCK as libc::c_short,
                };
                let len = if lk.end >= lk.start {
                    (lk.end - lk.start) as libc::off_t
                } else {
                    0
                };
                let mut flock = libc::flock {
                    l_type,
                    l_whence: libc::SEEK_SET as libc::c_short,
                    l_start: lk.start as libc::off_t,
                    l_len: len,
                    l_pid: 0,
                };
                let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_OFD_GETLK, &mut flock) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let typ = match flock.l_type as i32 {
                    libc::F_RDLCK => LockType::Read,
                    libc::F_WRLCK => LockType::Write,
                    _ => LockType::Unlock,
                };
                Ok(LockSpec {
                    typ,
                    whence: 0,
                    start: flock.l_start as u64,
                    end: (flock.l_start + flock.l_len) as u64,
                    pid: flock.l_pid as u32,
                })
            })
            .await;
            return match res {
                Ok(Ok(spec)) => Res::Lock(spec),
                Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
                Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (f, lk);
            Res::Error(errno_for(&VfsError::NotSupported("getlk".into())))
        }
    }

    pub(in crate::vfs::host) async fn op_setlk(&self, fh: u64, _owner: u64, lk: LockSpec, sleep: bool) -> Res {
        let Some(f) = self.host_file(fh) else {
            return Res::Error(errno_for(&VfsError::NotSupported("setlk without host file".into())));
        };
        #[cfg(target_os = "linux")]
        {
            let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                use std::os::fd::AsRawFd;
                let l_type: libc::c_short = match lk.typ {
                    LockType::Read => libc::F_RDLCK as libc::c_short,
                    LockType::Write => libc::F_WRLCK as libc::c_short,
                    LockType::Unlock => libc::F_UNLCK as libc::c_short,
                };
                let len = if lk.end >= lk.start {
                    (lk.end - lk.start) as libc::off_t
                } else {
                    0
                };
                let mut flock = libc::flock {
                    l_type,
                    l_whence: libc::SEEK_SET as libc::c_short,
                    l_start: lk.start as libc::off_t,
                    l_len: len,
                    l_pid: 0,
                };
                let cmd = if sleep { libc::F_OFD_SETLKW } else { libc::F_OFD_SETLK };
                let rc = unsafe { libc::fcntl(f.as_raw_fd(), cmd, &mut flock) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .await;
            return match res {
                Ok(Ok(())) => Res::Ok,
                Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
                Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (f, lk, sleep);
            Res::Error(errno_for(&VfsError::NotSupported("setlk".into())))
        }
    }

    pub(in crate::vfs::host) async fn op_bmap(&self, _mount_id: u32, _nodeid: u64, _bs: u32, _idx: u64) -> Res {
        Res::Error(WireError::new(Errno::Enosys, "bmap unsupported on FUSE mount"))
    }

    pub(in crate::vfs::host) async fn op_ioctl(
        &self,
        _fh: u64,
        _cmd: u32,
        _arg: u64,
        _in_data: Vec<u8>,
        _out_size: u32,
        _flags: u32,
    ) -> Res {
        Res::Error(WireError::new(Errno::Enotsup, "ioctl not exposed"))
    }

    pub(in crate::vfs::host) async fn op_poll(&self, _fh: u64, _events: u32, _flags: u32) -> Res {
        Res::Error(WireError::new(Errno::Enosys, "poll unsupported"))
    }
}
