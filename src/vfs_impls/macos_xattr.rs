//! macOS xattr fallback for socket / FIFO nodes
//!
//! Darwin's `mknod(2)` requires root for *every* node kind, including
//! `S_IFSOCK` and `S_IFIFO`. The FUSE bridge runs as an unprivileged
//! user, so when guest code inside the Linux micro-VM does `bind(AF_UNIX)`
//! the host-side `LocalDirVfs::mknod` falls back to creating an empty
//! regular file plus a single-byte `com.tokimo.kind` extended attribute
//! recording the *logical* node type. On lookup we read the xattr back
//! and report `is_socket=true` / `is_fifo=true`, so the FUSE bridge tells
//! the Linux kernel `S_ISSOCK(inode->i_mode)` and `connect(2)` works.
//!
//! This is the moral equivalent of the `$LXMOD` NTFS EA on the Windows
//! backend — same problem (host FS has no native socket inode kind for
//! unprivileged callers), same solution (out-of-band kind marker).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const XATTR_NAME: &[u8] = b"com.tokimo.kind\0";
pub(super) const KIND_SOCKET: u8 = 1;
pub(super) const KIND_FIFO: u8 = 2;

fn cpath(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has NUL byte"))
}

pub(super) fn set(path: &Path, kind: u8) -> std::io::Result<()> {
    let cpath = cpath(path)?;
    let value = [kind];
    let ret = unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            XATTR_NAME.as_ptr() as *const _,
            value.as_ptr() as *const _,
            value.len(),
            0, // position (only used for resource forks)
            0, // options
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(super) fn get(path: &Path) -> Option<u8> {
    let cpath = cpath(path).ok()?;
    let mut buf = [0u8; 1];
    let ret = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            XATTR_NAME.as_ptr() as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            0,
            0,
        )
    };
    if ret == 1 { Some(buf[0]) } else { None }
}
