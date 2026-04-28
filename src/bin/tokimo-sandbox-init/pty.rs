//! PTY allocation + winsize ioctl helpers.

use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Allocate a UNIX98 pseudo-terminal pair via posix_openpt + grantpt + unlockpt.
/// Returns the master fd (CLOEXEC, non-blocking will be set later) and the
/// resolved slave path (e.g., `/dev/pts/3`).
pub fn open_pty() -> Result<(OwnedFd, String), String> {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if master < 0 {
            return Err(format!("posix_openpt: {}", std::io::Error::last_os_error()));
        }
        if libc::grantpt(master) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(master);
            return Err(format!("grantpt: {e}"));
        }
        if libc::unlockpt(master) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(master);
            return Err(format!("unlockpt: {e}"));
        }
        // Linux ptsname_r is preferred; fall back to ptsname (not async-safe
        // but we're in init parent, no signal hazard).
        let mut buf = [0i8; 256];
        let r = libc::ptsname_r(master, buf.as_mut_ptr().cast(), buf.len());
        if r != 0 {
            libc::close(master);
            return Err(format!("ptsname_r: errno {r}"));
        }
        let cstr = CStr::from_ptr(buf.as_ptr().cast());
        let path = cstr.to_string_lossy().into_owned();
        let master_fd = OwnedFd::from_raw_fd(master);
        // Suppress unused warning for CString import.
        let _ = CString::new("");
        Ok((master_fd, path))
    }
}

pub fn set_winsize(master_fd: i32, rows: u16, cols: u16) -> Result<(), String> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let r = unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws as *const _) };
    if r < 0 {
        return Err(format!("TIOCSWINSZ: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[allow(dead_code)]
fn _silence() {
    let _ = OwnedFd::as_raw_fd;
}
