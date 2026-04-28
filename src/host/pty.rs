//! Host-side PTY helpers (cross-platform).
//!
//! The host opens a PTY master and bridges it to the guest's PTY via the
//! init protocol. This architecture (host-allocated PTY, guest-allocated
//! PTY, protocol bridge) is used by Firecracker and Kata Containers.
//!
//! Key design decisions:
//! - Host PTY is set to **raw mode**: all bytes pass through transparently.
//!   Signal generation (^C → SIGINT, ^\ → SIGQUIT, ^Z → SIGTSTP) happens
//!   on the **guest** side where the child has a real controlling terminal.
//! - Host controls the fd lifecycle; guest PTY death doesn't invalidate
//!   the host fd.
//! - `mio::Poll` on the PTY master fd provides event-driven I/O (no busy
//!   polling).

#![cfg(unix)]

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::{Error, Result};

/// Open a PTY master and return it as an `OwnedFd`.
pub(crate) fn open_pty_master() -> Result<OwnedFd> {
    #[cfg(target_os = "macos")]
    {
        let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if fd < 0 {
            return Err(Error::exec(format!(
                "posix_openpt: {}",
                std::io::Error::last_os_error()
            )));
        }
        if unsafe { libc::grantpt(fd) } != 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::exec(format!("grantpt: {e}")));
        }
        if unsafe { libc::unlockpt(fd) } != 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::exec(format!("unlockpt: {e}")));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    #[cfg(target_os = "linux")]
    {
        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(Error::exec(format!("openpty: {}", std::io::Error::last_os_error())));
        }
        unsafe { libc::close(slave) };
        Ok(unsafe { OwnedFd::from_raw_fd(master) })
    }
}

/// Put the PTY master into raw mode: disable all special-character processing
/// (^C → SIGINT, ^\ → SIGQUIT, ^Z → SIGTSTP, echo, canonical mode, etc.).
/// All bytes pass through transparently so the guest PTY handles signal
/// generation for the child process.
pub(crate) fn set_raw_mode(fd: RawFd) -> Result<()> {
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(Error::exec(format!("tcgetattr: {}", std::io::Error::last_os_error())));
    }
    // cfmakeraw equivalent.
    termios.c_iflag &= !(libc::IGNBRK
        | libc::BRKINT
        | libc::PARMRK
        | libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON);
    termios.c_oflag &= !libc::OPOST;
    termios.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
    termios.c_cflag &= !(libc::CSIZE | libc::PARENB);
    termios.c_cflag |= libc::CS8;
    termios.c_cc[libc::VMIN] = 1;
    termios.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(Error::exec(format!("tcsetattr: {}", std::io::Error::last_os_error())));
    }
    Ok(())
}

/// Set the window size on a PTY master fd.
pub(crate) fn set_winsize(fd: RawFd, rows: u16, cols: u16) -> Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } != 0 {
        return Err(Error::exec(format!(
            "ioctl(TIOCSWINSZ): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
