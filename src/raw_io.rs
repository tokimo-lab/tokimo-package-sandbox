//! Thin wrappers around `libc::read` / `libc::write` that handle the
//! most common edge-cases uniformly:
//!
//! * **EINTR** — automatically retried in all functions.
//! * **Short writes** — `write_all` loops until the full buffer is sent.
//! * **Nonblocking fds** — `_nb` variants treat `EAGAIN` / `EWOULDBLOCK`
//!   as `Ok(None)` rather than an error.
//!
//! All functions take a `RawFd` and are safe at the call-site; the `unsafe`
//! is confined to the implementations below.  Error values are
//! `std::io::Error` throughout.

#![cfg(unix)]

use std::io;
use std::os::fd::RawFd;

/// One-shot read with automatic EINTR retry.
///
/// Returns `Ok(0)` on EOF, `Ok(n)` when `n` bytes were placed in `buf`,
/// or `Err` for any other error (including `EAGAIN`/`EWOULDBLOCK` on a
/// nonblocking fd — use [`read_once_nb`] to handle those).
pub fn read_once(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// One-shot write with automatic EINTR retry.
///
/// Short writes (0 < returned n < buf.len()) are allowed; the caller is
/// responsible for looping if needed.  Use [`write_all`] to guarantee a full
/// write.  Returns `Err` for any error (including `EAGAIN`/`EWOULDBLOCK` on
/// a nonblocking fd — use [`write_once_nb`] to handle those).
pub fn write_once(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Write the entire `buf` to `fd`, looping on short writes and EINTR.
///
/// Returns `Ok(())` once every byte has been written, or `Err` on the first
/// unrecoverable error.
pub fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        off += write_once(fd, &buf[off..])?;
    }
    Ok(())
}

/// Nonblocking read with automatic EINTR retry.
///
/// Returns:
/// * `Ok(Some(n))` — `n` bytes read (0 means EOF).
/// * `Ok(None)`    — fd is not ready (`EAGAIN` / `EWOULDBLOCK`).
/// * `Err`         — any other I/O error.
pub fn read_once_nb(fd: RawFd, buf: &mut [u8]) -> io::Result<Option<usize>> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(Some(n as usize));
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(e),
        }
    }
}

/// Nonblocking write with automatic EINTR retry.
///
/// Returns:
/// * `Ok(Some(n))` — `n` bytes written (short write allowed).
/// * `Ok(None)`    — fd is not ready (`EAGAIN` / `EWOULDBLOCK`).
/// * `Err`         — any other I/O error.
pub fn write_once_nb(fd: RawFd, buf: &[u8]) -> io::Result<Option<usize>> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(Some(n as usize));
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::FromRawFd;

    fn make_pipe() -> (RawFd, RawFd) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    fn close(fd: RawFd) {
        unsafe { libc::close(fd) };
    }

    #[test]
    fn read_once_eof() {
        let (r, w) = make_pipe();
        close(w);
        let mut buf = [0u8; 8];
        assert_eq!(read_once(r, &mut buf).unwrap(), 0);
        close(r);
    }

    #[test]
    fn write_once_and_read_once() {
        let (r, w) = make_pipe();
        let written = write_once(w, b"hello").unwrap();
        assert_eq!(written, 5);
        let mut buf = [0u8; 8];
        let n = read_once(r, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        close(r);
        close(w);
    }

    #[test]
    fn write_all_looping() {
        let (r, w) = make_pipe();
        let data = vec![42u8; 1024];
        write_all(w, &data).unwrap();
        let mut buf = vec![0u8; 1024];
        let mut received = 0;
        while received < 1024 {
            let n = read_once(r, &mut buf[received..]).unwrap();
            assert!(n > 0);
            received += n;
        }
        assert_eq!(buf, data);
        close(r);
        close(w);
    }

    #[test]
    fn read_once_nb_would_block() {
        let (r, w) = make_pipe();
        // Set read end nonblocking.
        unsafe {
            let flags = libc::fcntl(r, libc::F_GETFL);
            libc::fcntl(r, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut buf = [0u8; 8];
        // Nothing written yet — should return Ok(None).
        assert!(read_once_nb(r, &mut buf).unwrap().is_none());
        close(r);
        close(w);
    }

    #[test]
    fn write_once_nb_data() {
        let (r, w) = make_pipe();
        // Set write end nonblocking.
        unsafe {
            let flags = libc::fcntl(w, libc::F_GETFL);
            libc::fcntl(w, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let n = write_once_nb(w, b"world").unwrap();
        assert_eq!(n, Some(5));
        let mut buf = [0u8; 8];
        let got = read_once(r, &mut buf).unwrap();
        assert_eq!(&buf[..got], b"world");
        // Suppress unused-variable warning from `_file` used only to trigger drop.
        let _r_file = unsafe { std::fs::File::from_raw_fd(r) };
        let _w_file = unsafe { std::fs::File::from_raw_fd(w) };
    }
}
