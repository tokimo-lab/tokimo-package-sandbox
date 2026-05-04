//! Linux `struct ifreq` / `SIOCSIFFLAGS` helpers used by guest-side
//! networking code.
//!
//! Centralises the small amount of `unsafe` needed to construct a
//! zero-initialised `libc::ifreq` and call common ioctls on it. Used by
//! `tokimo-sandbox-init`'s `bringup_lo` and by the netstack pump.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::RawFd;

/// Build a zero-initialised `libc::ifreq` with `ifr_name` set to `name`.
/// `name` must fit in `IFNAMSIZ - 1` bytes (`ifr_name` is 16 chars
/// including the trailing NUL).
pub fn ifr_with_name(name: &str) -> io::Result<libc::ifreq> {
    let bytes = name.as_bytes();
    if bytes.len() >= 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name too long: {name:?}"),
        ));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, &b) in bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    Ok(ifr)
}

/// Bring an interface UP (sets `IFF_UP | IFF_RUNNING` via `SIOCSIFFLAGS`).
/// `sock` is any open ioctl-delivery socket (typically `AF_INET DGRAM`).
pub fn set_iff_up(sock: RawFd, name: &str) -> io::Result<()> {
    let mut ifr = ifr_with_name(name)?;
    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bring up the loopback interface inside the current network namespace.
/// Allocates its own AF_INET DGRAM socket as the ioctl vehicle and closes
/// it before returning.
pub fn bringup_lo() -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = set_iff_up(sock, "lo");
    unsafe { libc::close(sock) };
    res
}
