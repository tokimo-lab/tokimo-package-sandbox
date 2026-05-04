//! Linux-only AF_VSOCK helpers shared by guest-side binaries.
//!
//! Both `tokimo-sandbox-init` (control plane) and `tokimo-sandbox-fuse`
//! (FUSE bridge) and `tokimo-tun-pump` need to dial the host on
//! `(VMADDR_CID_HOST, port)` shortly after VM boot, with bounded retries
//! while Hyper-V / VZ finish setting up per-VM hvsock plumbing.
//!
//! This module centralises the connect-with-retry loop so callers don't
//! each reimplement timeout + sleep semantics.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};

use crate::net_constants::VMADDR_CID_HOST;

/// Open an AF_VSOCK stream socket and connect to `(cid, port)` with
/// bounded retries. Returns the connected `OwnedFd` on success.
///
/// The socket is created with `SOCK_CLOEXEC`. The caller is responsible
/// for any post-connect mode flips (e.g. `O_NONBLOCK`).
pub fn connect_with_retry(cid: u32, port: u32, timeout: Duration, retry_interval: Duration) -> io::Result<OwnedFd> {
    let deadline = Instant::now() + timeout;
    let addr = VsockAddr::new(cid, port);
    loop {
        let fd =
            socket(AddressFamily::Vsock, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).map_err(io::Error::from)?;
        match connect(fd.as_raw_fd(), &addr) {
            Ok(()) => return Ok(fd),
            Err(e) => {
                drop(fd);
                if Instant::now() >= deadline {
                    return Err(io::Error::from(e));
                }
                std::thread::sleep(retry_interval);
            }
        }
    }
}

/// Connect to the well-known host CID with library-default retry timing
/// (30 s deadline, 200 ms retry interval). Convenience wrapper.
pub fn connect_host(port: u32) -> io::Result<OwnedFd> {
    connect_with_retry(
        VMADDR_CID_HOST,
        port,
        Duration::from_secs(30),
        Duration::from_millis(200),
    )
}
