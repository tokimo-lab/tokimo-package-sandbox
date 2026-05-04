//! macOS VSOCK stream transport adapter for the unified `InitClient`.
//!
//! Wraps an `OwnedFd` (virtio-vsock stream socket), `dup(2)`'ing it so the
//! reader thread and the writer path operate on independent file descriptors.

#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::init_client::{ReceivedFrame, TransportRecv, TransportSend};
use crate::protocol::types::Frame;
use crate::protocol::wire::{recv_frame_stream, send_frame_stream};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Transport halves
// ---------------------------------------------------------------------------

/// Outbound VSOCK stream send half.
pub struct VsockSend(OwnedFd);

/// Inbound VSOCK stream recv half.
pub struct VsockRecv(OwnedFd);

impl TransportSend for VsockSend {
    fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        send_frame_stream(&mut FdWriter(&mut self.0), frame)
    }
}

impl TransportRecv for VsockRecv {
    fn recv_frame(&mut self) -> Result<Option<ReceivedFrame>> {
        match recv_frame_stream(&mut FdReader(&mut self.0)) {
            Ok(None) => Ok(None),
            Ok(Some(frame)) => Ok(Some(ReceivedFrame { frame, fd: None })),
            Err(e) => Err(e),
        }
    }
}

/// Split a connected VSOCK `OwnedFd` into send / recv halves via `dup(2)`.
fn split(fd: OwnedFd) -> Result<(VsockSend, VsockRecv)> {
    let dup_raw = unsafe { libc::dup(fd.as_raw_fd()) };
    if dup_raw < 0 {
        return Err(Error::other(format!(
            "dup VSOCK fd: {}",
            std::io::Error::last_os_error()
        )));
    }
    let recv_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
    Ok((VsockSend(fd), VsockRecv(recv_fd)))
}

// ---------------------------------------------------------------------------
// Constructors on InitClient<VsockSend>
// ---------------------------------------------------------------------------

impl crate::init_client::InitClient<VsockSend> {
    /// Wrap an already-connected VSOCK stream socket and spawn the reader.
    pub fn new(sock: OwnedFd) -> Result<Self> {
        let (send, recv) = split(sock)?;
        // macOS VM mode: init is always PID 1.
        crate::init_client::InitClient::new(send, recv, true)
    }
}

// ---------------------------------------------------------------------------
// FdReader / FdWriter adapters (via nix for macOS compatibility)
// ---------------------------------------------------------------------------

struct FdReader<'a>(&'a mut OwnedFd);

impl<'a> Read for FdReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        nix::unistd::read(self.0.as_raw_fd(), buf).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }
}

struct FdWriter<'a>(&'a mut OwnedFd);

impl<'a> Write for FdWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        nix::unistd::write(&*self.0, buf).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
