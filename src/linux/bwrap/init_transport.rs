//! Linux SEQPACKET transport adapter for the unified `InitClient`.
//!
//! Wraps `AF_UNIX SOCK_SEQPACKET` sockets, supporting SCM_RIGHTS fd passing
//! for PTY master fds and FUSE socketpairs.

#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::init_client::{ReceivedFrame, TransportRecv, TransportSend};
use crate::protocol::types::Frame;
use crate::protocol::wire::{recv_frame_seqpacket, send_frame_seqpacket};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Transport halves
// ---------------------------------------------------------------------------

/// Outbound SEQPACKET send half.  Supports optional SCM_RIGHTS fd attachment.
pub struct SeqpacketSend(OwnedFd);

/// Inbound SEQPACKET recv half.  Returns any SCM_RIGHTS fd alongside the frame.
pub struct SeqpacketRecv(OwnedFd);

impl TransportSend for SeqpacketSend {
    fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let bf = unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) };
        send_frame_seqpacket(bf, frame, None)
    }

    fn send_frame_with_fd(&mut self, frame: &Frame, fd: RawFd) -> Result<()> {
        let bf = unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) };
        send_frame_seqpacket(bf, frame, Some(fd))
    }
}

impl TransportRecv for SeqpacketRecv {
    fn recv_frame(&mut self) -> Result<Option<ReceivedFrame>> {
        let bf = unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) };
        match recv_frame_seqpacket(bf) {
            Ok(None) => Ok(None),
            Ok(Some((frame, fd))) => Ok(Some(ReceivedFrame { frame, fd })),
            Err(e) => Err(e),
        }
    }
}

/// Split a connected SEQPACKET `OwnedFd` into send / recv halves.
///
/// The fd is `dup(2)`'d so the reader thread and the write-lock path operate
/// on independent file descriptors (no I/O state sharing, no blocking each
/// other).
fn split(fd: OwnedFd) -> Result<(SeqpacketSend, SeqpacketRecv)> {
    let dup_raw = unsafe { libc::dup(fd.as_raw_fd()) };
    if dup_raw < 0 {
        return Err(Error::other(format!(
            "dup SEQPACKET fd: {}",
            std::io::Error::last_os_error()
        )));
    }
    let recv_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
    Ok((SeqpacketSend(fd), SeqpacketRecv(recv_fd)))
}

// ---------------------------------------------------------------------------
// Constructors on InitClient<SeqpacketSend>
// ---------------------------------------------------------------------------

impl crate::init_client::InitClient<SeqpacketSend> {
    /// Wrap an already-connected SEQPACKET socket (bwrap mode: init is PID 2).
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        Self::from_fd_inner(fd, false)
    }

    /// Like [`from_fd`] but asserts that init is PID 1 (VM modes).
    #[allow(dead_code)]
    pub fn from_fd_expect_pid1(fd: OwnedFd) -> Result<Self> {
        Self::from_fd_inner(fd, true)
    }

    fn from_fd_inner(fd: OwnedFd, expect_pid1: bool) -> Result<Self> {
        let (send, recv) = split(fd)?;
        crate::init_client::InitClient::new(send, recv, expect_pid1)
    }
}
