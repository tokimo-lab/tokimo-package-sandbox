//! Wire framing shared between init and host client.
//!
//! Two transports are supported:
//!
//! - **SEQPACKET** (Linux bwrap): one `sendmsg`/`recvmsg` per frame, with
//!   optional `SCM_RIGHTS` fd passing (PTY master). Kernel-preserved message
//!   boundaries eliminate the need for a length prefix.
//! - **STREAM** (VSOCK / virtio-vsock): length-prefixed frames over any
//!   `Read`+`Write` byte stream. 4-byte big-endian length followed by JSON
//!   payload. No fd passing (VSOCK doesn't support SCM_RIGHTS).
//!
//! Both paths share the same JSON `Frame` envelope and the same max-payload
//! constant (`MAX_FRAME_BYTES` from `init_protocol`).

use std::io::{Read, Write};

use crate::protocol::types::{Frame, MAX_FRAME_BYTES};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Common: length-prefixed wire encoding
// ---------------------------------------------------------------------------

/// Serialise `frame` to wire format: 4-byte BE length + JSON.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(frame).map_err(|e| Error::exec(format!("serialize wire frame: {e}")))?;
    if json.len() > MAX_FRAME_BYTES {
        return Err(Error::exec(format!(
            "wire frame too large: {} > {} bytes",
            json.len(),
            MAX_FRAME_BYTES
        )));
    }
    let len = json.len() as u32;
    let mut framed = Vec::with_capacity(4 + json.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&json);
    Ok(framed)
}

/// Decode one frame from a byte buffer. Returns `(frame, consumed)` on
/// success, or `None` if the buffer doesn't yet contain a complete frame.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::exec(format!(
            "wire frame too large: declared {len} > max {MAX_FRAME_BYTES}"
        )));
    }
    let total = 4 + len;
    if buf.len() < total {
        return Ok(None);
    }
    let frame: Frame =
        serde_json::from_slice(&buf[4..total]).map_err(|e| Error::exec(format!("parse wire frame: {e}")))?;
    Ok(Some((frame, total)))
}

// ---------------------------------------------------------------------------
// STREAM framing (VSOCK / any Read+Write transport)
// ---------------------------------------------------------------------------

/// Write one frame to a byte-stream writer. Blocks until all bytes are sent.
pub fn send_frame_stream(w: &mut impl Write, frame: &Frame) -> Result<()> {
    let data = encode_frame(frame)?;
    w.write_all(&data)
        .map_err(|e| Error::exec(format!("write frame: {e}")))?;
    w.flush().map_err(|e| Error::exec(format!("flush frame: {e}")))?;
    Ok(())
}

/// Read one frame from a byte-stream reader. Blocks until a complete frame
/// arrives. Returns `None` on clean EOF (0 bytes read for the length prefix).
pub fn recv_frame_stream(r: &mut impl Read) -> Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::exec(format!("read frame len: {e}"))),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::exec(format!(
            "wire frame too large: declared {len} > max {MAX_FRAME_BYTES}"
        )));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)
        .map_err(|e| Error::exec(format!("read frame payload {len}B: {e}")))?;
    let frame: Frame = serde_json::from_slice(&payload).map_err(|e| Error::exec(format!("parse wire frame: {e}")))?;
    Ok(Some(frame))
}

// ---------------------------------------------------------------------------
// SEQPACKET framing (Linux bwrap — SOCK_SEQPACKET + SCM_RIGHTS)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod seqpacket {
    use std::io::IoSliceMut;
    use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

    use nix::cmsg_space;
    use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

    use crate::protocol::types::{Frame, MAX_FRAME_BYTES};
    use crate::{Error, Result};

    /// Send `frame` as one SEQPACKET packet, optionally attaching `fd` via
    /// SCM_RIGHTS. The kernel duplicates the fd into the receiver, so the
    /// caller retains ownership of the original.
    pub fn send_frame_seqpacket(sock: BorrowedFd<'_>, frame: &Frame, fd: Option<RawFd>) -> Result<()> {
        let bytes = serde_json::to_vec(frame).map_err(|e| Error::exec(format!("serialize wire frame: {e}")))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(Error::exec(format!(
                "wire frame too large: {} > {} bytes",
                bytes.len(),
                MAX_FRAME_BYTES
            )));
        }
        let iov = [std::io::IoSlice::new(&bytes)];
        let fd_slot;
        let cmsg_slot;
        let cmsgs: &[ControlMessage<'_>] = match fd {
            Some(raw) => {
                fd_slot = [raw];
                cmsg_slot = [ControlMessage::ScmRights(&fd_slot)];
                &cmsg_slot
            }
            None => &[],
        };
        sendmsg::<()>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None).or_else(|e| {
            if matches!(e, nix::errno::Errno::EAGAIN) {
                wait_writable_blocking(sock.as_raw_fd())?;
                sendmsg::<()>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None)
                    .map_err(|e2| Error::exec(format!("sendmsg (retry): {e2}")))
            } else {
                Err(Error::exec(format!("sendmsg: {e}")))
            }
        })?;
        Ok(())
    }

    fn wait_writable_blocking(fd: RawFd) -> Result<()> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        let bf = unsafe { BorrowedFd::borrow_raw(fd) };
        loop {
            let mut fds = [PollFd::new(bf, PollFlags::POLLOUT)];
            match poll(&mut fds, PollTimeout::NONE) {
                Ok(_) => {
                    let revents = fds[0].revents().unwrap_or(PollFlags::empty());
                    if revents.intersects(PollFlags::POLLOUT) {
                        return Ok(());
                    }
                    if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
                        return Err(Error::exec("socket POLLERR/POLLHUP while waiting writable"));
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(Error::exec(format!("poll(POLLOUT): {e}"))),
            }
        }
    }

    /// Receive one SEQPACKET packet. Returns the parsed `Frame` and any
    /// attached fd (PTY master, exclusively) as an `OwnedFd`.
    /// On EOF (peer closed) returns `Ok(None)`.
    pub fn recv_frame_seqpacket(sock: BorrowedFd<'_>) -> Result<Option<(Frame, Option<OwnedFd>)>> {
        let mut buf = vec![0u8; MAX_FRAME_BYTES + 4096];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg = cmsg_space!([RawFd; 1]);
        let res = recvmsg::<()>(sock.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::empty())
            .map_err(|e| Error::exec(format!("recvmsg: {e}")))?;
        let n = res.bytes;
        if n == 0 {
            return Ok(None);
        }
        if res.flags.contains(MsgFlags::MSG_TRUNC) {
            return Err(Error::exec(format!(
                "wire frame truncated: {n} bytes (cap {})",
                MAX_FRAME_BYTES
            )));
        }
        let mut owned: Option<OwnedFd> = None;
        for cm in res.cmsgs().map_err(|e| Error::exec(format!("cmsgs iter: {e}")))? {
            if let ControlMessageOwned::ScmRights(fds) = cm {
                for fd in fds {
                    let new = unsafe { OwnedFd::from_raw_fd_checked(fd) }?;
                    if owned.is_some() {
                        return Err(Error::exec("wire frame carried >1 fd"));
                    }
                    owned = Some(new);
                }
            }
        }
        let _ = res;
        let payload = &buf[..n];
        let frame: Frame =
            serde_json::from_slice(payload).map_err(|e| Error::exec(format!("parse wire frame: {e}")))?;
        Ok(Some((frame, owned)))
    }

    trait FromRawFdChecked: Sized {
        unsafe fn from_raw_fd_checked(fd: RawFd) -> Result<Self>;
    }

    impl FromRawFdChecked for OwnedFd {
        unsafe fn from_raw_fd_checked(fd: RawFd) -> Result<Self> {
            use std::os::fd::FromRawFd;
            if fd < 0 {
                return Err(Error::exec(format!("invalid fd {fd} from SCM_RIGHTS")));
            }
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
}

#[cfg(target_os = "linux")]
pub use seqpacket::{recv_frame_seqpacket, send_frame_seqpacket};
