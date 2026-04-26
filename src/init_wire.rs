//! SOCK_SEQPACKET framing helpers shared between init and the host client.
//!
//! Each wire packet is a single `sendmsg`/`recvmsg` call carrying:
//!   - the JSON-encoded `Frame` payload (UTF-8 bytes), and
//!   - optionally one ancillary `SCM_RIGHTS` fd (PTY master).
//!
//! SEQPACKET preserves message boundaries, so a partial recv is impossible:
//! either the whole packet is delivered or `EAGAIN`/`MSG_TRUNC` is returned.
//! We size the receive buffer to `MAX_FRAME_BYTES` (`init_protocol`) +
//! ancillary slack so MSG_TRUNC can never silently drop trailing bytes.

#![cfg(target_os = "linux")]

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use nix::cmsg_space;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg,
};

use crate::init_protocol::{Frame, MAX_FRAME_BYTES};
use crate::{Error, Result};

/// Send `frame` as one SEQPACKET packet, optionally attaching `fd` via
/// SCM_RIGHTS. The kernel duplicates the fd into the receiver, so the
/// caller retains ownership of the original.
pub fn send_frame(sock: BorrowedFd<'_>, frame: &Frame, fd: Option<RawFd>) -> Result<()> {
    let bytes = serde_json::to_vec(frame)
        .map_err(|e| Error::exec(format!("serialize wire frame: {e}")))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::exec(format!(
            "wire frame too large: {} > {} bytes",
            bytes.len(),
            MAX_FRAME_BYTES
        )));
    }
    let iov = [IoSlice::new(&bytes)];
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
    sendmsg::<()>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None)
        .or_else(|e| {
            if matches!(e, nix::errno::Errno::EAGAIN) {
                // Socket was set non-blocking (e.g. by mio on the server side).
                // Wait for it to become writable, then retry. This is the
                // backpressure path under heavy child output bursts.
                wait_writable_blocking(sock.as_raw_fd())?;
                sendmsg::<()>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None)
                    .map_err(|e2| Error::exec(format!("sendmsg (retry): {e2}")))
            } else {
                Err(Error::exec(format!("sendmsg: {e}")))
            }
        })?;
    Ok(())
}

/// Block until the given fd is writable. Used as backpressure when the
/// non-blocking SEQPACKET socket's send buffer is full.
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
///
/// On EOF (peer closed) returns `Ok(None)`.
pub fn recv_frame(sock: BorrowedFd<'_>) -> Result<Option<(Frame, Option<OwnedFd>)>> {
    // Generous receive buffer: protocol cap + small overhead margin.
    let mut buf = vec![0u8; MAX_FRAME_BYTES + 4096];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = cmsg_space!([RawFd; 1]);
    let res = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )
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
    // Pull cmsgs out before borrowing buf again.
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
    let frame: Frame = serde_json::from_slice(payload)
        .map_err(|e| Error::exec(format!("parse wire frame: {e}")))?;
    Ok(Some((frame, owned)))
}

trait FromRawFdChecked: Sized {
    /// Convert a raw fd to OwnedFd. Returns Err for negative fds.
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
