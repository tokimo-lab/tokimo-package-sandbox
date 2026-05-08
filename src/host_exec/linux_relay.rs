//! Linux: receive guest-side host-exec client fds from init via the
//! SEQPACKET relay socket pair, and dispatch each one to a worker
//! thread that calls [`HostExecBridge::handle_one`].

#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

use super::HostExecBridge;

pub(super) fn start(bridge: Arc<HostExecBridge>, relay_fd: OwnedFd) {
    let shutdown = bridge.shutdown_flag();
    std::thread::Builder::new()
        .name("host-exec-relay".into())
        .spawn(move || run(bridge, relay_fd, shutdown))
        .expect("spawn host-exec-relay");
}

fn run(bridge: Arc<HostExecBridge>, relay_fd: OwnedFd, shutdown: Arc<std::sync::atomic::AtomicBool>) {
    let raw = relay_fd.as_raw_fd();
    let mut buf = [0u8; 8];
    let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let res = recvmsg::<()>(raw, &mut iov, Some(&mut cmsg), MsgFlags::empty());
        let msg = match res {
            Ok(m) => m,
            Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                tracing::warn!("host-exec/relay recvmsg: {e}");
                break;
            }
        };
        if msg.bytes == 0 && msg.cmsgs().map(|mut c| c.next().is_none()).unwrap_or(true) {
            break;
        }
        let cmsgs = match msg.cmsgs() {
            Ok(it) => it,
            Err(e) => {
                tracing::warn!("host-exec/relay cmsgs: {e}");
                continue;
            }
        };
        for cm in cmsgs {
            if let ControlMessageOwned::ScmRights(fds) = cm {
                for fd in fds {
                    // SAFETY: kernel just gave us this fd via SCM_RIGHTS.
                    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                    let bridge_for_thread = bridge.clone();
                    std::thread::Builder::new()
                        .name("host-exec-conn".into())
                        .spawn(move || {
                            // SAFETY: we own this fd.
                            let stream: std::os::unix::net::UnixStream = owned.into();
                            bridge_for_thread.handle_one(stream);
                        })
                        .expect("spawn host-exec-conn");
                }
            }
        }
    }
}
