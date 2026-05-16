//! Dispatcher: serialise wire writes, route responses by `req_id`.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use tokimo_package_sandbox::vfs_protocol::wire::blocking as wire;
use tokimo_package_sandbox::vfs_protocol::{Frame, Req, Res, WireError};

use super::dup_fd;

pub(crate) struct Dispatcher {
    // Two `File`s wrapping `dup`'d fds of the same underlying socket.
    // vsock + unix-stream both support concurrent r/w on the same fd,
    // but separate fds keep the locking rules trivial: writer holds
    // `write_file` lock, reader thread parks in `read(2)` on
    // `read_file` without contention.
    write_file: Mutex<File>,
    read_file: Mutex<Option<File>>,
    next_req_id: AtomicU64,
    pending: Mutex<HashMap<u64, mpsc::Sender<Res>>>,
    bound_mount_id: u32,
}

impl Dispatcher {
    pub(crate) fn new(fd: OwnedFd, bound_mount_id: u32) -> io::Result<Self> {
        let read_dup = dup_fd(&fd)?;
        Ok(Self {
            write_file: Mutex::new(File::from(fd)),
            read_file: Mutex::new(Some(File::from(read_dup))),
            next_req_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            bound_mount_id,
        })
    }

    /// Spawn the reader thread that demuxes frames from the host.
    pub(crate) fn spawn_reader(self: Arc<Self>) -> thread::JoinHandle<()> {
        let me = self;
        thread::spawn(move || {
            let mut read_file = match me.read_file.lock().unwrap().take() {
                Some(f) => f,
                None => {
                    eprintln!("[tokimo-fuse] reader: no read fd");
                    return;
                }
            };
            let mut read_buf = Vec::with_capacity(8192);
            loop {
                let frame = match wire::read_frame_into(&mut read_file, &mut read_buf) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        eprintln!("[tokimo-fuse] host closed connection");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[tokimo-fuse] reader error: {e}");
                        break;
                    }
                };
                match frame {
                    Frame::Response { req_id, result } => {
                        let tx = me.pending.lock().unwrap().remove(&req_id);
                        if let Some(tx) = tx {
                            let _ = tx.send(result);
                        } else {
                            eprintln!("[tokimo-fuse] orphan response req_id={req_id}");
                        }
                    }
                    Frame::Notify(_) => {}
                    other => {
                        eprintln!("[tokimo-fuse] unexpected frame: {other:?}");
                    }
                }
            }
            // On reader exit, fail any pending requests.
            let pending = std::mem::take(&mut *me.pending.lock().unwrap());
            for (_, tx) in pending {
                let _ = tx.send(Res::Error(WireError {
                    errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                    message: "host disconnected".into(),
                }));
            }
        })
    }

    /// Send a request and block waiting for the response.
    pub(crate) fn call(&self, op: Req) -> Res {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(req_id, tx);
        let frame = Frame::Request {
            req_id,
            mount_id: self.bound_mount_id,
            op,
        };
        {
            let mut guard = self.write_file.lock().unwrap();
            if let Err(e) = wire::write_frame(&mut *guard, &frame) {
                self.pending.lock().unwrap().remove(&req_id);
                return Res::Error(WireError {
                    errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                    message: format!("send: {e}"),
                });
            }
        }
        // Block on response. 30s budget to avoid deadlock if reader died.
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(r) => r,
            Err(_) => {
                self.pending.lock().unwrap().remove(&req_id);
                Res::Error(WireError {
                    errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                    message: "timeout".into(),
                })
            }
        }
    }
}
