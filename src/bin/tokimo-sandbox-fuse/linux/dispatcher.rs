//! Dispatcher: serialise wire writes, route responses by `req_id`.
//!
//! Concurrency model:
//!   * `call_async(op, cb)` registers a per-request callback and
//!     returns immediately. The reader thread demuxes responses and
//!     hands each `(cb, res)` to a worker thread pool which invokes
//!     the callback. This lets FUSE handlers complete without
//!     blocking the `fuser::Session::run` read loop, allowing many
//!     in-flight FUSE ops to overlap. Without this we cap at exactly
//!     one in-flight op (one socket RTT per op) — a hard wall around
//!     500-2000 ops/s depending on transport.
//!   * `call(op)` is the legacy synchronous wrapper used by setup
//!     code (init, etc.) that runs before any kernel ops; built on
//!     top of `call_async`.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver as CbRecv, Sender as CbSend, unbounded};
use tokimo_package_sandbox::vfs_protocol::wire::blocking as wire;
use tokimo_package_sandbox::vfs_protocol::{Frame, Inval, Req, Res, WireError};

use super::dup_fd;

/// Worker pool that runs FUSE response callbacks off the reader thread.
/// Sized once at dispatcher init (defaults to 16). 16 workers ≈ 16
/// concurrent in-flight FUSE ops; the host `FuseHost` already runs
/// each op in its own tokio task, so the only serialisation left is
/// the single host-side socket writer (a `tokio::sync::Mutex<TX>`).
struct WorkerPool {
    tx: CbSend<Box<dyn FnOnce() + Send + 'static>>,
    _handles: Vec<thread::JoinHandle<()>>,
}

impl WorkerPool {
    fn new(n: usize) -> Self {
        let (tx, rx) = unbounded::<Box<dyn FnOnce() + Send + 'static>>();
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let rx: CbRecv<Box<dyn FnOnce() + Send + 'static>> = rx.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("tokimo-fuse-w{i}"))
                    .spawn(move || {
                        while let Ok(job) = rx.recv() {
                            job();
                        }
                    })
                    .expect("spawn worker"),
            );
        }
        Self { tx, _handles: handles }
    }

    fn submit<F: FnOnce() + Send + 'static>(&self, f: F) {
        // Channel is unbounded; only fails if all receivers dropped,
        // which only happens during shutdown.
        let _ = self.tx.send(Box::new(f));
    }
}

type ResCb = Box<dyn FnOnce(Res) + Send + 'static>;

pub(crate) struct Dispatcher {
    // Two `File`s wrapping `dup`'d fds of the same underlying socket.
    // vsock + unix-stream both support concurrent r/w on the same fd,
    // but separate fds keep the locking rules trivial: writer holds
    // `write_file` lock, reader thread parks in `read(2)` on
    // `read_file` without contention.
    write_file: Mutex<File>,
    read_file: Mutex<Option<File>>,
    next_req_id: AtomicU64,
    pending: Mutex<HashMap<u64, ResCb>>,
    bound_mount_id: u32,
    notifier: Mutex<Option<fuser::Notifier>>,
    inval_tx: Mutex<Option<mpsc::Sender<Inval>>>,
    /// Pool that runs response callbacks (i.e. the `reply.xxx(...)`
    /// side of each FUSE op). Sized to 16 workers; tune via
    /// `TOKIMO_FUSE_WORKERS` env if needed.
    pool: WorkerPool,
}

impl Dispatcher {
    pub(crate) fn new(fd: OwnedFd, bound_mount_id: u32) -> io::Result<Self> {
        let read_dup = dup_fd(&fd)?;
        let workers = std::env::var("TOKIMO_FUSE_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(16);
        Ok(Self {
            write_file: Mutex::new(File::from(fd)),
            read_file: Mutex::new(Some(File::from(read_dup))),
            next_req_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            bound_mount_id,
            notifier: Mutex::new(None),
            inval_tx: Mutex::new(None),
            pool: WorkerPool::new(workers),
        })
    }

    /// Attach the FUSE kernel notifier obtained from
    /// [`fuser::Session::notifier`] *after* the session has been
    /// constructed, and spawn the dedicated invalidator thread that
    /// drains incoming `Inval` items off the wire and forwards them to
    /// the kernel. Returns the thread join handle so the caller can
    /// keep it alive for the lifetime of the bridge.
    pub(crate) fn install_notifier(self: &Arc<Self>, n: fuser::Notifier) -> thread::JoinHandle<()> {
        *self.notifier.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        }) = Some(n.clone());
        let (tx, rx) = mpsc::channel::<Inval>();
        *self.inval_tx.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        }) = Some(tx);
        thread::Builder::new()
            .name("tokimo-fuse-inval".into())
            .spawn(move || {
                while let Ok(inval) = rx.recv() {
                    match inval {
                        Inval::Inode { nodeid, off, len } => {
                            let _ = n.inval_inode(nodeid, off, len);
                        }
                        Inval::Entry { parent_nodeid, name } => {
                            let _ = n.inval_entry(parent_nodeid, std::ffi::OsStr::new(&name));
                        }
                    }
                }
            })
            .expect("spawn tokimo-fuse-inval")
    }

    /// Spawn the reader thread that demuxes frames from the host.
    pub(crate) fn spawn_reader(self: Arc<Self>) -> thread::JoinHandle<()> {
        let me = self;
        thread::spawn(move || {
            let mut read_file = match me
                .read_file
                .lock()
                .unwrap_or_else(|e| {
                    tracing::warn!("mutex poisoned, recovering: {e}");
                    e.into_inner()
                })
                .take()
            {
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
                        let cb = me
                            .pending
                            .lock()
                            .unwrap_or_else(|e| {
                                tracing::warn!("mutex poisoned, recovering: {e}");
                                e.into_inner()
                            })
                            .remove(&req_id);
                        if let Some(cb) = cb {
                            me.pool.submit(move || cb(result));
                        } else {
                            eprintln!("[tokimo-fuse] orphan response req_id={req_id}");
                        }
                    }
                    Frame::Notify(inval) => {
                        let tx = me
                            .inval_tx
                            .lock()
                            .unwrap_or_else(|e| {
                                tracing::warn!("mutex poisoned, recovering: {e}");
                                e.into_inner()
                            })
                            .clone();
                        if let Some(tx) = tx {
                            let _ = tx.send(inval);
                        }
                    }
                    other => {
                        eprintln!("[tokimo-fuse] unexpected frame: {other:?}");
                    }
                }
            }
            // On reader exit, fail any pending requests.
            let pending = std::mem::take(&mut *me.pending.lock().unwrap_or_else(|e| {
                tracing::warn!("mutex poisoned, recovering: {e}");
                e.into_inner()
            }));
            for (_, cb) in pending {
                let err = Res::Error(WireError {
                    errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                    message: "host disconnected".into(),
                });
                me.pool.submit(move || cb(err));
            }
        })
    }

    /// Asynchronous send: register a callback to be invoked on a worker
    /// thread when the host's response arrives. Returns immediately so
    /// the caller (a FUSE handler running on `fuser::Session::run`'s
    /// read loop) can return and let the loop fetch the next request.
    pub(crate) fn call_async<F>(&self, op: Req, cb: F)
    where
        F: FnOnce(Res) + Send + 'static,
    {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        self.pending
            .lock()
            .unwrap_or_else(|e| {
                tracing::warn!("mutex poisoned, recovering: {e}");
                e.into_inner()
            })
            .insert(req_id, Box::new(cb));
        let frame = Frame::Request {
            req_id,
            mount_id: self.bound_mount_id,
            op,
        };
        let mut guard = self.write_file.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        if let Err(e) = wire::write_frame(&mut *guard, &frame) {
            drop(guard);
            // Remove the pending entry and invoke the callback with
            // the wire error so callers don't leak FUSE replies.
            if let Some(cb) = self
                .pending
                .lock()
                .unwrap_or_else(|e| {
                    tracing::warn!("mutex poisoned, recovering: {e}");
                    e.into_inner()
                })
                .remove(&req_id)
            {
                let err = Res::Error(WireError {
                    errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                    message: format!("send: {e}"),
                });
                self.pool.submit(move || cb(err));
            }
        }
    }

    /// Synchronous wrapper, retained for setup paths that prefer
    /// blocking semantics. Currently unused but kept around so the
    /// dispatcher stays self-contained for tests.
    #[allow(dead_code)]
    pub(crate) fn call(&self, op: Req) -> Res {
        let (tx, rx) = mpsc::channel();
        self.call_async(op, move |r| {
            let _ = tx.send(r);
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(r) => r,
            Err(_) => Res::Error(WireError {
                errno: tokimo_package_sandbox::vfs_protocol::Errno::Eio as i32,
                message: "timeout".into(),
            }),
        }
    }
}
