//! Host-side client for the in-sandbox `tokimo-sandbox-init`. Synchronous
//! API that mirrors the wire protocol from `init_protocol`. A background
//! reader thread demuxes init's reply / event packets into per-call channels.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::protocol::types::{ErrorReply, Event, Frame, Op, PROTOCOL_VERSION, Reply, default_features};
use crate::protocol::wire::{recv_frame_seqpacket, send_frame_seqpacket};
use crate::{Error, Result};

/// Outbound op id sequence.
fn next_id(counter: &AtomicU64) -> String {
    format!("h{}", counter.fetch_add(1, Ordering::Relaxed))
}

/// Per-child fan-out channel for stdout / stderr / exit events. Held inside
/// the shared state so the reader thread can deliver into it.
#[derive(Default)]
pub struct ChildEvents {
    pub stdout: Vec<Vec<u8>>,
    pub stderr: Vec<Vec<u8>>,
    pub exit: Option<(i32, Option<i32>)>,
}

#[derive(Default)]
struct Shared {
    /// child_id → buffered events (reader appends, consumer drains).
    children: HashMap<String, ChildEvents>,
    /// Reply id → Reply. Reader inserts on arrival.
    replies: HashMap<String, Reply>,
    /// True when the reader thread observed EOF or a fatal error.
    eof: bool,
}

/// Synchronous client. Cheap to clone (the inner `Arc` carries the socket
/// + shared state).
pub struct InitClient {
    inner: Arc<Inner>,
}

struct Inner {
    sock: OwnedFd,
    /// Mutex around send so concurrent op submissions don't interleave on
    /// the SEQPACKET (kernel handles atomicity per packet, but our build
    /// of the JSON payload would otherwise be racy).
    send_lock: Mutex<()>,
    state: Arc<(Mutex<Shared>, Condvar)>,
    counter: AtomicU64,
    /// JoinHandle for the reader thread; held to keep it alive.
    _reader: Mutex<Option<JoinHandle<()>>>,
}

impl InitClient {
    /// Wrap an already-connected SEQPACKET socket (e.g. one half of a
    /// `socketpair(2)` whose other end was inherited by the bwrap+init
    /// child via `Command::pre_exec`). Spawns the reader thread.
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        let state = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let reader_state = state.clone();
        let reader_fd_raw = fd.as_raw_fd();
        let reader = thread::Builder::new()
            .name("tokimo-init-client-reader".into())
            .spawn(move || reader_loop(reader_fd_raw, reader_state))
            .map_err(|e| Error::exec(format!("spawn reader thread: {e}")))?;

        Ok(Self {
            inner: Arc::new(Inner {
                sock: fd,
                send_lock: Mutex::new(()),
                state,
                counter: AtomicU64::new(0),
                _reader: Mutex::new(Some(reader)),
            }),
        })
    }

    /// Send Hello and verify init replies with `init_pid == 1` + matching
    /// protocol version.
    pub fn hello(&self) -> Result<i32> {
        let id = next_id(&self.inner.counter);
        let op = Op::Hello {
            id: id.clone(),
            protocol: PROTOCOL_VERSION,
            features: default_features(),
        };
        let reply = self.send_op_sync(&id, op, Duration::from_secs(5))?;
        match reply {
            Reply::Hello {
                ok,
                init_pid,
                error,
                protocol,
                ..
            } => {
                if !ok {
                    return Err(Error::exec(format!(
                        "init handshake rejected: {:?}",
                        error.map(|e| e.message)
                    )));
                }
                if protocol != PROTOCOL_VERSION {
                    return Err(Error::exec(format!(
                        "init protocol mismatch: client={PROTOCOL_VERSION} init={protocol}"
                    )));
                }
                // bwrap-mode init runs as PID 2 (bwrap is PID 1). The
                // strict PID-1 check is meaningful only for the VM
                // backends where init is the literal first userspace
                // process.
                let allow_non_pid1 = std::env::var_os("TOKIMO_SANDBOX_ALLOW_NON_PID1").is_some();
                if init_pid != 1 && !allow_non_pid1 {
                    return Err(Error::exec(format!(
                        "init not PID 1 (got {init_pid}); host forgot --as-pid-1"
                    )));
                }
                Ok(init_pid)
            }
            other => Err(Error::exec(format!("expected Hello reply, got {other:?}"))),
        }
    }

    /// OpenShell → returns child_id of the long-lived shell.
    pub fn open_shell(&self, argv: &[&str], env_overlay: &[(String, String)], cwd: Option<&str>) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::OpenShell {
            id: id.clone(),
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            env_overlay: env_overlay.to_vec(),
            cwd: cwd.map(str::to_string),
        };
        self.spawn_ack(&id, op)
    }

    /// Add a runtime bind mount in the bwrap container. Init opens
    /// `host_path` (absolute) relative to its long-lived staging fd and
    /// bind-mounts it at `target`. No SCM_RIGHTS needed — init resolves
    /// the path entirely on its own side.
    pub fn add_mount_fd(
        &self,
        name: &str,
        host_path: &str,
        target: &str,
        read_only: bool,
    ) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::AddMountFd {
            id: id.clone(),
            name: name.into(),
            host_path: host_path.into(),
            target: target.into(),
            read_only,
        };
        self.ack_op(&id, op)
    }

    /// Counterpart to [`add_mount_fd`]: ask init to umount + rmdir a
    /// previously-added dynamic mount, looked up by `name`.
    pub fn remove_mount_by_name(&self, name: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::RemoveMountByName {
            id: id.clone(),
            name: name.into(),
        };
        self.ack_op(&id, op)
    }

    fn spawn_ack(&self, id: &str, op: Op) -> Result<SpawnInfo> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(10))?;
        match reply {
            Reply::Spawn {
                ok,
                child_id,
                error,
                ..
            } => {
                if !ok {
                    return Err(Error::exec(format!("spawn failed: {:?}", error.map(|e| e.message))));
                }
                Ok(SpawnInfo {
                    child_id: child_id.unwrap_or_default(),
                })
            }
            other => Err(Error::exec(format!("unexpected reply: {other:?}"))),
        }
    }

    pub fn write(&self, child_id: &str, data: &[u8]) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::Write {
            id: id.clone(),
            child_id: child_id.into(),
            data_b64: B64.encode(data),
        };
        self.ack_op(&id, op)
    }

    pub fn signal(&self, child_id: &str, sig: i32, to_pgrp: bool) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::Signal {
            id: id.clone(),
            child_id: child_id.into(),
            sig,
            to_pgrp,
        };
        self.ack_op(&id, op)
    }

    pub fn shutdown(&self) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::Shutdown {
            id: id.clone(),
            kill_all: true,
        };
        self.ack_op(&id, op)
    }

    fn ack_op(&self, id: &str, op: Op) -> Result<()> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(5))?;
        match reply {
            Reply::Ack { ok, error, .. } => {
                if ok {
                    Ok(())
                } else {
                    Err(Error::exec(format!("init op failed: {:?}", error.map(|e| e.message))))
                }
            }
            other => Err(Error::exec(format!("expected Ack, got {other:?}"))),
        }
    }

    fn send_op_sync(&self, id: &str, op: Op, timeout: Duration) -> Result<Reply> {
        // Send the op while holding send_lock (kernel atomicity for SEQPACKET
        // is per-packet, but we still need to serialize JSON build + sendmsg).
        {
            let _guard = self
                .inner
                .send_lock
                .lock()
                .map_err(|_| Error::exec("send lock poisoned"))?;
            let bf = unsafe { BorrowedFd::borrow_raw(self.inner.sock.as_raw_fd()) };
            send_frame_seqpacket(bf, &Frame::Op(op), None)?;
        }
        // Wait for matching reply.
        let deadline = Instant::now() + timeout;
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().map_err(|_| Error::exec("client state poisoned"))?;
        loop {
            if let Some(r) = g.replies.remove(id) {
                return Ok(r);
            }
            if g.eof {
                return Err(Error::exec("init connection closed before reply"));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::exec(format!("init op {id} timed out after {timeout:?}")));
            }
            let (g2, _) = cv
                .wait_timeout(g, deadline - now)
                .map_err(|_| Error::exec("client state poisoned"))?;
            g = g2;
        }
    }

    /// Block until any child has data (stdout/stderr/exit), or the reader
    /// observed EOF, or `deadline` is reached. Returns `true` if there is
    /// pending data or EOF; `false` on timeout.
    pub fn wait_any_event_or_eof(&self, deadline: Instant) -> bool {
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().expect("client state");
        loop {
            if g.eof {
                return true;
            }
            let any = g.children.values().any(|c| {
                !c.stdout.is_empty() || !c.stderr.is_empty() || c.exit.is_some()
            });
            if any {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (g2, _) = cv.wait_timeout(g, deadline - now).expect("wait");
            g = g2;
        }
    }

    /// Drain pending events ONLY for the given set of `child_id`s. Used
    /// by the event pump so it doesn't steal events from synchronous
    /// `run_oneshot` callers (which look up child events directly).
    pub fn drain_pending_events_for(&self, ids: &std::collections::HashSet<String>) -> Vec<DrainedEvent> {
        let mut out = Vec::new();
        let mut g = self.inner.state.0.lock().expect("client state");
        for cid in ids {
            let Some(c) = g.children.get_mut(cid) else { continue };
            for chunk in std::mem::take(&mut c.stdout) {
                out.push(DrainedEvent::Stdout {
                    child_id: cid.clone(),
                    data: chunk,
                });
            }
            for chunk in std::mem::take(&mut c.stderr) {
                out.push(DrainedEvent::Stderr {
                    child_id: cid.clone(),
                    data: chunk,
                });
            }
            if let Some((code, sig)) = c.exit.take() {
                out.push(DrainedEvent::Exit {
                    child_id: cid.clone(),
                    code,
                    signal: sig,
                });
            }
        }
        out
    }

    pub fn take_exit(&self, child_id: &str) -> Option<(i32, Option<i32>)> {
        let mut g = self.inner.state.0.lock().expect("client state");
        g.children.get_mut(child_id).and_then(|c| c.exit.take())
    }

    /// Has the reader thread observed EOF / fatal error?
    pub fn is_dead(&self) -> bool {
        self.inner.state.0.lock().map(|g| g.eof).unwrap_or(true)
    }
}

/// Result of a successful Spawn / OpenShell.
#[derive(Debug, Clone)]
pub struct SpawnInfo {
    pub child_id: String,
}

/// Event handed to the event pump by [`InitClient::drain_pending_events_for`].
#[derive(Debug, Clone)]
pub enum DrainedEvent {
    Stdout {
        child_id: String,
        data: Vec<u8>,
    },
    Stderr {
        child_id: String,
        data: Vec<u8>,
    },
    Exit {
        child_id: String,
        code: i32,
        signal: Option<i32>,
    },
}

fn reader_loop(sock_fd: i32, state: Arc<(Mutex<Shared>, Condvar)>) {
    let bf = unsafe { BorrowedFd::borrow_raw(sock_fd) };
    loop {
        match recv_frame_seqpacket(bf) {
            Ok(None) => break,
            Ok(Some((frame, _fd))) => {
                let (lock, cv) = &*state;
                let mut g = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                match frame {
                    Frame::Reply(r) => {
                        let id = reply_id(&r);
                        g.replies.insert(id, r);
                    }
                    Frame::Event(e) => match e {
                        Event::Stdout { child_id, data_b64 } => {
                            if let Ok(bytes) = B64.decode(&data_b64) {
                                g.children.entry(child_id).or_default().stdout.push(bytes);
                            }
                        }
                        Event::Stderr { child_id, data_b64 } => {
                            if let Ok(bytes) = B64.decode(&data_b64) {
                                g.children.entry(child_id).or_default().stderr.push(bytes);
                            }
                        }
                        Event::Exit { child_id, code, signal } => {
                            g.children.entry(child_id).or_default().exit = Some((code, signal));
                        }
                    },
                    Frame::Op(_) => { /* unexpected on host side */ }
                }
                cv.notify_all();
            }
            Err(_) => break,
        }
    }
    let (lock, cv) = &*state;
    if let Ok(mut g) = lock.lock() {
        g.eof = true;
        cv.notify_all();
    }
}

fn reply_id(r: &Reply) -> String {
    match r {
        Reply::Hello { id, .. } | Reply::Spawn { id, .. } | Reply::Ack { id, .. } | Reply::MountManifest { id, .. } => {
            id.clone()
        }
    }
}

#[allow(dead_code)]
fn _silence() {
    let _: Result<()> = Err(Error::exec(""));
    let _: ErrorReply = ErrorReply::new(crate::protocol::types::ErrorCode::Internal, "");
}
