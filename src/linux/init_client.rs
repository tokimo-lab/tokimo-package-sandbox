//! Host-side client for the in-sandbox `tokimo-sandbox-init`. Synchronous
//! API that mirrors the wire protocol from `init_protocol`. A background
//! reader thread demuxes init's reply / event packets into per-call channels.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::protocol::types::{ErrorReply, Event, Frame, Op, PROTOCOL_VERSION, Reply, StdioMode, default_features};
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
    /// Reply id → ancillary OwnedFd attached to the reply (for PTY spawn
    /// SCM_RIGHTS). Pulled out atomically with the reply by
    /// [`InitClient::send_op_sync_with_fd`].
    reply_fds: HashMap<String, OwnedFd>,
    /// True when the reader thread observed EOF or a fatal error.
    eof: bool,
}

/// Synchronous client. Cheap to clone (the inner `Arc` carries the socket
/// + shared state).
pub struct InitClient {
    inner: Arc<Inner>,
    /// True if the host expects init to be PID 1 (VM modes). False for
    /// bwrap mode where bwrap is PID 1 and init is PID 2. The host knows
    /// which mode it's in, so this is set by the constructor rather than
    /// inferred via env-var hack.
    expect_pid1: bool,
}

struct Inner {
    sock: OwnedFd,
    /// Mutex around send so concurrent op submissions don't interleave on
    /// the SEQPACKET (kernel atomicity is per-packet, but our build
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
    /// Bwrap mode: init runs as PID 2 (bwrap is PID 1).
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        Self::from_fd_inner(fd, false)
    }

    /// Same as [`from_fd`] but for VM-mode transports where init is
    /// guaranteed to be PID 1; rejects the Hello reply otherwise.
    #[allow(dead_code)]
    pub fn from_fd_expect_pid1(fd: OwnedFd) -> Result<Self> {
        Self::from_fd_inner(fd, true)
    }

    fn from_fd_inner(fd: OwnedFd, expect_pid1: bool) -> Result<Self> {
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
            expect_pid1,
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
                if init_pid != 1 && self.expect_pid1 {
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

    /// Spawn `tokimo-sandbox-fuse` inside the guest using a pre-created
    /// socketpair fd (passed via SCM_RIGHTS). The guest fuse child
    /// inherits the fd and uses `--transport unix-fd --fd <N>`.
    pub fn mount_fuse_with_fd(&self, name: &str, fuse_fd: RawFd, target: &str, read_only: bool) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::MountFuse {
            id: id.clone(),
            name: name.into(),
            vsock_port: 0, // unused when fd is attached via SCM_RIGHTS
            target: target.into(),
            read_only,
        };
        let _guard = self
            .inner
            .send_lock
            .lock()
            .map_err(|_| Error::exec("send lock poisoned"))?;
        let bf = unsafe { BorrowedFd::borrow_raw(self.inner.sock.as_raw_fd()) };
        send_frame_seqpacket(bf, &Frame::Op(op), Some(fuse_fd))?;
        drop(_guard);
        // Wait for ack.
        let deadline = Instant::now() + Duration::from_secs(10);
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().map_err(|_| Error::exec("client state poisoned"))?;
        loop {
            if let Some(r) = g.replies.remove(&id) {
                match r {
                    Reply::Ack { ok, error, .. } => {
                        if !ok {
                            return Err(Error::exec(format!(
                                "mount_fuse_with_fd failed: {:?}",
                                error.map(|e| e.message)
                            )));
                        }
                        return Ok(());
                    }
                    other => return Err(Error::exec(format!("unexpected reply: {other:?}"))),
                }
            }
            if g.eof {
                return Err(Error::exec("init connection closed before reply"));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::exec(format!("mount_fuse_with_fd {name:?} timed out")));
            }
            let (g2, _) = cv
                .wait_timeout(g, deadline - now)
                .map_err(|_| Error::exec("client state poisoned"))?;
            g = g2;
        }
    }

    /// Ask init to `umount2(target, MNT_DETACH)` and SIGTERM + reap the
    /// `tokimo-sandbox-fuse` child for the given mount name.
    pub fn unmount_fuse(&self, name: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::UnmountFuse {
            id: id.clone(),
            name: name.into(),
        };
        self.ack_op(&id, op)
    }

    /// AddUser → returns child_id of the per-user bash shell.
    pub fn add_user(
        &self,
        user_id: &str,
        home: &str,
        cwd: Option<&str>,
        env_overlay: &[(String, String)],
        real_user: bool,
    ) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::AddUser {
            id: id.clone(),
            user_id: user_id.into(),
            home: home.into(),
            cwd: cwd.map(str::to_string),
            env_overlay: env_overlay.to_vec(),
            real_user,
        };
        self.spawn_ack(&id, op)
    }

    /// RemoveUser — best-effort SIGKILL + userdel inside the guest.
    pub fn remove_user(&self, user_id: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::RemoveUser {
            id: id.clone(),
            user_id: user_id.into(),
        };
        self.ack_op(&id, op)
    }

    /// RenameUser — `userdel <old>` + `useradd --badname <new>` inside
    /// the guest. Best-effort.
    pub fn rename_user(&self, old: &str, new: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::RenameUser {
            id: id.clone(),
            old: old.into(),
            new: new.into(),
        };
        self.ack_op(&id, op)
    }

    fn spawn_ack(&self, id: &str, op: Op) -> Result<SpawnInfo> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(10))?;
        match reply {
            Reply::Spawn {
                ok, child_id, error, ..
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

    /// Spawn a PTY-mode child. Init replies with the PTY master fd
    /// attached as `SCM_RIGHTS`; the host owns the fd thereafter.
    pub fn spawn_pty(
        &self,
        argv: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        rows: u16,
        cols: u16,
    ) -> Result<(SpawnInfo, OwnedFd)> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.to_vec(),
            env_overlay: env.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pty { rows, cols },
            inherit_from_child: None,
        };
        let (reply, fd) = self.send_op_sync_with_fd(&id, op, Duration::from_secs(10))?;
        match reply {
            Reply::Spawn {
                ok, child_id, error, ..
            } => {
                if !ok {
                    return Err(Error::exec(format!("spawn pty failed: {:?}", error.map(|e| e.message))));
                }
                let fd = fd.ok_or_else(|| Error::exec("PTY spawn reply missing master fd"))?;
                Ok((
                    SpawnInfo {
                        child_id: child_id.unwrap_or_default(),
                    },
                    fd,
                ))
            }
            other => Err(Error::exec(format!("unexpected reply: {other:?}"))),
        }
    }

    /// Resize a PTY child: ioctl(master, TIOCSWINSZ) + killpg(SIGWINCH).
    pub fn resize(&self, child_id: &str, rows: u16, cols: u16) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::Resize {
            id: id.clone(),
            child_id: child_id.into(),
            rows,
            cols,
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
        let (reply, _fd) = self.send_op_sync_with_fd(id, op, timeout)?;
        Ok(reply)
    }

    fn send_op_sync_with_fd(&self, id: &str, op: Op, timeout: Duration) -> Result<(Reply, Option<OwnedFd>)> {
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
                let fd = g.reply_fds.remove(id);
                return Ok((r, fd));
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
            let any = g
                .children
                .values()
                .any(|c| !c.stdout.is_empty() || !c.stderr.is_empty() || c.exit.is_some());
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
            Ok(Some((frame, fd))) => {
                let (lock, cv) = &*state;
                let mut g = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                match frame {
                    Frame::Reply(r) => {
                        let id = reply_id(&r);
                        if let Some(fd) = fd {
                            g.reply_fds.insert(id.clone(), fd);
                        }
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
        Reply::Hello { id, .. } | Reply::Spawn { id, .. } | Reply::Ack { id, .. } => id.clone(),
    }
}

#[allow(dead_code)]
fn _silence() {
    let _: Result<()> = Err(Error::exec(""));
    let _: ErrorReply = ErrorReply::new(crate::protocol::types::ErrorCode::Internal, "");
}
