//! Unified host-side client for `tokimo-sandbox-init`.
//!
//! Platform-generic implementation; transport-specific wiring lives in
//! `src/{linux,macos,windows}/init_transport.rs`.  Per-platform shims in
//! the old module paths re-export the concrete type aliases so existing call
//! sites compile without change.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::protocol::types::{Event, Frame, Op, PROTOCOL_VERSION, Reply, StdioMode, default_features};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Transport traits
// ---------------------------------------------------------------------------

/// Outbound half of an init transport.
pub trait TransportSend: Send + 'static {
    fn send_frame(&mut self, frame: &Frame) -> Result<()>;

    /// Send a frame with an ancillary file descriptor (SCM_RIGHTS).
    /// Only the Linux SEQPACKET transport supports this; all others
    /// return an error from the default implementation.
    #[cfg(unix)]
    fn send_frame_with_fd(&mut self, frame: &Frame, fd: std::os::unix::io::RawFd) -> Result<()> {
        let _ = (frame, fd);
        Err(Error::exec("fd passing not supported on this transport"))
    }
}

/// Inbound half of an init transport.
pub trait TransportRecv: Send + 'static {
    fn recv_frame(&mut self) -> Result<Option<ReceivedFrame>>;
}

/// A frame received from the transport, with an optional ancillary fd
/// (populated only by the Linux SEQPACKET transport via SCM_RIGHTS).
pub struct ReceivedFrame {
    pub frame: Frame,
    #[cfg(unix)]
    pub fd: Option<std::os::fd::OwnedFd>,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Per-child fan-out channel for stdout / stderr / exit events.
#[derive(Default)]
pub struct ChildEvents {
    pub stdout: Vec<Vec<u8>>,
    pub stderr: Vec<Vec<u8>>,
    pub exit: Option<(i32, Option<i32>)>,
}

#[derive(Default)]
pub(crate) struct Shared {
    pub(crate) children: HashMap<String, ChildEvents>,
    pub(crate) replies: HashMap<String, Reply>,
    #[cfg(unix)]
    pub(crate) reply_fds: HashMap<String, std::os::fd::OwnedFd>,
    pub(crate) eof: bool,
}

// ---------------------------------------------------------------------------
// InitClient<S>
// ---------------------------------------------------------------------------

/// Synchronous init client, generic over the outbound transport `S`.
/// Cheap to clone — the `Arc<Inner<S>>` carries the shared state.
pub struct InitClient<S: TransportSend> {
    pub(crate) inner: Arc<Inner<S>>,
    /// True for VM backends where init is expected to be PID 1.
    /// False for bwrap mode where bwrap is PID 1 and init is PID 2.
    expect_pid1: bool,
}

impl<S: TransportSend> Clone for InitClient<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            expect_pid1: self.expect_pid1,
        }
    }
}

pub(crate) struct Inner<S: TransportSend> {
    send: Mutex<S>,
    pub(crate) state: Arc<(Mutex<Shared>, Condvar)>,
    counter: AtomicU64,
    _reader: Mutex<Option<JoinHandle<()>>>,
}

fn next_id(counter: &AtomicU64) -> String {
    format!("h{}", counter.fetch_add(1, Ordering::Relaxed))
}

impl<S: TransportSend> InitClient<S> {
    /// Construct a new client from separate send / recv transport halves.
    /// Spawns the background reader thread immediately.
    pub fn new<R: TransportRecv>(sender: S, receiver: R, expect_pid1: bool) -> Result<Self> {
        let state = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let reader_state = state.clone();
        let reader = thread::Builder::new()
            .name("tokimo-init-client-reader".into())
            .spawn(move || reader_loop(receiver, reader_state))
            .map_err(|e| Error::exec(format!("spawn reader thread: {e}")))?;
        Ok(Self {
            inner: Arc::new(Inner {
                send: Mutex::new(sender),
                state,
                counter: AtomicU64::new(0),
                _reader: Mutex::new(Some(reader)),
            }),
            expect_pid1,
        })
    }

    // -- Handshake ----------------------------------------------------------

    pub fn hello(&self) -> Result<i32> {
        let id = next_id(&self.inner.counter);
        let op = Op::Hello {
            id: id.clone(),
            protocol: PROTOCOL_VERSION,
            features: default_features(),
        };
        let reply = self.send_op_sync(&id, op, Duration::from_secs(15))?;
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

    // -- Shell / spawn ------------------------------------------------------

    pub fn open_shell(
        &self,
        argv: &[String],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::OpenShell {
            id: id.clone(),
            argv: argv.to_vec(),
            env_overlay: env_overlay.to_vec(),
            cwd: cwd.map(str::to_string),
        };
        self.spawn_ack(&id, op)
    }

    pub fn spawn_pipes(
        &self,
        argv: &[String],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<SpawnInfo> {
        self.spawn_pipes_inherit(argv, env_overlay, cwd, None)
    }

    pub fn spawn_pipes_inherit(
        &self,
        argv: &[String],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        inherit_from_child: Option<&str>,
    ) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.to_vec(),
            env_overlay: env_overlay.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pipes,
            inherit_from_child: inherit_from_child.map(str::to_string),
        };
        self.spawn_ack(&id, op)
    }

    /// Spawn a PTY-mode child.
    ///
    /// On Linux (SEQPACKET transport with SCM_RIGHTS): init attaches the PTY
    /// master fd to the reply; the host receives it as `Some(fd)`.
    /// On macOS / Windows (stream transports without SCM_RIGHTS): the master
    /// stays inside the guest and init streams output via events; the host
    /// receives `None`.
    #[cfg(unix)]
    pub fn spawn_pty(
        &self,
        argv: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        rows: u16,
        cols: u16,
    ) -> Result<(SpawnInfo, Option<std::os::fd::OwnedFd>)> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.to_vec(),
            env_overlay: env.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pty { rows, cols },
            inherit_from_child: None,
        };
        let (reply, fd) = self.send_op_sync_with_fd(&id, op, Duration::from_secs(15))?;
        match reply {
            Reply::Spawn {
                ok, child_id, error, ..
            } => {
                if !ok {
                    return Err(Error::exec(format!("spawn pty failed: {:?}", error.map(|e| e.message))));
                }
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

    /// Spawn a PTY-mode child (Windows / non-Unix variant).
    ///
    /// The PTY master stays inside the guest; init streams output via events.
    #[cfg(not(unix))]
    pub fn spawn_pty(
        &self,
        argv: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        rows: u16,
        cols: u16,
    ) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.to_vec(),
            env_overlay: env.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pty { rows, cols },
            inherit_from_child: None,
        };
        self.spawn_ack(&id, op)
    }

    fn spawn_ack(&self, id: &str, op: Op) -> Result<SpawnInfo> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(15))?;
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

    // -- I/O ops ------------------------------------------------------------

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

    pub fn close_child(&self, child_id: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::Close {
            id: id.clone(),
            child_id: child_id.into(),
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

    // -- FUSE mount ops -----------------------------------------------------

    /// Tell the guest to mount a FUSE share over vsock / HvSocket.
    pub fn mount_fuse(&self, name: &str, vsock_port: u32, target: &str, read_only: bool) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::MountFuse {
            id: id.clone(),
            name: name.into(),
            vsock_port,
            target: target.into(),
            read_only,
        };
        self.ack_op(&id, op)
    }

    /// Send a MountFuse op with an ancillary fd passed via SCM_RIGHTS
    /// (Linux bwrap / SEQPACKET transport only).
    #[cfg(unix)]
    pub fn mount_fuse_with_fd(
        &self,
        name: &str,
        fuse_fd: std::os::unix::io::RawFd,
        target: &str,
        read_only: bool,
    ) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::MountFuse {
            id: id.clone(),
            name: name.into(),
            vsock_port: 0,
            target: target.into(),
            read_only,
        };
        {
            let mut s = self.inner.send.lock().map_err(|_| Error::exec("send lock poisoned"))?;
            s.send_frame_with_fd(&Frame::Op(op), fuse_fd)?;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().map_err(|_| Error::exec("client state poisoned"))?;
        loop {
            if let Some(r) = g.replies.remove(&id) {
                return match r {
                    Reply::Ack { ok, error, .. } => {
                        if ok {
                            Ok(())
                        } else {
                            Err(Error::exec(format!(
                                "mount_fuse_with_fd failed: {:?}",
                                error.map(|e| e.message)
                            )))
                        }
                    }
                    other => Err(Error::exec(format!("unexpected reply: {other:?}"))),
                };
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

    pub fn unmount_fuse(&self, name: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::UnmountFuse {
            id: id.clone(),
            name: name.into(),
        };
        self.ack_op(&id, op)
    }

    // -- Event drain --------------------------------------------------------

    pub fn drain_stdout(&self, child_id: &str) -> Vec<Vec<u8>> {
        let mut g = self.inner.state.0.lock().expect("client state");
        let entry = g.children.entry(child_id.into()).or_default();
        std::mem::take(&mut entry.stdout)
    }

    pub fn drain_stderr(&self, child_id: &str) -> Vec<Vec<u8>> {
        let mut g = self.inner.state.0.lock().expect("client state");
        let entry = g.children.entry(child_id.into()).or_default();
        std::mem::take(&mut entry.stderr)
    }

    pub fn take_exit(&self, child_id: &str) -> Option<(i32, Option<i32>)> {
        let mut g = self.inner.state.0.lock().expect("client state");
        g.children.get_mut(child_id).and_then(|c| c.exit.take())
    }

    /// Block until the reader has data for `child_id` or `deadline` is
    /// reached.  Returns `true` if there is something to read, `false` on
    /// timeout.
    pub fn wait_for_event(&self, child_id: &str, deadline: Instant) -> bool {
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().expect("client state");
        loop {
            if let Some(c) = g.children.get(child_id)
                && (!c.stdout.is_empty() || !c.stderr.is_empty() || c.exit.is_some())
            {
                return true;
            }
            if g.eof {
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

    /// Block until any child has data (stdout/stderr/exit), or the reader
    /// observed EOF, or `deadline` is reached.  Returns `true` if there is
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

    /// Drain pending events only for the given set of `child_id`s.  Used
    /// by the Linux event pump so it doesn't steal events from synchronous
    /// `run_oneshot` callers.
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

    /// Snapshot of all child ids currently tracked by the reader thread.
    pub fn child_ids(&self) -> Vec<String> {
        let g = self.inner.state.0.lock().expect("client state");
        g.children.keys().cloned().collect()
    }

    /// Returns `true` if the reader thread has observed EOF / a fatal error.
    pub fn is_dead(&self) -> bool {
        self.inner.state.0.lock().map(|g| g.eof).unwrap_or(true)
    }

    /// Returns `true` if the named child has an exit status recorded.
    pub fn child_exited(&self, child_id: &str) -> bool {
        self.inner
            .state
            .0
            .lock()
            .map(|g| g.children.get(child_id).map(|c| c.exit.is_some()).unwrap_or(false))
            .unwrap_or(true)
    }

    // -- One-shot -----------------------------------------------------------

    pub fn run_oneshot(
        &self,
        argv: &[String],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let info = self.spawn_pipes(argv, env_overlay, cwd)?;
        self.collect_until_exit(&info.child_id, timeout)
    }

    pub fn run_oneshot_inherit(
        &self,
        argv: &[String],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        inherit_from_child: Option<&str>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let info = self.spawn_pipes_inherit(argv, env_overlay, cwd, inherit_from_child)?;
        self.collect_until_exit(&info.child_id, timeout)
    }

    fn collect_until_exit(&self, child_id: &str, timeout: Duration) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let deadline = Instant::now() + timeout;
        let mut stdout_buf: Vec<u8> = Vec::new();
        let mut stderr_buf: Vec<u8> = Vec::new();
        let mut exit_code: Option<i32> = None;
        let mut timed_out = false;

        loop {
            for chunk in self.drain_stdout(child_id) {
                stdout_buf.extend_from_slice(&chunk);
            }
            for chunk in self.drain_stderr(child_id) {
                stderr_buf.extend_from_slice(&chunk);
            }
            if let Some((code, _)) = self.take_exit(child_id) {
                exit_code = Some(code);
                break;
            }
            if self.is_dead() {
                exit_code = Some(-1);
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                timed_out = true;
                let _ = self.signal(child_id, 9, true); // SIGKILL
                let drain_deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < drain_deadline {
                    self.wait_for_event(child_id, drain_deadline);
                    for chunk in self.drain_stdout(child_id) {
                        stdout_buf.extend_from_slice(&chunk);
                    }
                    for chunk in self.drain_stderr(child_id) {
                        stderr_buf.extend_from_slice(&chunk);
                    }
                    if let Some((code, _)) = self.take_exit(child_id) {
                        exit_code = Some(code);
                        break;
                    }
                }
                break;
            }
            self.wait_for_event(child_id, deadline);
        }

        let _ = self.close_child(child_id);
        let code = if timed_out { 124 } else { exit_code.unwrap_or(-1) };
        Ok((stdout_buf, stderr_buf, code))
    }

    // -- Internal -----------------------------------------------------------

    fn ack_op(&self, id: &str, op: Op) -> Result<()> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(10))?;
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
        {
            let mut s = self.inner.send.lock().map_err(|_| Error::exec("send lock poisoned"))?;
            s.send_frame(&Frame::Op(op))?;
        }
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

    /// Like `send_op_sync` but also returns any ancillary fd that arrived
    /// with the reply (Linux SEQPACKET / SCM_RIGHTS only).
    #[cfg(unix)]
    fn send_op_sync_with_fd(
        &self,
        id: &str,
        op: Op,
        timeout: Duration,
    ) -> Result<(Reply, Option<std::os::fd::OwnedFd>)> {
        {
            let mut s = self.inner.send.lock().map_err(|_| Error::exec("send lock poisoned"))?;
            s.send_frame(&Frame::Op(op))?;
        }
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
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a successful Spawn / OpenShell operation.
#[derive(Debug, Clone)]
pub struct SpawnInfo {
    pub child_id: String,
}

/// Event handed to the Linux event pump by
/// [`InitClient::drain_pending_events_for`].
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

// ---------------------------------------------------------------------------
// Reader thread (generic over TransportRecv)
// ---------------------------------------------------------------------------

fn reader_loop<R: TransportRecv>(mut recv: R, state: Arc<(Mutex<Shared>, Condvar)>) {
    loop {
        match recv.recv_frame() {
            Ok(None) => break,
            Err(_) => {
                let (lock, cv) = &*state;
                if let Ok(mut g) = lock.lock() {
                    g.eof = true;
                }
                cv.notify_all();
                break;
            }
            Ok(Some(received)) => {
                let (lock, cv) = &*state;
                let mut g = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                match received.frame {
                    Frame::Reply(r) => {
                        let id = reply_id(&r);
                        #[cfg(unix)]
                        if let Some(fd) = received.fd {
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
