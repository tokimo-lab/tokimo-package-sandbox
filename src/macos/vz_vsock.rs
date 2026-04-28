//! VSOCK transport for host ↔ init communication on macOS.
//!
//! The Virtualization.framework VM exposes one or more virtio-vsock ports.
//! This module wraps the host-side VSOCK connection (a raw fd obtained from
//! [`VirtioSocketConnection::into_raw_fd`][arcbox_vz::VirtioSocketConnection])
//! and speaks the length-prefixed init wire protocol over it.
//!
//! ```text
//! macOS host                          Linux guest (VM)
//! ──────────                          ────────────────
//! VsockInitClient                     tokimo-sandbox-init
//!   ├─ reader thread                    ├─ VSOCK listener (port 1)
//!   ├─ send_frame_stream ──────────▶   ├─ handle_client_readable_vsock
//!   └─ recv_frame_stream ◀──────────   └─ send_to_client (stream)
//! ```

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::protocol::types::{Event, Frame, Op, PROTOCOL_VERSION, Reply, StdioMode, default_features};
use crate::protocol::wire::{recv_frame_stream, send_frame_stream};
use crate::{Error, Result};

/// Opaque transport wrapping a VSOCK file descriptor.
///
/// Created from the raw fd returned by
/// [`VirtioSocketConnection::into_raw_fd`][arcbox_vz::VirtioSocketConnection].
/// The fd is wrapped in a `std::fs::File` for safe blocking Read + Write.
pub struct VsockTransport {
    /// Write half (cloned fd at construction).
    write: Option<std::fs::File>,
    /// Original fd for the reader side.
    read_fd: Option<RawFd>,
}

impl VsockTransport {
    /// Create a transport from a raw VSOCK fd. The fd must be a valid,
    /// connected virtio-vsock file descriptor.
    ///
    /// The fd is duplicated so we can have independent read and write
    /// positions (one for the reader thread, one for the send path).
    pub fn from_raw_fd(fd: RawFd) -> Result<Self> {
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(Error::exec(format!(
                "dup VSOCK fd: {}",
                std::io::Error::last_os_error()
            )));
        }
        let write = unsafe { std::fs::File::from_raw_fd(dup) };
        Ok(Self {
            write: Some(write),
            read_fd: Some(fd),
        })
    }

    /// Create a transport from separate read and write fds (serial console).
    pub fn from_raw_fd_pair(read_fd: RawFd, write_fd: RawFd) -> Result<Self> {
        Ok(Self {
            read_fd: Some(read_fd),
            write: Some(unsafe { std::fs::File::from_raw_fd(write_fd) }),
        })
    }

    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self> {
        Self::from_raw_fd(fd.into_raw_fd())
    }

    /// Take the read half as a `std::fs::File` for use in a reader thread.
    /// After calling this, `write` (the dup'd fd) remains for sending.
    pub fn take_read(&mut self) -> std::fs::File {
        let fd = self.read_fd.take().expect("take_read called twice");
        unsafe { std::fs::File::from_raw_fd(fd) }
    }
}

impl Drop for VsockTransport {
    fn drop(&mut self) {
        if let Some(fd) = self.read_fd.take() {
            unsafe { libc::close(fd) };
        }
        // write's Drop closes its fd.
    }
}

// ---------------------------------------------------------------------------
// Shared state and event channels (mirrors InitClient architecture)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Shared {
    /// child_id → buffered events (reader appends, consumer drains).
    children: HashMap<String, ChildEvents>,
    /// Reply id → Reply. Reader inserts on arrival.
    replies: HashMap<String, Reply>,
    /// True when the reader thread observed EOF or a fatal error.
    eof: bool,
}

#[derive(Default)]
struct ChildEvents {
    pub stdout: Vec<Vec<u8>>,
    pub stderr: Vec<Vec<u8>>,
    pub exit: Option<(i32, Option<i32>)>,
}

// ---------------------------------------------------------------------------
// VsockInitClient
// ---------------------------------------------------------------------------

/// Synchronous client for the in-VM `tokimo-sandbox-init` over VSOCK.
/// Cheap to clone (the inner `Arc` carries the transport + shared state).
pub struct VsockInitClient {
    inner: Arc<Inner>,
}

struct Inner {
    /// Writer half (cloned at construction time).
    write: Mutex<std::fs::File>,
    state: Arc<(Mutex<Shared>, Condvar)>,
    counter: AtomicU64,
    /// JoinHandle for the reader thread.
    _reader: Mutex<Option<JoinHandle<()>>>,
}

fn next_id(counter: &AtomicU64) -> String {
    format!("h{}", counter.fetch_add(1, Ordering::Relaxed))
}

impl VsockInitClient {
    /// Build a client from a VSOCK transport. Spawns the background reader
    /// thread immediately.
    pub fn new(mut transport: VsockTransport) -> Result<Self> {
        let reader_file = transport.take_read();
        let writer = transport.write.take().expect("write fd");
        // Consume transport — Drop is a no-op since we took both fds.
        std::mem::forget(transport);
        let state = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let reader_state = state.clone();

        let reader = thread::Builder::new()
            .name("tokimo-vsock-reader".into())
            .spawn(move || reader_loop(reader_file, reader_state))
            .map_err(|e| Error::exec(format!("spawn vsock reader thread: {e}")))?;

        Ok(Self {
            inner: Arc::new(Inner {
                write: Mutex::new(writer),
                state,
                counter: AtomicU64::new(0),
                _reader: Mutex::new(Some(reader)),
            }),
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
                if init_pid != 1 {
                    return Err(Error::exec(format!("init not PID 1 (got {init_pid})")));
                }
                Ok(init_pid)
            }
            other => Err(Error::exec(format!("expected Hello reply, got {other:?}"))),
        }
    }

    // -- Shell / spawn ------------------------------------------------------

    /// Open a long-lived bash shell. Returns the `child_id`.
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

    /// Spawn a pipes-mode child. Returns spawn info.
    pub fn spawn_pipes(&self, argv: &[&str], env_overlay: &[(String, String)], cwd: Option<&str>) -> Result<SpawnInfo> {
        self.spawn_pipes_inherit(argv, env_overlay, cwd, None)
    }

    /// Spawn a pipes-mode child with optional env/cwd inheritance from an
    /// existing child.
    pub fn spawn_pipes_inherit(
        &self,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        inherit_from_child: Option<&str>,
    ) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            env_overlay: env_overlay.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pipes,
            inherit_from_child: inherit_from_child.map(str::to_string),
        };
        self.spawn_ack(&id, op)
    }

    /// Spawn a child in Pty mode. Returns spawn info. On stream transports
    /// (VSOCK), the master fd is NOT returned via SCM_RIGHTS — I/O is bridged
    /// through the protocol.
    pub fn spawn_pty(
        &self,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        rows: u16,
        cols: u16,
    ) -> Result<(SpawnInfo, Option<OwnedFd>)> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            env_overlay: env_overlay.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pty { rows, cols },
            inherit_from_child: None,
        };
        let reply = self.send_op_sync(&id, op, Duration::from_secs(10))?;
        match reply {
            Reply::Spawn {
                ok,
                child_id,
                pid,
                error,
                ..
            } => {
                if !ok {
                    return Err(Error::exec(format!("spawn pty failed: {:?}", error.map(|e| e.message))));
                }
                Ok((
                    SpawnInfo {
                        child_id: child_id.unwrap_or_default(),
                        pid: pid.unwrap_or(0),
                    },
                    None, // No fd on stream transport
                ))
            }
            other => Err(Error::exec(format!("unexpected reply: {other:?}"))),
        }
    }

    fn spawn_ack(&self, id: &str, op: Op) -> Result<SpawnInfo> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(10))?;
        match reply {
            Reply::Spawn {
                ok,
                child_id,
                pid,
                error,
                ..
            } => {
                if !ok {
                    return Err(Error::exec(format!("spawn failed: {:?}", error.map(|e| e.message))));
                }
                Ok(SpawnInfo {
                    child_id: child_id.unwrap_or_default(),
                    pid: pid.unwrap_or(0),
                })
            }
            other => Err(Error::exec(format!("unexpected reply: {other:?}"))),
        }
    }

    // -- Add / Remove user (Workspace) --------------------------------------

    pub fn add_user(&self, user_id: &str, env_overlay: &[(String, String)], cwd: Option<&str>) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::AddUser {
            id: id.clone(),
            user_id: user_id.into(),
            cwd: cwd.map(str::to_string),
            env_overlay: env_overlay.to_vec(),
        };
        self.spawn_ack(&id, op)
    }

    pub fn remove_user(&self, user_id: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::RemoveUser {
            id: id.clone(),
            user_id: user_id.into(),
        };
        self.ack_op(&id, op)
    }

    // -- Dynamic mounts (Workspace) -----------------------------------------

    pub fn bind_mount(&self, source: &str, target: &str, read_only: bool) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::BindMount {
            id: id.clone(),
            source: source.into(),
            target: target.into(),
            read_only,
        };
        self.ack_op(&id, op)
    }

    pub fn unmount(&self, target: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::Unmount {
            id: id.clone(),
            target: target.into(),
        };
        self.ack_op(&id, op)
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

    // -- Event draining -----------------------------------------------------

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

    pub fn wait_for_event(&self, child_id: &str, deadline: Instant) -> bool {
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().expect("client state");
        loop {
            if let Some(c) = g.children.get(child_id) {
                if !c.stdout.is_empty() || !c.stderr.is_empty() || c.exit.is_some() {
                    return true;
                }
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

    pub fn is_dead(&self) -> bool {
        self.inner.state.0.lock().map(|g| g.eof).unwrap_or(true)
    }

    // -- One-shot execution -------------------------------------------------

    pub fn run_oneshot(
        &self,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let info = self.spawn_pipes(argv, env_overlay, cwd)?;
        let child_id = info.child_id;
        let deadline = Instant::now() + timeout;
        let mut stdout_buf: Vec<u8> = Vec::new();
        let mut stderr_buf: Vec<u8> = Vec::new();
        let mut exit_code: Option<i32> = None;
        let mut timed_out = false;

        loop {
            for chunk in self.drain_stdout(&child_id) {
                stdout_buf.extend_from_slice(&chunk);
            }
            for chunk in self.drain_stderr(&child_id) {
                stderr_buf.extend_from_slice(&chunk);
            }
            if let Some((code, _sig)) = self.take_exit(&child_id) {
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
                let _ = self.signal(&child_id, libc::SIGKILL, true);
                let drain_deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < drain_deadline {
                    self.wait_for_event(&child_id, drain_deadline);
                    for chunk in self.drain_stdout(&child_id) {
                        stdout_buf.extend_from_slice(&chunk);
                    }
                    for chunk in self.drain_stderr(&child_id) {
                        stderr_buf.extend_from_slice(&chunk);
                    }
                    if let Some((code, _sig)) = self.take_exit(&child_id) {
                        exit_code = Some(code);
                        break;
                    }
                }
                break;
            }
            self.wait_for_event(&child_id, deadline);
        }

        let _ = self.close_child(&child_id);
        let code = if timed_out { 124 } else { exit_code.unwrap_or(-1) };
        Ok((stdout_buf, stderr_buf, code))
    }

    // -- Internal -----------------------------------------------------------

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
        // Serialise send under a lock so concurrent ops don't interleave
        // bytes on the stream.
        {
            let mut w = self
                .inner
                .write
                .lock()
                .map_err(|_| Error::exec("write lock poisoned"))?;
            send_frame_stream(&mut *w, &Frame::Op(op))?;
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
}

/// Result of a successful Spawn / OpenShell.
#[derive(Debug, Clone)]
pub struct SpawnInfo {
    pub child_id: String,
    pub pid: i32,
}

/// Handle to a running child spawned via `spawn_pipes_async`.
pub struct ChildHandle {
    client: Arc<VsockInitClient>,
    child_id: String,
}

impl ChildHandle {
    pub(crate) fn new(client: Arc<VsockInitClient>, child_id: String) -> Self {
        Self { client, child_id }
    }

    pub fn child_id(&self) -> &str {
        &self.child_id
    }

    pub fn wait_with_timeout(&self, timeout: Duration) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let deadline = Instant::now() + timeout;
        let mut stdout_buf: Vec<u8> = Vec::new();
        let mut stderr_buf: Vec<u8> = Vec::new();
        let mut exit_code: Option<i32> = None;
        let mut timed_out = false;

        loop {
            for chunk in self.client.drain_stdout(&self.child_id) {
                stdout_buf.extend_from_slice(&chunk);
            }
            for chunk in self.client.drain_stderr(&self.child_id) {
                stderr_buf.extend_from_slice(&chunk);
            }
            if let Some((code, _sig)) = self.client.take_exit(&self.child_id) {
                exit_code = Some(code);
                break;
            }
            if self.client.is_dead() {
                exit_code = Some(-1);
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                timed_out = true;
                let _ = self.client.signal(&self.child_id, libc::SIGKILL, true);
                let drain_deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < drain_deadline {
                    self.client.wait_for_event(&self.child_id, drain_deadline);
                    for chunk in self.client.drain_stdout(&self.child_id) {
                        stdout_buf.extend_from_slice(&chunk);
                    }
                    for chunk in self.client.drain_stderr(&self.child_id) {
                        stderr_buf.extend_from_slice(&chunk);
                    }
                    if let Some((code, _sig)) = self.client.take_exit(&self.child_id) {
                        exit_code = Some(code);
                        break;
                    }
                }
                break;
            }
            self.client.wait_for_event(&self.child_id, deadline);
        }

        let _ = self.client.close_child(&self.child_id);
        let code = if timed_out { 124 } else { exit_code.unwrap_or(-1) };
        Ok((stdout_buf, stderr_buf, code))
    }
}

impl VsockInitClient {
    pub fn spawn_pipes_async(
        self: &Arc<Self>,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<ChildHandle> {
        self.spawn_pipes_inherit_async(argv, env_overlay, cwd, None)
    }

    pub fn spawn_pipes_inherit_async(
        self: &Arc<Self>,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        inherit_from_child: Option<&str>,
    ) -> Result<ChildHandle> {
        let info = self.spawn_pipes_inherit(argv, env_overlay, cwd, inherit_from_child)?;
        Ok(ChildHandle::new(Arc::clone(self), info.child_id))
    }
}

// ---------------------------------------------------------------------------
// Reader thread
// ---------------------------------------------------------------------------

fn reply_id(r: &Reply) -> String {
    match r {
        Reply::Hello { id, .. } | Reply::Spawn { id, .. } | Reply::Ack { id, .. } => id.clone(),
    }
}

fn reader_loop(mut read: std::fs::File, state: Arc<(Mutex<Shared>, Condvar)>) {
    loop {
        match recv_frame_stream(&mut read) {
            Ok(None) => break, // EOF
            Ok(Some(frame)) => {
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
