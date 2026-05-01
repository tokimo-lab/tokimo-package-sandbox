//! Windows host-side client for the in-VM `tokimo-sandbox-init` over a
//! named-pipe-tunneled COM1 stream.
//!
//! Architecturally identical to [`crate::macos::vz_vsock::VsockInitClient`]
//! but the transport is a pair of `std::fs::File` halves wrapping a single
//! Windows named pipe HANDLE (one half cloned via `try_clone()` so the
//! reader thread and the synchronous send path don't fight over the
//! handle's I/O state).
//!
//! Wire format: length-prefixed JSON frames defined in
//! [`crate::protocol::wire`].

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::protocol::types::{Event, Frame, MountEntry, Op, PROTOCOL_VERSION, Reply, StdioMode, default_features};
use crate::protocol::wire::{recv_frame_stream, send_frame_stream};
use crate::{Error, Result};

use super::ov_pipe::OvPipe;

// ---------------------------------------------------------------------------
// Shared state and event channels (mirrors VsockInitClient architecture)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Shared {
    /// child_id → buffered events.
    children: HashMap<String, ChildEvents>,
    /// Reply id → Reply. Reader inserts on arrival.
    replies: HashMap<String, Reply>,
    /// Set when the reader thread sees EOF / a fatal read error.
    eof: bool,
}

#[derive(Default)]
pub(crate) struct ChildEvents {
    pub stdout: Vec<Vec<u8>>,
    pub stderr: Vec<Vec<u8>>,
    pub exit: Option<(i32, Option<i32>)>,
}

// ---------------------------------------------------------------------------
// WinInitClient
// ---------------------------------------------------------------------------

/// Synchronous client for `tokimo-sandbox-init` over a Windows named pipe.
/// Cheap to clone (the inner `Arc` carries the writer + shared state).
pub struct WinInitClient {
    inner: Arc<Inner>,
}

impl Clone for WinInitClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct Inner {
    write: Mutex<Box<dyn Write + Send>>,
    state: Arc<(Mutex<Shared>, Condvar)>,
    counter: AtomicU64,
    _reader: Mutex<Option<JoinHandle<()>>>,
}

fn next_id(counter: &AtomicU64) -> String {
    format!("h{}", counter.fetch_add(1, Ordering::Relaxed))
}

impl WinInitClient {
    /// Build a client from the bidirectional pipe `File`. Spawns the reader
    /// thread immediately. The provided `pipe` is used as the writer; the
    /// reader half is created via `try_clone()` (which calls
    /// `DuplicateHandle` underneath so the two ends don't share I/O state).
    pub fn new(pipe: OvPipe) -> Result<Self> {
        let read = pipe
            .try_clone()
            .map_err(|e| Error::exec(format!("try_clone session pipe: {e}")))?;
        Self::with_transport(Box::new(pipe), Box::new(read))
    }

    /// Build a client from arbitrary transport halves. Each half must implement
    /// the relevant byte-oriented trait. Used by the Windows service to drive
    /// the in-VM init protocol over an `HvSock` pair without going through a
    /// named-pipe tunnel.
    pub fn with_transport(
        write_half: Box<dyn Write + Send>,
        read_half: Box<dyn Read + Send>,
    ) -> Result<Self> {
        let state = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let reader_state = state.clone();

        let reader = thread::Builder::new()
            .name("tokimo-win-init-reader".into())
            .spawn(move || reader_loop(read_half, reader_state))
            .map_err(|e| Error::exec(format!("spawn reader thread: {e}")))?;

        Ok(Self {
            inner: Arc::new(Inner {
                write: Mutex::new(write_half),
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
                if init_pid != 1 {
                    return Err(Error::exec(format!("init not PID 1 (got {init_pid})")));
                }
                Ok(init_pid)
            }
            other => Err(Error::exec(format!("expected Hello reply, got {other:?}"))),
        }
    }

    // -- Shell / spawn ------------------------------------------------------

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

    pub fn spawn_pipes(&self, argv: &[&str], env_overlay: &[(String, String)], cwd: Option<&str>) -> Result<SpawnInfo> {
        self.spawn_pipes_inherit(argv, env_overlay, cwd, None)
    }

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

    /// Spawn (PTY mode). The master fd lives inside the guest; init streams
    /// the slave's output via `Reply::Stdout` events the same way pipe
    /// children do.
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

    /// Resize a PTY child (TIOCSWINSZ + SIGWINCH inside the guest).
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

    fn spawn_ack(&self, id: &str, op: Op) -> Result<SpawnInfo> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(15))?;
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

    /// Send a `MountManifest` op listing every share the guest must dial
    /// and 9p-mount. Sent after `Hello` and before any `OpenShell`. The
    /// service has already created an AF_HYPERV listener for each port
    /// before booting the VM, so the guest can dial them without races.
    /// The mount fds live forever inside init's `State` so the kernel
    /// keeps the channels alive — there is no `Unmount` reply path for
    /// shares; tearing the session down tears the mounts down.
    pub fn send_mount_manifest(&self, entries: Vec<MountEntry>) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::MountManifest {
            id: id.clone(),
            entries,
        };
        // Mounting is a blocking operation in the guest (one vsock dial
        // + one mount(2) per entry); allow plenty of time for slow boots
        // / many shares before declaring the session dead.
        let reply = self.send_op_sync(&id, op, Duration::from_secs(60))?;
        match reply {
            Reply::MountManifest {
                ok,
                failing_index,
                error,
                ..
            } => {
                if ok {
                    Ok(())
                } else {
                    Err(Error::exec(format!(
                        "MountManifest failed at entry {:?}: {:?}",
                        failing_index,
                        error.map(|e| e.message),
                    )))
                }
            }
            other => Err(Error::exec(format!("expected MountManifest reply, got {other:?}"))),
        }
    }

    /// Dynamically add one Plan9-over-vsock share at runtime. The host
    /// must have already attached the share to the live VM via
    /// `HcsModifyComputeSystem` so the guest's vsock dial succeeds.
    pub fn add_mount(&self, entry: MountEntry) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::AddMount {
            id: id.clone(),
            entry,
        };
        // mount(2) inside the guest can take a moment for slow boots.
        let reply = self.send_op_sync(&id, op, Duration::from_secs(30))?;
        match reply {
            Reply::Ack { ok, error, .. } => {
                if ok {
                    Ok(())
                } else {
                    Err(Error::exec(format!(
                        "AddMount failed: {:?}",
                        error.map(|e| e.message)
                    )))
                }
            }
            other => Err(Error::exec(format!("expected Ack reply, got {other:?}"))),
        }
    }

    /// Dynamically remove a Plan9 share by 9p tag (`aname`).
    pub fn remove_mount(&self, name: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::RemoveMount {
            id: id.clone(),
            name: name.to_string(),
        };
        let reply = self.send_op_sync(&id, op, Duration::from_secs(30))?;
        match reply {
            Reply::Ack { ok, error, .. } => {
                if ok {
                    Ok(())
                } else {
                    Err(Error::exec(format!(
                        "RemoveMount failed: {:?}",
                        error.map(|e| e.message)
                    )))
                }
            }
            other => Err(Error::exec(format!("expected Ack reply, got {other:?}"))),
        }
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

    pub fn is_dead(&self) -> bool {
        self.inner.state.0.lock().map(|g| g.eof).unwrap_or(true)
    }

    /// Snapshot of (child_exited, transport_dead). Used by ShellHandle's
    /// `try_wait` closure on the host side.
    pub fn child_exited(&self, child_id: &str) -> bool {
        self.inner
            .state
            .0
            .lock()
            .map(|g| g.children.get(child_id).map(|c| c.exit.is_some()).unwrap_or(false))
            .unwrap_or(true)
    }

    // -- One-shot ----------------------------------------------------------

    pub fn run_oneshot(
        &self,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let info = self.spawn_pipes(argv, env_overlay, cwd)?;
        self.collect_until_exit(&info.child_id, timeout)
    }

    pub fn run_oneshot_inherit(
        &self,
        argv: &[&str],
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
            let mut w = self
                .inner
                .write
                .lock()
                .map_err(|_| Error::exec("write lock poisoned"))?;
            send_frame_stream(&mut *w, &Frame::Op(op))?;
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
}

#[derive(Debug, Clone)]
pub struct SpawnInfo {
    pub child_id: String,
    pub pid: i32,
}

// ---------------------------------------------------------------------------
// Reader thread
// ---------------------------------------------------------------------------

fn reply_id(r: &Reply) -> String {
    match r {
        Reply::Hello { id, .. } | Reply::Spawn { id, .. } | Reply::Ack { id, .. } | Reply::MountManifest { id, .. } => {
            id.clone()
        }
    }
}

fn reader_loop<R: Read>(mut r: R, state: Arc<(Mutex<Shared>, Condvar)>) {
    loop {
        match recv_frame_stream(&mut r) {
            Ok(None) => break,
            Err(_) => {
                let (lock, cv) = &*state;
                if let Ok(mut g) = lock.lock() {
                    g.eof = true;
                }
                cv.notify_all();
                break;
            }
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
                    Frame::Op(_) => {}
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

// ---------------------------------------------------------------------------
// Stdin adapter — Write impl that converts host stdin bytes into Op::Write.
// ---------------------------------------------------------------------------

/// `Write` adapter that turns bytes written to the long-lived shell's stdin
/// into `Op::Write` ops on the init protocol.
pub struct InitStdin {
    pub client: WinInitClient,
    pub child_id: String,
    pub closed: bool,
}

impl Write for InitStdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdin closed"));
        }
        self.client
            .write(&self.child_id, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Read adapter — drains buffered Stdout/Stderr events from `Shared`.
// ---------------------------------------------------------------------------

/// Stream side selector for [`InitReader`].
#[derive(Clone, Copy, Debug)]
pub enum InitStream {
    Stdout,
    Stderr,
}

/// `Read` adapter that drains buffered child stream events. Blocks the
/// caller (via the underlying `Condvar`) when no data is available, until
/// a chunk arrives, the child exits, or the connection dies.
pub struct InitReader {
    client: WinInitClient,
    child_id: String,
    side: InitStream,
    /// Carry-over bytes from the previous read when `buf` was smaller than
    /// the next available chunk.
    leftover: Vec<u8>,
}

impl InitReader {
    pub fn new(client: WinInitClient, child_id: String, side: InitStream) -> Self {
        Self {
            client,
            child_id,
            side,
            leftover: Vec::new(),
        }
    }
}

impl Read for InitReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.leftover.is_empty() {
            let n = buf.len().min(self.leftover.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }

        // Block on the client's Condvar until something is available.
        loop {
            let (lock, cv) = &*self.client.inner.state;
            let mut g = lock
                .lock()
                .map_err(|_| std::io::Error::other("client state poisoned"))?;
            loop {
                let entry_has_data = g
                    .children
                    .get(&self.child_id)
                    .map(|c| match self.side {
                        InitStream::Stdout => !c.stdout.is_empty(),
                        InitStream::Stderr => !c.stderr.is_empty(),
                    })
                    .unwrap_or(false);
                let exit_seen = g
                    .children
                    .get(&self.child_id)
                    .map(|c| c.exit.is_some())
                    .unwrap_or(false);
                if entry_has_data {
                    let entry = g.children.entry(self.child_id.clone()).or_default();
                    let chunks = match self.side {
                        InitStream::Stdout => std::mem::take(&mut entry.stdout),
                        InitStream::Stderr => std::mem::take(&mut entry.stderr),
                    };
                    drop(g);
                    let mut concat = Vec::new();
                    for c in chunks {
                        concat.extend_from_slice(&c);
                    }
                    let n = buf.len().min(concat.len());
                    buf[..n].copy_from_slice(&concat[..n]);
                    if n < concat.len() {
                        self.leftover.extend_from_slice(&concat[n..]);
                    }
                    return Ok(n);
                }
                if g.eof || exit_seen {
                    // Drain any leftover events one final time, then EOF.
                    if let Some(c) = g.children.get_mut(&self.child_id) {
                        let chunks = match self.side {
                            InitStream::Stdout => std::mem::take(&mut c.stdout),
                            InitStream::Stderr => std::mem::take(&mut c.stderr),
                        };
                        if !chunks.is_empty() {
                            drop(g);
                            let mut concat = Vec::new();
                            for c in chunks {
                                concat.extend_from_slice(&c);
                            }
                            let n = buf.len().min(concat.len());
                            buf[..n].copy_from_slice(&concat[..n]);
                            if n < concat.len() {
                                self.leftover.extend_from_slice(&concat[n..]);
                            }
                            return Ok(n);
                        }
                    }
                    return Ok(0); // EOF
                }
                let g2 = cv.wait(g).map_err(|_| std::io::Error::other("client state poisoned"))?;
                g = g2;
            }
        }
    }
}
