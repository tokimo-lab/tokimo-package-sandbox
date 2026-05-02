//! Host-side client for the in-sandbox `tokimo-sandbox-init` over VSOCK.
//!
//! Structurally identical to `src/linux/init_client.rs` but uses stream-based
//! framing (`recv_frame_stream` / `send_frame_stream`) instead of seqpacket.
//! No fd passing (VSOCK doesn't support SCM_RIGHTS) — PTY mode returns
//! NotImplemented on macOS for now.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::error::{Error, Result};
use crate::protocol::types::{Event, Frame, Op, PROTOCOL_VERSION, Reply, StdioMode, default_features};
use crate::protocol::wire::{recv_frame_stream, send_frame_stream};

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
pub struct VsockInitClient {
    inner: Arc<Inner>,
}

struct Inner {
    /// Write half of the VSOCK socket. The reader thread holds an
    /// independent `dup`'d fd, so the writer Mutex never blocks the reader.
    write_fd: Mutex<OwnedFd>,
    state: Arc<(Mutex<Shared>, Condvar)>,
    counter: AtomicU64,
    /// JoinHandle for the reader thread; held to keep it alive.
    _reader: Mutex<Option<JoinHandle<()>>>,
}

impl VsockInitClient {
    /// Wrap an already-connected VSOCK stream socket and spawn the background
    /// reader thread. Internally `dup`s the fd so reader and writer can
    /// operate on independent file descriptors.
    pub fn new(sock: OwnedFd) -> Result<Self> {
        let raw = sock.as_raw_fd();
        let dup_raw = unsafe { libc::dup(raw) };
        if dup_raw < 0 {
            return Err(Error::other(format!(
                "dup VSOCK fd: {}",
                std::io::Error::last_os_error()
            )));
        }
        let read_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
        let state = Arc::new((Mutex::new(Shared::default()), Condvar::new()));

        let reader_state = state.clone();
        let reader = thread::Builder::new()
            .name("tokimo-vsock-init-reader".into())
            .spawn(move || reader_loop(read_fd, reader_state))
            .map_err(|e| Error::other(format!("spawn reader thread: {e}")))?;

        Ok(Self {
            inner: Arc::new(Inner {
                write_fd: Mutex::new(sock),
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
                    return Err(Error::other(format!(
                        "init handshake rejected: {:?}",
                        error.map(|e| e.message)
                    )));
                }
                if protocol != PROTOCOL_VERSION {
                    return Err(Error::other(format!(
                        "init protocol mismatch: client={PROTOCOL_VERSION} init={protocol}"
                    )));
                }
                if init_pid != 1 {
                    return Err(Error::other(format!("init not PID 1 (got {init_pid})")));
                }
                Ok(init_pid)
            }
            other => Err(Error::other(format!("expected Hello reply, got {other:?}"))),
        }
    }

    /// OpenShell → returns child_id of the long-lived shell.
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

    /// Spawn (Pipes mode).
    #[allow(dead_code)] // exposed for future spawn_pipes RPC; kept for API parity with bwrap backend
    pub fn spawn_pipes(
        &self,
        argv: &[String],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<SpawnInfo> {
        let id = next_id(&self.inner.counter);
        let op = Op::Spawn {
            id: id.clone(),
            argv: argv.to_vec(),
            env_overlay: env_overlay.to_vec(),
            cwd: cwd.map(str::to_string),
            stdio: StdioMode::Pipes,
            inherit_from_child: None,
        };
        self.spawn_ack(&id, op)
    }

    fn spawn_ack(&self, id: &str, op: Op) -> Result<SpawnInfo> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(10))?;
        match reply {
            Reply::Spawn {
                ok, child_id, error, ..
            } => {
                if !ok {
                    return Err(Error::other(format!("spawn failed: {:?}", error.map(|e| e.message))));
                }
                Ok(SpawnInfo {
                    child_id: child_id.unwrap_or_default(),
                })
            }
            other => Err(Error::other(format!("unexpected reply: {other:?}"))),
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

    /// Spawn `tokimo-sandbox-fuse` inside the guest. Init opens a vsock
    /// connection from the child to the host's FUSE listener at
    /// `vsock://2:vsock_port` (host CID), performs the VFS-protocol
    /// handshake bound to `name`, then `mount(2)`s FUSE at `target`.
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

    /// Counterpart for `mount_fuse`.
    pub fn unmount_fuse(&self, name: &str) -> Result<()> {
        let id = next_id(&self.inner.counter);
        let op = Op::UnmountFuse {
            id: id.clone(),
            name: name.into(),
        };
        self.ack_op(&id, op)
    }

    /// Spawn (PTY mode). VSOCK has no SCM_RIGHTS, so the master fd stays
    /// inside the guest; init streams its stdout via `Reply::Stdout`
    /// events the same way pipe-mode children do.
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

    /// Resize a PTY child: ioctl(master, TIOCSWINSZ) + killpg(SIGWINCH)
    /// inside the guest.
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

    #[allow(dead_code)] // future close_child RPC
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

    fn ack_op(&self, id: &str, op: Op) -> Result<()> {
        let reply = self.send_op_sync(id, op, Duration::from_secs(5))?;
        match reply {
            Reply::Ack { ok, error, .. } => {
                if ok {
                    Ok(())
                } else {
                    Err(Error::other(format!("init op failed: {:?}", error.map(|e| e.message))))
                }
            }
            other => Err(Error::other(format!("expected Ack, got {other:?}"))),
        }
    }

    fn send_op_sync(&self, id: &str, op: Op, timeout: Duration) -> Result<Reply> {
        // Send the op while holding the write lock (multiple writer threads
        // might race; the reader uses an independent dup'd fd so it is not
        // blocked here).
        {
            let mut sock_guard = self
                .inner
                .write_fd
                .lock()
                .map_err(|_| Error::other("sock lock poisoned"))?;
            let mut writer = FdWriter(&mut sock_guard);
            send_frame_stream(&mut writer, &Frame::Op(op))?;
        }

        // Wait for matching reply.
        let deadline = Instant::now() + timeout;
        let (lock, cv) = &*self.inner.state;
        let mut g = lock.lock().map_err(|_| Error::other("client state poisoned"))?;
        loop {
            if let Some(r) = g.replies.remove(id) {
                return Ok(r);
            }
            if g.eof {
                return Err(Error::other("init connection closed before reply"));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::other(format!("init op {id} timed out after {timeout:?}")));
            }
            let (g2, _) = cv
                .wait_timeout(g, deadline - now)
                .map_err(|_| Error::other("client state poisoned"))?;
            g = g2;
        }
    }

    /// Drain pending stdout for `child_id` (returns empty Vec if none).
    pub fn drain_stdout(&self, child_id: &str) -> Vec<Vec<u8>> {
        let mut g = self.inner.state.0.lock().expect("client state");
        let entry = g.children.entry(child_id.into()).or_default();
        std::mem::take(&mut entry.stdout)
    }

    /// Drain pending stderr.
    pub fn drain_stderr(&self, child_id: &str) -> Vec<Vec<u8>> {
        let mut g = self.inner.state.0.lock().expect("client state");
        let entry = g.children.entry(child_id.into()).or_default();
        std::mem::take(&mut entry.stderr)
    }

    /// Block until the reader has data (stdout/stderr/exit) for `child_id`
    /// or `deadline` is reached. Returns `true` if there is something to
    /// read, `false` on timeout.
    #[allow(dead_code)] // diagnostic helper used by tests/manual probes
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

    /// Take the exit status if known.
    pub fn take_exit(&self, child_id: &str) -> Option<(i32, Option<i32>)> {
        let mut g = self.inner.state.0.lock().expect("client state");
        g.children.get_mut(child_id).and_then(|c| c.exit.take())
    }

    /// Snapshot of all child ids currently tracked by the reader thread.
    /// Useful for an event-pump loop that doesn't pre-register children.
    pub fn child_ids(&self) -> Vec<String> {
        let g = self.inner.state.0.lock().expect("client state");
        g.children.keys().cloned().collect()
    }

    /// Has the reader thread observed EOF / fatal error?
    pub fn is_dead(&self) -> bool {
        self.inner.state.0.lock().map(|g| g.eof).unwrap_or(true)
    }

    /// Run a one-shot command in pipes mode and block until completion or
    /// `timeout`. Returns (stdout_bytes, stderr_bytes, exit_code).
    ///
    /// On timeout: SIGKILLs the process group and returns whatever was
    /// captured plus exit_code = 124 (matching coreutils `timeout`).
    #[allow(dead_code)] // future Exec(oneshot) RPC
    pub fn run_oneshot(
        &self,
        argv: &[String],
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
            // Drain any pending bytes first.
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
                let _ = self.signal(&child_id, 9 /* SIGKILL */, true);
                // Give init a brief window to reap and forward the exit.
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
}

/// Result of a successful Spawn / OpenShell.
#[derive(Debug, Clone)]
pub struct SpawnInfo {
    pub child_id: String,
}

fn reader_loop(mut sock: OwnedFd, state: Arc<(Mutex<Shared>, Condvar)>) {
    loop {
        let frame_opt = {
            let mut reader = FdReader(&mut sock);
            match recv_frame_stream(&mut reader) {
                Ok(f) => f,
                Err(_) => break,
            }
        };

        match frame_opt {
            None => break,
            Some(frame) => {
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

/// Adapter to make OwnedFd implement Read.
struct FdReader<'a>(&'a mut OwnedFd);

impl<'a> Read for FdReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        nix::unistd::read(self.0.as_raw_fd(), buf).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }
}

/// Adapter to make OwnedFd implement Write.
struct FdWriter<'a>(&'a mut OwnedFd);

impl<'a> Write for FdWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        nix::unistd::write(&*self.0, buf).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
