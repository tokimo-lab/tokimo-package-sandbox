//! Event loop for `tokimo-sandbox-init`.
//!
//! Single-threaded mio loop watching:
//!   - the SEQPACKET listener (accept new control clients)
//!   - the active control client (recv ops)
//!   - signalfd (SIGCHLD reap → Exit events)
//!   - per-pipe-child stdout/stderr fds (drain → Stdout/Stderr events)

use std::collections::{HashMap, HashSet};
use std::env;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use nix::sys::signal::{Signal, killpg, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::sys::socket::{accept4, SockFlag};
use nix::unistd::{Pid, getpid};
use tokimo_package_sandbox::init_protocol::{
    Event, ErrorCode, ErrorReply, Frame, Op, PROTOCOL_VERSION, Reply, STREAM_CHUNK_BYTES,
    StdioMode, default_features,
};
use tokimo_package_sandbox::init_wire::{recv_frame, send_frame};

use crate::child::{ChildKind, ChildRecord};
use crate::pty as ptymod;

/// Env vars that init protects: the user's `env_overlay` cannot override
/// these. Rationale per plan §5: bwrap injects HTTP_PROXY/etc to route the
/// AI's network traffic through the L7 audit proxy; letting a child blow
/// them away defeats audit.
const PROTECTED_ENV: &[&str] = &[
    "PATH", "LANG", "LC_ALL", "SAFEBOX",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
];

const TOK_LISTENER: Token = Token(0);
const TOK_SIGFD: Token = Token(1);
/// Client tokens start at 2; per-client token = TOK_CLIENT_BASE + slot.
const TOK_CLIENT_BASE: usize = 2;
/// Per-child fd tokens start at 100; even = stdout pipe, odd = stderr pipe.
/// The numeric child slot id is encoded as `100 + slot * 2 + (is_stderr as usize)`.
const TOK_CHILD_BASE: usize = 100;

/// Per-connection state inside the init server.
pub struct ClientState {
    pub fd: OwnedFd,
    /// child_ids owned by this client (for disconnect cleanup).
    pub children: HashSet<String>,
}

pub struct State {
    pub base_env: Vec<(String, String)>,
    pub children: HashMap<String, ChildRecord>,
    /// Maps child slot index (0..) → child_id, used to decode stream tokens.
    pub child_slots: Vec<Option<String>>,
    /// Connected clients keyed by fd.
    pub clients: HashMap<RawFd, ClientState>,
    /// Maps client slot index → RawFd for mio event demux.
    /// Index = token.0 - TOK_CLIENT_BASE.
    pub client_slots: Vec<Option<RawFd>>,
}

impl State {
    fn alloc_slot(&mut self) -> usize {
        // Never recycle slots — child_ids must remain unique for the
        // lifetime of the session because host-side ChildHandle may
        // still be draining events after the child has exited.
        let slot = self.child_slots.len();
        self.child_slots.push(None);
        slot
    }
}

pub fn snapshot_base_env() -> Vec<(String, String)> {
    env::vars().collect()
}

pub fn run_loop(
    listener: OwnedFd,
    sigfd: OwnedFd,
    base_env: Vec<(String, String)>,
) -> Result<(), String> {
    let mut poll = Poll::new().map_err(|e| format!("Poll::new: {e}"))?;
    let mut events = Events::with_capacity(64);

    poll.registry()
        .register(
            &mut SourceFd(&listener.as_raw_fd()),
            TOK_LISTENER,
            Interest::READABLE,
        )
        .map_err(|e| format!("register listener: {e}"))?;
    poll.registry()
        .register(
            &mut SourceFd(&sigfd.as_raw_fd()),
            TOK_SIGFD,
            Interest::READABLE,
        )
        .map_err(|e| format!("register sigfd: {e}"))?;

    let mut state = State {
        base_env,
        children: HashMap::new(),
        child_slots: Vec::new(),
        clients: HashMap::new(),
        client_slots: Vec::new(),
    };
    let mut shutdown = false;

    while !shutdown {
        if let Err(e) = poll.poll(&mut events, None) {
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }

        for ev in events.iter() {
            match ev.token() {
                TOK_LISTENER => {
                    if let Err(e) =
                        accept_client(&listener, &mut state, poll.registry())
                    {
                        eprintln!("[init] accept_client: {e}");
                    }
                }
                TOK_SIGFD => {
                    drain_sigfd(&sigfd);
                    reap_children(&mut state, poll.registry());
                }
                tok if tok.0 >= TOK_CLIENT_BASE && tok.0 < TOK_CHILD_BASE => {
                    let slot = tok.0 - TOK_CLIENT_BASE;
                    if let Some(fd) = state.client_slots.get(slot).and_then(|o| *o) {
                        match handle_client_readable(fd, &mut state, poll.registry()) {
                            Ok(false) => {
                                // EOF: clean up this client's children.
                                disconnect_client(fd, &mut state, poll.registry());
                            }
                            Err(e) => {
                                eprintln!("[init] client error: {e}");
                                disconnect_client(fd, &mut state, poll.registry());
                            }
                            _ => {} // Ok(true): more to read
                        }
                        if let Some(reason) = state.shutdown_signal() {
                            shutdown = true;
                            kill_all_children(&mut state);
                            let _ = reason;
                        }
                    }
                }
                tok => {
                    // Per-child stdout/stderr pipe became readable.
                    pump_child_stream(tok, &mut state, poll.registry());
                }
            }
        }
    }
    Ok(())
}

impl State {
    fn shutdown_signal(&self) -> Option<&'static str> {
        // Set when an Op::Shutdown was processed. We use a separate flag so
        // we can finish flushing the current event batch first.
        if self.children.values().any(|c| c.shutdown_pending) {
            Some("op-shutdown")
        } else {
            None
        }
    }
}

fn accept_client(
    listener: &OwnedFd,
    state: &mut State,
    registry: &mio::Registry,
) -> Result<(), String> {
    let fd = accept4(
        listener.as_raw_fd(),
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .map_err(|e| format!("accept4: {e}"))?;
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = owned.as_raw_fd();
    // Allocate a client slot (never recycled).
    let slot = state.client_slots.len();
    let token = Token(TOK_CLIENT_BASE + slot);
    registry
        .register(
            &mut SourceFd(&raw),
            token,
            Interest::READABLE,
        )
        .map_err(|e| format!("register client: {e}"))?;
    state.client_slots.push(Some(raw));
    state.clients.insert(
        raw,
        ClientState {
            fd: owned,
            children: HashSet::new(),
        },
    );
    Ok(())
}

/// Clean up a disconnected client: kill its children, deregister all fds
/// (including per-child pipe fds), and remove from tracking maps.
fn disconnect_client(fd: RawFd, state: &mut State, registry: &mio::Registry) {
    // Collect and kill all children owned by this client.
    let child_ids: Vec<String> = state
        .children
        .iter()
        .filter(|(_, c)| c.owner_fd == fd)
        .map(|(id, _)| id.clone())
        .collect();
    for cid in &child_ids {
        if let Some(rec) = state.children.get(cid) {
            if rec.pgid > 0 {
                let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGKILL);
            }
        }
    }
    // Remove children AND deregister their pipe fds immediately.
    // If we don't deregister here, the pipes stay readable (EOF) but
    // pump_child_stream can't drain them because the owner client is
    // already gone — causing an infinite poll loop that starves new
    // connections.
    for cid in &child_ids {
        if let Some(rec) = state.children.remove(cid) {
            if let Some(fd) = rec.stdout_fd.as_ref() {
                let _ = registry.deregister(&mut SourceFd(&fd.as_raw_fd()));
            }
            if let Some(fd) = rec.stderr_fd.as_ref() {
                let _ = registry.deregister(&mut SourceFd(&fd.as_raw_fd()));
            }
        }
    }
    // Remove client from tracking.
    if let Some(client) = state.clients.remove(&fd) {
        let _ = registry.deregister(&mut SourceFd(&client.fd.as_raw_fd()));
        // Clear the slot so the mio token won't resolve to this fd anymore.
        for slot_entry in state.client_slots.iter_mut() {
            if *slot_entry == Some(fd) {
                *slot_entry = None;
                break;
            }
        }
    }
}

fn drain_sigfd(sigfd: &OwnedFd) {
    // Just drain — content not used; we always waitpid(-1, WNOHANG).
    let mut buf = [0u8; 1024];
    loop {
        let n = unsafe {
            libc::read(sigfd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
        };
        if n <= 0 {
            break;
        }
    }
}

fn reap_children(
    state: &mut State,
    registry: &mio::Registry,
) {
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) => {
                emit_exit(state, registry, pid, code, None);
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                emit_exit(state, registry, pid, 128 + (sig as i32), Some(sig as i32));
            }
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
}

fn emit_exit(
    state: &mut State,
    registry: &mio::Registry,
    pid: Pid,
    code: i32,
    signal: Option<i32>,
) {
    // Find child by pid (reverse lookup).
    let child_id = state
        .children
        .iter()
        .find(|(_, c)| c.pid == pid.as_raw())
        .map(|(id, _)| id.clone());
    let Some(id) = child_id else { return };
    let owner_fd = state.children.get(&id).map(|c| c.owner_fd);
    if let Some(rec) = state.children.get(&id) {
        // Drain any remaining bytes before emitting Exit.
        if let Some(fd) = rec.stdout_fd.as_ref() {
            if let Some(c) = owner_fd.and_then(|of| state.clients.get(&of)) {
                drain_pipe(fd, &id, &c.fd, false);
            }
        }
        if let Some(fd) = rec.stderr_fd.as_ref() {
            if let Some(c) = owner_fd.and_then(|of| state.clients.get(&of)) {
                drain_pipe(fd, &id, &c.fd, true);
            }
        }
    }
    // Send Exit event to the owner client.
    if let Some(of) = owner_fd {
        if let Some(client) = state.clients.get(&of) {
            let frame = Frame::Event(Event::Exit {
                child_id: id.clone(),
                code,
                signal,
            });
            let _ = send_frame(
                unsafe { BorrowedFd::borrow_raw(client.fd.as_raw_fd()) },
                &frame,
                None,
            );
        }
    }
    // Cleanup: deregister fds and remove from client's children set.
    if let Some(rec) = state.children.remove(&id) {
        if let Some(fd) = rec.stdout_fd.as_ref() {
            let _ = registry.deregister(&mut SourceFd(&fd.as_raw_fd()));
        }
        if let Some(fd) = rec.stderr_fd.as_ref() {
            let _ = registry.deregister(&mut SourceFd(&fd.as_raw_fd()));
        }
        // Remove from client's child set.
        if let Some(cs) = state.clients.get_mut(&rec.owner_fd) {
            cs.children.remove(&id);
        }
    }
}

fn drain_pipe(fd: &OwnedFd, child_id: &str, client: &OwnedFd, is_stderr: bool) {
    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        let chunk = &buf[..n as usize];
        let frame = Frame::Event(if is_stderr {
            Event::Stderr {
                child_id: child_id.to_string(),
                data_b64: B64.encode(chunk),
            }
        } else {
            Event::Stdout {
                child_id: child_id.to_string(),
                data_b64: B64.encode(chunk),
            }
        });
        let _ = send_frame(unsafe { BorrowedFd::borrow_raw(client.as_raw_fd()) }, &frame, None);
    }
}

fn pump_child_stream(
    token: Token,
    state: &mut State,
    _registry: &mio::Registry,
) {
    let raw = token.0;
    if raw < TOK_CHILD_BASE {
        return;
    }
    let offset = raw - TOK_CHILD_BASE;
    let slot = offset / 2;
    let is_stderr = (offset % 2) == 1;
    let child_id = match state.child_slots.get(slot).and_then(|s| s.clone()) {
        Some(id) => id,
        None => return,
    };
    let Some(rec) = state.children.get(&child_id) else { return };
    let owner_fd = rec.owner_fd;
    let fd = if is_stderr {
        rec.stderr_fd.as_ref()
    } else {
        rec.stdout_fd.as_ref()
    };
    let Some(fd) = fd else { return };
    let Some(client) = state.clients.get(&owner_fd) else { return };
    drain_pipe(fd, &child_id, &client.fd, is_stderr);
}

fn handle_client_readable(
    client_fd: RawFd,
    state: &mut State,
    registry: &mio::Registry,
) -> Result<bool, String> {
    loop {
        let bf = unsafe { BorrowedFd::borrow_raw(client_fd) };
        let res = recv_frame(bf);
        match res {
            Ok(None) => return Ok(false), // EOF
            Ok(Some((Frame::Op(op), _fd))) => {
                handle_op(op, client_fd, state, registry);
            }
            Ok(Some((other, _))) => {
                eprintln!("[init] client sent non-Op frame: {other:?}");
            }
            Err(e) => {
                let s = e.to_string();
                if s.contains("EAGAIN") || s.contains("Resource temporarily unavailable") {
                    return Ok(true);
                }
                return Err(s);
            }
        }
    }
}

fn handle_op(op: Op, client_fd: RawFd, state: &mut State, registry: &mio::Registry) {
    let bf = unsafe { BorrowedFd::borrow_raw(client_fd) };
    match op {
        Op::Hello { id, protocol, .. } => {
            let ok = protocol == PROTOCOL_VERSION;
            let reply = Reply::Hello {
                id,
                ok,
                protocol: PROTOCOL_VERSION,
                features: default_features(),
                init_pid: getpid().as_raw(),
                error: if ok {
                    None
                } else {
                    Some(ErrorReply::new(
                        ErrorCode::BadHandshake,
                        format!("protocol mismatch: client={protocol} init={PROTOCOL_VERSION}"),
                    ))
                },
            };
            let _ = send_frame(bf, &Frame::Reply(reply), None);
        }
        Op::OpenShell { id, argv, env_overlay, cwd } => {
            spawn_child(
                client_fd,
                state,
                registry,
                id,
                argv,
                env_overlay,
                cwd,
                StdioMode::Pipes,
                ChildKind::Shell,
            );
        }
        Op::Spawn { id, argv, env_overlay, cwd, stdio, inherit_from_child } => {
            let inherited_env = inherit_from_child
                .as_ref()
                .and_then(|cid| resolve_child_env(state, cid));
            let inherited_cwd = inherit_from_child
                .as_ref()
                .and_then(|cid| resolve_child_cwd(state, cid));

            let effective_cwd = cwd.or(inherited_cwd);
            let effective_env = if let Some(base_env) = inherited_env {
                let mut merged = base_env;
                merged.extend(env_overlay);
                merged
            } else {
                env_overlay
            };

            spawn_child(
                client_fd,
                state,
                registry,
                id,
                argv,
                effective_env,
                effective_cwd,
                stdio,
                ChildKind::Generic,
            );
        }
        Op::Write { id, child_id, data_b64 } => {
            let res = (|| -> Result<(), ErrorReply> {
                let bytes = B64
                    .decode(&data_b64)
                    .map_err(|e| ErrorReply::new(ErrorCode::BadRequest, format!("base64: {e}")))?;
                let rec = state.children.get_mut(&child_id).ok_or_else(|| {
                    ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}"))
                })?;
                let fd = rec.stdin_fd.as_ref().ok_or_else(|| {
                    ErrorReply::new(ErrorCode::BadRequest, "child has no stdin (PTY?)")
                })?;
                let mut off = 0;
                while off < bytes.len() {
                    let n = unsafe {
                        libc::write(
                            fd.as_raw_fd(),
                            bytes.as_ptr().add(off).cast(),
                            bytes.len() - off,
                        )
                    };
                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(ErrorReply::new(
                            ErrorCode::Internal,
                            format!("write child stdin: {err}"),
                        ));
                    }
                    off += n as usize;
                }
                Ok(())
            })();
            ack(bf, id, res);
        }
        Op::Resize { id, child_id, rows, cols } => {
            let res = (|| -> Result<(), ErrorReply> {
                let rec = state.children.get(&child_id).ok_or_else(|| {
                    ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}"))
                })?;
                let master = rec.master_fd.as_ref().ok_or_else(|| {
                    ErrorReply::new(ErrorCode::BadRequest, "child has no PTY")
                })?;
                ptymod::set_winsize(master.as_raw_fd(), rows, cols)
                    .map_err(|e| ErrorReply::new(ErrorCode::Internal, e))?;
                let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGWINCH);
                Ok(())
            })();
            ack(bf, id, res);
        }
        Op::Signal { id, child_id, sig, to_pgrp } => {
            let res = (|| -> Result<(), ErrorReply> {
                let sig = Signal::try_from(sig).map_err(|_| {
                    ErrorReply::new(ErrorCode::BadRequest, format!("invalid signal {sig}"))
                })?;
                let rec = state.children.get(&child_id).ok_or_else(|| {
                    ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}"))
                })?;
                let target = if to_pgrp { rec.pgid } else { rec.pid };
                let r = if to_pgrp {
                    killpg(Pid::from_raw(target), sig)
                } else {
                    kill(Pid::from_raw(target), sig)
                };
                r.map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("kill: {e}")))
            })();
            ack(bf, id, res);
        }
        Op::Wait { id, child_id } => {
            // v1: synchronous Wait returns immediately if child already gone,
            // otherwise just acks (Exit event will follow when reaper sees it).
            let already = !state.children.contains_key(&child_id);
            if already {
                ack(bf, id, Ok(()));
            } else {
                ack(bf, id, Ok(()));
            }
        }
        Op::Close { id, child_id } => {
            let res = (|| -> Result<(), ErrorReply> {
                let rec = state.children.get_mut(&child_id).ok_or_else(|| {
                    ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}"))
                })?;
                rec.stdin_fd.take(); // drop = close
                rec.master_fd.take();
                Ok(())
            })();
            ack(bf, id, res);
        }
        Op::Shutdown { id, kill_all } => {
            if kill_all {
                kill_all_children_internal(state);
            }
            // Mark first child shutdown_pending=true so the loop exits;
            // if no children, we exit by setting a sentinel pseudo-record.
            if let Some(rec) = state.children.values_mut().next() {
                rec.shutdown_pending = true;
            } else {
                // No children: insert a phantom marker so the loop sees
                // shutdown_signal() == Some.
                state.children.insert(
                    "__shutdown__".into(),
                    ChildRecord {
                        pid: 0,
                        pgid: 0,
                        slot: usize::MAX,
                        kind: ChildKind::Generic,
                        stdin_fd: None,
                        stdout_fd: None,
                        stderr_fd: None,
                        master_fd: None,
                        shutdown_pending: true,
                        owner_fd: 0,
                    },
                );
            }
            ack(bf, id, Ok(()));
        }
        Op::AddUser { id, user_id, cwd, env_overlay } => {
            // Ensure per-user directories exist.
            let tmpdir = format!("/tmp/{}", user_id);
            let workdir = format!("/work/{}", user_id);
            let _ = std::fs::create_dir_all(&tmpdir);
            let _ = std::fs::create_dir_all(&workdir);

            // Build per-user env with TMPDIR + HOME isolation.
            // We must bypass `merge_env`'s PROTECTED_ENV filter here
            // because TMPDIR and HOME *are* the isolation boundary.
            let mut env = merge_env(&state.base_env, &env_overlay);
            // Override TMPDIR and HOME directly (they would be dropped by merge_env).
            env.retain(|(k, _)| k != "TMPDIR" && k != "HOME");
            env.push(("TMPDIR".into(), tmpdir));
            env.push(("HOME".into(), format!("/home/{}", user_id)));

            let effective_cwd = cwd.unwrap_or(workdir);
            spawn_child_inner(
                client_fd,
                state,
                registry,
                id,
                vec!["/bin/bash".into(), "--noprofile".into(), "--norc".into()],
                env,
                Some(effective_cwd),
                StdioMode::Pipes,
                ChildKind::Shell,
            );
        }
        Op::RemoveUser { id, user_id: _user_id } => {
            // Kill all children owned by this client.
            let child_ids: Vec<String> = state
                .children
                .iter()
                .filter(|(_, c)| c.owner_fd == client_fd)
                .map(|(cid, _)| cid.clone())
                .collect();
            for cid in &child_ids {
                if let Some(rec) = state.children.get(cid) {
                    if rec.pgid > 0 {
                        let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGKILL);
                    }
                }
            }
            ack(bf, id, Ok(()));
        }
        Op::BindMount { id, source, target, read_only } => {
            let res = (|| -> Result<(), ErrorReply> {
                let src = std::ffi::CString::new(source.as_str())
                    .map_err(|e| ErrorReply::new(ErrorCode::BadRequest, format!("source: {e}")))?;
                let tgt = std::ffi::CString::new(target.as_str())
                    .map_err(|e| ErrorReply::new(ErrorCode::BadRequest, format!("target: {e}")))?;
                let flags = if read_only {
                    libc::MS_BIND | libc::MS_RDONLY | libc::MS_REMOUNT
                } else {
                    libc::MS_BIND
                };
                let rc = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), std::ptr::null::<libc::c_char>(), flags, std::ptr::null::<libc::c_void>()) };
                if rc != 0 {
                    return Err(ErrorReply::new(
                        ErrorCode::Internal,
                        format!("mount {source} -> {target}: {}", std::io::Error::last_os_error()),
                    ));
                }
                Ok(())
            })();
            ack(bf, id, res);
        }
        Op::Unmount { id, target } => {
            let res = (|| -> Result<(), ErrorReply> {
                let tgt = std::ffi::CString::new(target.as_str())
                    .map_err(|e| ErrorReply::new(ErrorCode::BadRequest, format!("target: {e}")))?;
                let rc = unsafe { libc::umount2(tgt.as_ptr(), libc::MNT_DETACH) };
                if rc != 0 {
                    return Err(ErrorReply::new(
                        ErrorCode::Internal,
                        format!("umount {target}: {}", std::io::Error::last_os_error()),
                    ));
                }
                Ok(())
            })();
            ack(bf, id, res);
        }
    }
}

fn ack(bf: BorrowedFd<'_>, id: String, res: Result<(), ErrorReply>) {
    let reply = match res {
        Ok(()) => Reply::Ack { id, ok: true, error: None },
        Err(e) => Reply::Ack { id, ok: false, error: Some(e) },
    };
    let _ = send_frame(bf, &Frame::Reply(reply), None);
}

#[allow(clippy::too_many_arguments)]
fn spawn_child(
    client_fd: RawFd,
    state: &mut State,
    registry: &mio::Registry,
    id: String,
    argv: Vec<String>,
    env_overlay: Vec<(String, String)>,
    cwd: Option<String>,
    stdio: StdioMode,
    kind: ChildKind,
) {
    let env = merge_env(&state.base_env, &env_overlay);
    spawn_child_inner(client_fd, state, registry, id, argv, env, cwd, stdio, kind);
}

#[allow(clippy::too_many_arguments)]
fn spawn_child_inner(
    client_fd: RawFd,
    state: &mut State,
    registry: &mio::Registry,
    id: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    stdio: StdioMode,
    kind: ChildKind,
) {
    let bf = unsafe { BorrowedFd::borrow_raw(client_fd) };
    let slot = state.alloc_slot();
    let child_id = format!("c{}", slot + 1);
    let cwd_ref = cwd.as_deref();

    let res = match &stdio {
        StdioMode::Pipes => crate::child::spawn_pipes(&argv, &env, cwd_ref),
        StdioMode::Pty { rows, cols } => crate::child::spawn_pty(&argv, &env, cwd_ref, *rows, *cols),
    };
    match res {
        Err(err) => {
            state.child_slots[slot] = None;
            let reply = Reply::Spawn {
                id,
                ok: false,
                child_id: None,
                pid: None,
                error: Some(err),
            };
            let _ = send_frame(bf, &Frame::Reply(reply), None);
        }
        Ok(spawned) => {
            // Register pipe fds.
            if let Some(fd) = spawned.stdout_fd.as_ref() {
                let tok = Token(TOK_CHILD_BASE + slot * 2);
                let _ = registry.register(
                    &mut SourceFd(&fd.as_raw_fd()),
                    tok,
                    Interest::READABLE,
                );
            }
            if let Some(fd) = spawned.stderr_fd.as_ref() {
                let tok = Token(TOK_CHILD_BASE + slot * 2 + 1);
                let _ = registry.register(
                    &mut SourceFd(&fd.as_raw_fd()),
                    tok,
                    Interest::READABLE,
                );
            }
            let pid = spawned.pid;
            state.child_slots[slot] = Some(child_id.clone());
            // Master fd to send back via SCM_RIGHTS.
            let master_for_send: Option<RawFd> = spawned.master_fd.as_ref().map(|f| f.as_raw_fd());
            let rec = ChildRecord {
                pid,
                pgid: pid,
                slot,
                kind,
                stdin_fd: spawned.stdin_fd,
                stdout_fd: spawned.stdout_fd,
                stderr_fd: spawned.stderr_fd,
                master_fd: spawned.master_fd,
                shutdown_pending: false,
                owner_fd: client_fd,
            };
            state.children.insert(child_id.clone(), rec);
            // Track child in client's set.
            if let Some(cs) = state.clients.get_mut(&client_fd) {
                cs.children.insert(child_id.clone());
            }
            let reply = Reply::Spawn {
                id,
                ok: true,
                child_id: Some(child_id.clone()),
                pid: Some(pid),
                error: None,
            };
            let _ = send_frame(bf, &Frame::Reply(reply), master_for_send);
        }
    }
}

fn merge_env(base: &[(String, String)], overlay: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: HashMap<String, String> =
        base.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, v) in overlay {
        if PROTECTED_ENV.iter().any(|p| *p == k.as_str()) {
            // Silently drop; child still gets the base value. (We could
            // surface this as an error but plan §11 lists EnvProtected as
            // a per-spawn outcome, so refuse rather than silently merge for
            // protected keys — but for v1 we permit safe extension via
            // append-only for PATH and ignore others.)
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    out.into_iter().collect()
}

fn resolve_child_cwd(state: &State, child_id: &str) -> Option<String> {
    let rec = state.children.get(child_id)?;
    let path = format!("/proc/{}/cwd", rec.pid);
    std::fs::read_link(&path).ok().map(|p| p.to_string_lossy().into_owned())
}

fn resolve_child_env(state: &State, child_id: &str) -> Option<Vec<(String, String)>> {
    let rec = state.children.get(child_id)?;
    let path = format!("/proc/{}/environ", rec.pid);
    let data = std::fs::read(&path).ok()?;
    let mut env = Vec::new();
    for chunk in data.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(chunk) {
            if let Some(eq) = s.find('=') {
                env.push((s[..eq].to_string(), s[eq + 1..].to_string()));
            }
        }
    }
    Some(env)
}

fn kill_all_children(state: &mut State) {
    kill_all_children_internal(state);
}

fn kill_all_children_internal(state: &mut State) {
    for rec in state.children.values() {
        if rec.pgid > 0 {
            let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGTERM);
        }
    }
}

// Allow unused — these exist only for fd consumption discipline.
#[allow(dead_code)]
fn _drop<T>(_t: T) {}

// Silence unused import warnings on platforms without the relevant features.
#[allow(dead_code)]
fn _touch() {
}

#[allow(dead_code)]
fn op_name(op: &Op) -> &'static str {
    match op {
        Op::Hello { .. } => "Hello",
        Op::OpenShell { .. } => "OpenShell",
        Op::Spawn { .. } => "Spawn",
        Op::Write { .. } => "Write",
        Op::Resize { .. } => "Resize",
        Op::Signal { .. } => "Signal",
        Op::Wait { .. } => "Wait",
        Op::Close { .. } => "Close",
        Op::Shutdown { .. } => "Shutdown",
        Op::AddUser { .. } => "AddUser",
        Op::RemoveUser { .. } => "RemoveUser",
        Op::BindMount { .. } => "BindMount",
        Op::Unmount { .. } => "Unmount",
    }
}
