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
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::socket::{SockFlag, accept4};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, getpid};
use tokimo_package_sandbox::protocol::types::{
    ErrorCode, ErrorReply, Event, Frame, MountEntry, Op, PROTOCOL_VERSION, Reply, STREAM_CHUNK_BYTES, StdioMode,
    default_features,
};
use tokimo_package_sandbox::protocol::wire::encode_frame;
use tokimo_package_sandbox::protocol::wire::{recv_frame_seqpacket, send_frame_seqpacket};

use crate::child::{ChildKind, ChildRecord};
use crate::pty as ptymod;

/// Env vars that init protects: the user's `env_overlay` cannot override
/// these. Rationale per plan §5: bwrap injects HTTP_PROXY/etc to route the
/// AI's network traffic through the L7 audit proxy; letting a child blow
/// them away defeats audit.
const PROTECTED_ENV: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "SAFEBOX",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

const TOK_LISTENER: Token = Token(0);
const TOK_SIGFD: Token = Token(1);
/// Client tokens start at 2; per-client token = TOK_CLIENT_BASE + slot.
const TOK_CLIENT_BASE: usize = 2;
/// Per-child fd tokens start at 100; even = stdout pipe, odd = stderr pipe.
/// The numeric child slot id is encoded as `100 + slot * 2 + (is_stderr as usize)`.
const TOK_CHILD_BASE: usize = 100;

/// Transport types for the control channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// Unix SEQPACKET socket (Linux bwrap).
    SeqPacket,
    /// virtio-vsock stream socket (macOS VZ with VSOCK-capable kernel).
    Vsock,
    /// Serial console (virtio console, fd 0/1). Single pre-connected client,
    /// stream framing.
    Serial,
}

/// Per-connection state inside the init server.
pub struct ClientState {
    pub fd: OwnedFd,
    /// For Serial transport: separate write fd (stdout, fd 1). For SeqPacket
    /// and Vsock, this is None and the primary `fd` is used for both.
    pub write_fd: Option<OwnedFd>,
    /// child_ids owned by this client (for disconnect cleanup).
    pub children: HashSet<String>,
    /// Transport type for this client.
    pub transport: Transport,
    /// Streaming receive buffer (used by Serial and Vsock transports).
    pub read_buf: Vec<u8>,
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
    /// If true the listener is VSOCK (stream framing); else Unix SEQPACKET.
    pub transport: Transport,
    /// 9p-over-vsock fds kept alive for the lifetime of the session;
    /// dropping them would tear down the share. The tuple is
    /// `(aname, guest_path, fd)` so dynamic `RemoveMount` can locate
    /// and umount a previously-attached share.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub mount_fds: Vec<MountedShare>,
    /// Bwrap-mode dynamic mounts (added via `Op::AddMountFd`). Keyed by
    /// the host-supplied logical name. Tracks the mount target so
    /// `Op::RemoveMountByName` can `umount2(target, MNT_DETACH)` + rmdir.
    pub dynamic_mounts: HashMap<String, String>,
    /// Long-lived O_PATH/O_DIRECTORY fd into the bwrap-staged
    /// `/.tps_host` (host root). Opened during init startup, before
    /// `/.tps_host` is umounted+rmdir'd. Used as the dirfd for
    /// `openat()` when handling `Op::AddMountFd` so that the fd we then
    /// bind-mount belongs to a mount inside our user_ns (kernel
    /// requirement; an init_user_ns fd passed via SCM_RIGHTS would
    /// otherwise EPERM in `mount(MS_BIND)`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub host_root_fd: Option<OwnedFd>,
}

#[allow(dead_code)]
pub struct MountedShare {
    pub name: String,
    pub target: String,
    pub fd: OwnedFd,
}

impl State {
    fn alloc_slot(&mut self) -> usize {
        let slot = self.child_slots.len();
        self.child_slots.push(None);
        slot
    }

    /// Send a `Frame` to the client identified by `client_fd`, dispatching
    /// to the correct framing based on transport type.
    fn send_to_client(&self, client_fd: RawFd, frame: &Frame, fd: Option<RawFd>) {
        let client = match self.clients.get(&client_fd) {
            Some(c) => c,
            None => return,
        };
        if client.transport != Transport::SeqPacket {
            if fd.is_some() {
                eprintln!("[init] WARNING: SCM_RIGHTS fd lost (no ancillary support)");
            }
            let data = match encode_frame(frame) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[init] encode_frame: {e}");
                    return;
                }
            };
            let write_fd = client.write_fd.as_ref().map(|f| f.as_raw_fd()).unwrap_or(client_fd);
            unsafe {
                let _ = libc::write(write_fd, data.as_ptr().cast(), data.len());
            }
        } else {
            let bf = unsafe { BorrowedFd::borrow_raw(client_fd) };
            let _ = send_frame_seqpacket(bf, frame, fd);
        }
    }
}

pub fn snapshot_base_env() -> Vec<(String, String)> {
    // Filter out init's private control vars (TOKIMO_SANDBOX_CONTROL_FD,
    // TOKIMO_SANDBOX_BRINGUP_LO, TOKIMO_SANDBOX_MOUNT_SYSFS,
    // TOKIMO_SANDBOX_SECCOMP_B64, TOKIMO_SANDBOX_PRE_CHROOTED,
    // TOKIMO_SANDBOX_ALLOW_NON_PID1, TOKIMO_SANDBOX_VSOCK_PORT,
    // TOKIMO_SANDBOX_SERIAL_MODE, TOKIMO_SANDBOX_CONTROL_SOCK,
    // TOKIMO_SANDBOX_GUEST_LISTENS, ...) so they don't leak into every
    // child spawned inside the sandbox. Anything legitimate the user wants
    // visible inside the guest must come through `ConfigureParams::env`
    // and `ShellOpts::env`/`ExecOpts::env`, not the host process env.
    env::vars().filter(|(k, _)| !k.starts_with("TOKIMO_SANDBOX_")).collect()
}

pub fn run_loop(
    listener: OwnedFd,
    write_fd: Option<OwnedFd>,
    sigfd: OwnedFd,
    base_env: Vec<(String, String)>,
    transport: Transport,
) -> Result<(), String> {
    run_loop_inner(listener, write_fd, sigfd, base_env, transport, false)
}

/// Linux bwrap entry point: the `client` fd is a pre-connected SEQPACKET
/// socket (one half of a `socketpair(2)` whose other end the host kept).
/// Skips listener `accept(2)` — there is no listener.
pub fn run_loop_preconnected(client: OwnedFd, sigfd: OwnedFd, base_env: Vec<(String, String)>) -> Result<(), String> {
    run_loop_inner(client, None, sigfd, base_env, Transport::SeqPacket, true)
}

fn run_loop_inner(
    listener: OwnedFd,
    write_fd: Option<OwnedFd>,
    sigfd: OwnedFd,
    base_env: Vec<(String, String)>,
    transport: Transport,
    preconnected_seqpacket: bool,
) -> Result<(), String> {
    let mut poll = Poll::new().map_err(|e| format!("Poll::new: {e}"))?;
    let mut events = Events::with_capacity(64);

    let mut state = State {
        base_env,
        children: HashMap::new(),
        child_slots: Vec::new(),
        clients: HashMap::new(),
        client_slots: Vec::new(),
        transport,
        mount_fds: Vec::new(),
        dynamic_mounts: HashMap::new(),
        host_root_fd: None,
    };

    // Bwrap mode: open a long-lived O_PATH fd on `/.tps_host` (the
    // pre-bound host root) so we can later openat() arbitrary host
    // paths whose resulting fd lives in our user_ns mount. Then
    // umount2 + rmdir `/.tps_host` so it leaves no observable trace
    // for sandboxed processes.
    #[cfg(target_os = "linux")]
    if preconnected_seqpacket {
        let cstr = std::ffi::CString::new("/.tps_host").unwrap();
        let raw = unsafe { libc::open(cstr.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if raw < 0 {
            eprintln!(
                "[init] open(/.tps_host) failed: {} (dynamic mounts will not work)",
                std::io::Error::last_os_error()
            );
        } else {
            state.host_root_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            // We cannot umount /.tps_host here: locked-rec mounts inherited
            // from bwrap's `--ro-bind /` cannot be released without
            // CAP_SYS_ADMIN over the parent user_ns. The staging path
            // remains visible at `/.tps_host` (dot-prefix hides it from
            // default `ls`); the held O_PATH fd is what matters for
            // future `openat()` resolutions.
        }
    }

    let mut shutdown = false;

    // Serial / Vsock-client mode: register the "listener" as a pre-connected
    // client. Cowork architecture has the host listen on AF_HYPERV and the
    // guest dial in, so by the time we reach run_loop the vsock socket is
    // already a single connected stream — same shape as Serial.
    let mut listener_opt = Some(listener);
    if transport == Transport::Serial || transport == Transport::Vsock || preconnected_seqpacket {
        let l = listener_opt.take().unwrap();
        let raw = l.as_raw_fd();
        let slot = state.client_slots.len();
        let token = Token(TOK_CLIENT_BASE + slot);
        poll.registry()
            .register(&mut SourceFd(&raw), token, Interest::READABLE)
            .map_err(|e| format!("register serial client: {e}"))?;
        state.client_slots.push(Some(raw));
        state.clients.insert(
            raw,
            ClientState {
                fd: l,
                write_fd,
                children: HashSet::new(),
                transport,
                read_buf: Vec::new(),
            },
        );
    }
    if let Some(ref l) = listener_opt {
        let raw = l.as_raw_fd();
        poll.registry()
            .register(&mut SourceFd(&raw), TOK_LISTENER, Interest::READABLE)
            .map_err(|e| format!("register listener: {e}"))?;
    }

    poll.registry()
        .register(&mut SourceFd(&sigfd.as_raw_fd()), TOK_SIGFD, Interest::READABLE)
        .map_err(|e| format!("register sigfd: {e}"))?;

    while !shutdown {
        if let Err(e) = poll.poll(&mut events, Some(std::time::Duration::from_millis(2000))) {
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }
        let n_evs = events.iter().count();
        if n_evs == 0 {
            // Heartbeat: try writing a marker byte to the write fd, and log
            // poll state to kmsg so we can verify whether (a) we're being
            // woken at all and (b) writes actually leave the guest.
            if transport == Transport::Serial
                && let Some(c) = state.clients.values().next()
            {
                let wfd = c.write_fd.as_ref().map(|f| f.as_raw_fd()).unwrap_or(c.fd.as_raw_fd());
                let marker = b"HBHBHBHBHB";
                let n = unsafe { libc::write(wfd, marker.as_ptr().cast(), marker.len()) };
                let _ = n;
            }
        }

        for ev in events.iter() {
            match ev.token() {
                TOK_LISTENER => {
                    if let Some(ref l) = listener_opt
                        && let Err(e) = accept_client(l, &mut state, poll.registry())
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

fn accept_client(listener: &OwnedFd, state: &mut State, registry: &mio::Registry) -> Result<(), String> {
    let fd = accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK)
        .map_err(|e| format!("accept4: {e}"))?;
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = owned.as_raw_fd();
    // Allocate a client slot (never recycled).
    let slot = state.client_slots.len();
    let token = Token(TOK_CLIENT_BASE + slot);
    registry
        .register(&mut SourceFd(&raw), token, Interest::READABLE)
        .map_err(|e| format!("register client: {e}"))?;
    state.client_slots.push(Some(raw));
    state.clients.insert(
        raw,
        ClientState {
            fd: owned,
            write_fd: None,
            children: HashSet::new(),
            transport: state.transport,
            read_buf: Vec::new(),
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
        if let Some(rec) = state.children.get(cid)
            && rec.pgid > 0
        {
            let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGKILL);
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
        let n = unsafe { libc::read(sigfd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

fn reap_children(state: &mut State, registry: &mio::Registry) {
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

fn emit_exit(state: &mut State, registry: &mio::Registry, pid: Pid, code: i32, signal: Option<i32>) {
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
        if let Some(fd) = rec.stdout_fd.as_ref()
            && let Some(of) = owner_fd
        {
            drain_pipe(fd, &id, of, false, state);
        }
        if let Some(fd) = rec.stderr_fd.as_ref()
            && let Some(of) = owner_fd
        {
            drain_pipe(fd, &id, of, true, state);
        }
    }
    // Send Exit event to the owner client.
    if let Some(of) = owner_fd
        && let Some(client) = state.clients.get(&of)
    {
        let frame = Frame::Event(Event::Exit {
            child_id: id.clone(),
            code,
            signal,
        });
        state.send_to_client(client.fd.as_raw_fd(), &frame, None);
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

fn drain_pipe(fd: &OwnedFd, child_id: &str, owner_fd: RawFd, is_stderr: bool, state: &State) {
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
        state.send_to_client(owner_fd, &frame, None);
    }
}

fn pump_child_stream(token: Token, state: &mut State, _registry: &mio::Registry) {
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
    let Some(rec) = state.children.get(&child_id) else {
        return;
    };
    let owner_fd = rec.owner_fd;
    let fd = if is_stderr {
        rec.stderr_fd.as_ref()
    } else {
        rec.stdout_fd.as_ref()
    };
    let Some(fd) = fd else { return };
    let Some(_client) = state.clients.get(&owner_fd) else {
        return;
    };
    drain_pipe(fd, &child_id, owner_fd, is_stderr, state);
}

fn handle_client_readable(client_fd: RawFd, state: &mut State, registry: &mio::Registry) -> Result<bool, String> {
    let transport = state
        .clients
        .get(&client_fd)
        .map(|c| c.transport)
        .unwrap_or(Transport::SeqPacket);
    if transport != Transport::SeqPacket {
        return handle_client_readable_vsock(client_fd, state, registry);
    }
    loop {
        let bf = unsafe { BorrowedFd::borrow_raw(client_fd) };
        let res = recv_frame_seqpacket(bf);
        match res {
            Ok(None) => return Ok(false),
            Ok(Some((Frame::Op(op), fd))) => {
                handle_op(op, client_fd, state, registry, fd);
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

/// Read length-prefixed frames from a VSOCK / Serial (stream) client.
/// Maintains a per-client buffer and processes all complete frames.
fn handle_client_readable_vsock(client_fd: RawFd, state: &mut State, registry: &mio::Registry) -> Result<bool, String> {
    let mut tmp = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(client_fd, tmp.as_mut_ptr().cast(), tmp.len()) };
        if n == 0 {
            return Ok(false);
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            return Err(err.to_string());
        }
        if let Some(c) = state.clients.get_mut(&client_fd) {
            c.read_buf.extend_from_slice(&tmp[..n as usize]);
        } else {
            return Ok(false);
        }
    }

    // Drain all complete frames from the buffer.
    loop {
        let frame_opt = {
            let c = match state.clients.get_mut(&client_fd) {
                Some(c) => c,
                None => return Ok(false),
            };
            if c.read_buf.len() < 4 {
                None
            } else {
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&c.read_buf[..4]);
                let len = u32::from_be_bytes(len_bytes) as usize;
                if c.read_buf.len() < 4 + len {
                    None
                } else {
                    let payload: Vec<u8> = c.read_buf.drain(..4 + len).skip(4).collect();
                    Some(payload)
                }
            }
        };
        let payload = match frame_opt {
            Some(p) => p,
            None => break,
        };
        let frame: Frame = serde_json::from_slice(&payload).map_err(|e| format!("parse wire frame: {e}"))?;
        match frame {
            Frame::Op(op) => handle_op(op, client_fd, state, registry, None),
            other => eprintln!("[init] client sent non-Op frame: {other:?}"),
        }
    }
    Ok(true)
}

fn handle_op(op: Op, client_fd: RawFd, state: &mut State, registry: &mio::Registry, attached_fd: Option<OwnedFd>) {
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
            state.send_to_client(client_fd, &Frame::Reply(reply), None);
        }
        Op::OpenShell {
            id,
            argv,
            env_overlay,
            cwd,
        } => {
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
        Op::Spawn {
            id,
            argv,
            env_overlay,
            cwd,
            stdio,
            inherit_from_child,
        } => {
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
                let rec = state
                    .children
                    .get_mut(&child_id)
                    .ok_or_else(|| ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}")))?;
                let fd = rec
                    .stdin_fd
                    .as_ref()
                    .ok_or_else(|| ErrorReply::new(ErrorCode::BadRequest, "child has no stdin (PTY?)"))?;
                let mut off = 0;
                while off < bytes.len() {
                    let n = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().add(off).cast(), bytes.len() - off) };
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
            ack(state, client_fd, id, res);
        }
        Op::Resize {
            id,
            child_id,
            rows,
            cols,
        } => {
            let res = (|| -> Result<(), ErrorReply> {
                let rec = state
                    .children
                    .get(&child_id)
                    .ok_or_else(|| ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}")))?;
                let master = rec
                    .master_fd
                    .as_ref()
                    .ok_or_else(|| ErrorReply::new(ErrorCode::BadRequest, "child has no PTY"))?;
                ptymod::set_winsize(master.as_raw_fd(), rows, cols)
                    .map_err(|e| ErrorReply::new(ErrorCode::Internal, e))?;
                let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGWINCH);
                Ok(())
            })();
            ack(state, client_fd, id, res);
        }
        Op::Signal {
            id,
            child_id,
            sig,
            to_pgrp,
        } => {
            let res = (|| -> Result<(), ErrorReply> {
                let sig = Signal::try_from(sig)
                    .map_err(|_| ErrorReply::new(ErrorCode::BadRequest, format!("invalid signal {sig}")))?;
                let rec = state
                    .children
                    .get(&child_id)
                    .ok_or_else(|| ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}")))?;
                let target = if to_pgrp { rec.pgid } else { rec.pid };
                let r = if to_pgrp {
                    killpg(Pid::from_raw(target), sig)
                } else {
                    kill(Pid::from_raw(target), sig)
                };
                r.map_err(|e| ErrorReply::new(ErrorCode::Internal, format!("kill: {e}")))
            })();
            ack(state, client_fd, id, res);
        }
        Op::Wait { id, child_id: _ } => {
            // v1: synchronous Wait returns immediately if child already gone,
            // otherwise just acks (Exit event will follow when reaper sees it).
            ack(state, client_fd, id, Ok(()));
        }
        Op::Close { id, child_id } => {
            let res = (|| -> Result<(), ErrorReply> {
                let rec = state
                    .children
                    .get_mut(&child_id)
                    .ok_or_else(|| ErrorReply::new(ErrorCode::UnknownChild, format!("no such child {child_id}")))?;
                rec.stdin_fd.take(); // drop = close
                rec.master_fd.take();
                Ok(())
            })();
            ack(state, client_fd, id, res);
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
            ack(state, client_fd, id, Ok(()));
        }
        Op::AddUser {
            id,
            user_id,
            home,
            cwd,
            env_overlay,
            real_user,
        } => {
            // Validate user_id — must not contain shell metacharacters
            // because we splice it into a sh -c script when real_user.
            if !is_valid_user_id(&user_id) {
                ack(
                    state,
                    client_fd,
                    id,
                    Err(ErrorReply::new(
                        ErrorCode::BadRequest,
                        format!("invalid user_id {user_id:?}: must match [A-Za-z0-9_-]+, len 1..=32"),
                    )),
                );
                return;
            }

            // Ensure HOME exists. Idempotent: if a host directory was
            // pre-mounted here via add_mount the existing mount point
            // stays as-is.
            let _ = std::fs::create_dir_all(&home);

            // Base env for the wrapping `sh` process. We do NOT preset
            // USER/LOGNAME/HOME/PS1/MAIL here:
            //   * VM path → `runuser -l` derives them from /etc/passwd.
            //   * bwrap fallback path → the sh script `export`s them
            //     before exec'ing bash.
            // env_overlay is included so the fallback path inherits it
            // automatically; the login path re-exports it inside the
            // -c snippet because `runuser -l` clears env.
            let env = merge_env(&state.base_env, &env_overlay);
            let effective_cwd = cwd.unwrap_or_else(|| home.clone());

            // real_user=true: hybrid script. Try real account creation
            // + `runuser -l` (works on macOS VZ / Windows HCS where the
            // VM has a real root). If that fails (Linux bwrap: user ns
            // fake-root cannot write /etc/passwd), fall back to plain
            // bash with manually-injected env (USER/HOME/PS1 etc.).
            let argv = if real_user {
                // Re-export env_overlay across the runuser -l boundary
                // (login clears env). Fallback path doesn't need this
                // because env is already in the sh process's env.
                let exports: String = env_overlay
                    .iter()
                    .map(|(k, v)| format!("export {}={}; ", k, shell_quote(v)))
                    .collect();
                let home_q = shell_quote(&home);
                let cwd_q = shell_quote(&effective_cwd);
                let inner = format!("{exports}cd {cwd_q} 2>/dev/null || true; exec bash");
                let inner_q = shell_quote(&inner);
                // user_id is validated [A-Za-z0-9_-]+ so direct splice is safe.
                let script = format!(
                    "if ! getent passwd {uid} >/dev/null 2>&1; then \
                         useradd -M -d {home_q} -s /bin/bash -g 1000 -N {uid} 2>/dev/null \
                         || adduser -D -H -h {home_q} -s /bin/bash -G users {uid} 2>/dev/null \
                         || true; \
                     fi; \
                     if getent passwd {uid} >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then \
                         exec runuser -l {uid} -c {inner_q}; \
                     fi; \
                     export USER={uid} LOGNAME={uid} HOME={home_q} \
                            PS1='\\u@tokimo:\\w\\$ ' MAIL=/var/mail/{uid}; \
                     cd {cwd_q} 2>/dev/null || true; \
                     exec /bin/bash --noprofile --norc",
                    uid = user_id,
                    home_q = home_q,
                    cwd_q = cwd_q,
                    inner_q = inner_q,
                );
                vec!["/bin/sh".into(), "-c".into(), script]
            } else {
                vec!["/bin/bash".into(), "--noprofile".into(), "--norc".into()]
            };

            spawn_child_inner(
                client_fd,
                state,
                registry,
                id,
                argv,
                env,
                Some(effective_cwd),
                StdioMode::Pipes,
                ChildKind::Shell,
            );
        }
        Op::RemoveUser { id, user_id } => {
            // Best-effort: SIGKILL every shell whose argv mentions this
            // user_id (we don't track per-user ownership in init state),
            // plus userdel if the account exists. The host already knows
            // which child_ids belong to which user via add_user replies,
            // so the canonical cleanup path is host-driven Op::Signal +
            // RemoveUser; this op is the safety net.
            let child_ids: Vec<String> = state
                .children
                .iter()
                .filter(|(_, c)| c.owner_fd == client_fd)
                .map(|(cid, _)| cid.clone())
                .collect();
            for cid in &child_ids {
                if let Some(rec) = state.children.get(cid)
                    && rec.pgid > 0
                {
                    let _ = killpg(Pid::from_raw(rec.pgid), Signal::SIGKILL);
                }
            }
            // Best-effort userdel — ignore errors (account may not have
            // been created in env-only mode).
            if is_valid_user_id(&user_id) {
                let _ = std::process::Command::new("/usr/sbin/userdel")
                    .arg("-f")
                    .arg(&user_id)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            ack(state, client_fd, id, Ok(()));
        }
        Op::BindMount {
            id,
            source,
            target,
            read_only,
        } => {
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
                let rc = unsafe {
                    libc::mount(
                        src.as_ptr(),
                        tgt.as_ptr(),
                        std::ptr::null::<libc::c_char>(),
                        flags,
                        std::ptr::null::<libc::c_void>(),
                    )
                };
                if rc != 0 {
                    return Err(ErrorReply::new(
                        ErrorCode::Internal,
                        format!("mount {source} -> {target}: {}", std::io::Error::last_os_error()),
                    ));
                }
                Ok(())
            })();
            ack(state, client_fd, id, res);
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
            ack(state, client_fd, id, res);
        }
        Op::MountManifest { id, entries } => {
            handle_mount_manifest(state, client_fd, id, entries);
        }
        Op::AddMount { id, entry } => {
            handle_add_mount(state, client_fd, id, entry);
        }
        Op::RemoveMount { id, name } => {
            handle_remove_mount(state, client_fd, id, name);
        }
        Op::AddMountFd {
            id,
            name,
            host_path,
            target,
            read_only,
        } => {
            handle_add_mount_fd(state, client_fd, id, name, host_path, target, read_only);
            let _ = attached_fd;
        }
        Op::RemoveMountByName { id, name } => {
            handle_remove_mount_by_name(state, client_fd, id, name);
        }
    }
}

fn ack(state: &State, client_fd: RawFd, id: String, res: Result<(), ErrorReply>) {
    let reply = match res {
        Ok(()) => Reply::Ack {
            id,
            ok: true,
            error: None,
        },
        Err(e) => Reply::Ack {
            id,
            ok: false,
            error: Some(e),
        },
    };
    state.send_to_client(client_fd, &Frame::Reply(reply), None);
}

/// Handle V2 `MountManifest`: dial each share's vsock port from the guest
/// (the host has unique AF_HYPERV listeners ready and waiting), mount the
/// resulting fd as a 9p2000.L share at `entry.guest_path`, and stash the
/// fd in `state.mount_fds` so the kernel keeps the channel open. The
/// reply tells the host whether every entry succeeded; on partial
/// failure the failing index is reported and the partial mounts are
/// left in place (caller tears the session down).
#[cfg(target_os = "linux")]
fn handle_mount_manifest(state: &mut State, client_fd: RawFd, id: String, entries: Vec<MountEntry>) {
    let mut failing_index: Option<u32> = None;
    let mut error: Option<ErrorReply> = None;

    for (i, entry) in entries.iter().enumerate() {
        match mount_one(entry) {
            Ok(fd) => {
                state.mount_fds.push(MountedShare {
                    name: entry.aname.clone(),
                    target: entry.guest_path.clone(),
                    fd,
                });
            }
            Err(msg) => {
                failing_index = Some(i as u32);
                error = Some(ErrorReply::new(ErrorCode::Internal, msg));
                break;
            }
        }
    }

    let ok = error.is_none();
    let reply = Reply::MountManifest {
        id,
        ok,
        failing_index,
        error,
    };
    state.send_to_client(client_fd, &Frame::Reply(reply), None);
}

#[cfg(not(target_os = "linux"))]
fn handle_mount_manifest(state: &mut State, client_fd: RawFd, id: String, _entries: Vec<MountEntry>) {
    let reply = Reply::MountManifest {
        id,
        ok: false,
        failing_index: Some(0),
        error: Some(ErrorReply::new(ErrorCode::Internal, "MountManifest is Linux-only")),
    };
    state.send_to_client(client_fd, &Frame::Reply(reply), None);
}

#[cfg(target_os = "linux")]
fn handle_add_mount(state: &mut State, client_fd: RawFd, id: String, entry: MountEntry) {
    if state.mount_fds.iter().any(|m| m.name == entry.aname) {
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::BadRequest,
                format!("share {:?} already mounted", entry.aname),
            )),
        );
        return;
    }
    match mount_one(&entry) {
        Ok(fd) => {
            state.mount_fds.push(MountedShare {
                name: entry.aname.clone(),
                target: entry.guest_path.clone(),
                fd,
            });
            ack(state, client_fd, id, Ok(()));
        }
        Err(msg) => {
            ack(state, client_fd, id, Err(ErrorReply::new(ErrorCode::Internal, msg)));
        }
    }
}

#[cfg(target_os = "linux")]
fn handle_remove_mount(state: &mut State, client_fd: RawFd, id: String, name: String) {
    let idx = match state.mount_fds.iter().position(|m| m.name == name) {
        Some(i) => i,
        None => {
            ack(
                state,
                client_fd,
                id,
                Err(ErrorReply::new(
                    ErrorCode::BadRequest,
                    format!("no such share: {name:?}"),
                )),
            );
            return;
        }
    };
    let entry = state.mount_fds.remove(idx);
    let target_str = entry.target.clone();
    let target_c = std::ffi::CString::new(target_str.as_str()).unwrap_or_default();
    // MNT_DETACH = lazy unmount; the kernel finalises once all refs go away.
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    drop(entry); // closes fd
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::Internal,
                format!("umount2({target_str}): {err}"),
            )),
        );
        return;
    }
    // Best-effort: remove the now-empty mountpoint so a subsequent
    // `ls <guest_path>` returns ENOENT.
    let _ = std::fs::remove_dir(&target_str);
    ack(state, client_fd, id, Ok(()));
}

#[cfg(not(target_os = "linux"))]
fn handle_add_mount(state: &mut State, client_fd: RawFd, id: String, _entry: MountEntry) {
    ack(
        state,
        client_fd,
        id,
        Err(ErrorReply::new(ErrorCode::Internal, "AddMount is Linux-only")),
    );
}

#[cfg(not(target_os = "linux"))]
fn handle_remove_mount(state: &mut State, client_fd: RawFd, id: String, _name: String) {
    ack(
        state,
        client_fd,
        id,
        Err(ErrorReply::new(ErrorCode::Internal, "RemoveMount is Linux-only")),
    );
}

#[cfg(target_os = "linux")]
fn handle_add_mount_fd(
    state: &mut State,
    client_fd: RawFd,
    id: String,
    name: String,
    host_path: String,
    target: String,
    read_only: bool,
) {
    if state.dynamic_mounts.contains_key(&name) {
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::BadRequest,
                format!("dynamic mount {name:?} already exists"),
            )),
        );
        return;
    }
    let host_root = match state.host_root_fd.as_ref() {
        Some(f) => f.as_raw_fd(),
        None => {
            ack(
                state,
                client_fd,
                id,
                Err(ErrorReply::new(
                    ErrorCode::Internal,
                    "host_root_fd unavailable (init started without /.tps_host)",
                )),
            );
            return;
        }
    };
    // Strip leading '/'s so openat() treats the path as relative.
    let rel = host_path.trim_start_matches('/');
    let rel_for_open: &str = if rel.is_empty() { "." } else { rel };
    let rel_c = match std::ffi::CString::new(rel_for_open) {
        Ok(c) => c,
        Err(e) => {
            ack(
                state,
                client_fd,
                id,
                Err(ErrorReply::new(ErrorCode::BadRequest, format!("host_path NUL: {e}"))),
            );
            return;
        }
    };
    let src_fd = unsafe {
        libc::openat(
            host_root,
            rel_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if src_fd < 0 {
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::Internal,
                format!(
                    "openat(host_root, {rel_for_open:?}): {}",
                    std::io::Error::last_os_error()
                ),
            )),
        );
        return;
    }
    let src_owned = unsafe { OwnedFd::from_raw_fd(src_fd) };

    if let Err(e) = std::fs::create_dir_all(&target) {
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::Internal,
                format!("create_dir_all {target}: {e}"),
            )),
        );
        return;
    }
    let src_proc = format!("/proc/self/fd/{}", src_owned.as_raw_fd());
    let src_c = std::ffi::CString::new(src_proc.as_str()).unwrap();
    let tgt_c = std::ffi::CString::new(target.as_str()).unwrap();
    let none_c = std::ffi::CString::new("").unwrap();
    // Source mount is the bwrap-staged `--bind /` (rw). Locked flags
    // inherited from the user_ns staging are MS_NOSUID|MS_NODEV (bwrap
    // applies these to all binds), so we must include them. The bind
    // itself is rw; we remount-RO afterward if the caller asked for it.
    let base_flags = libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV;
    let flags = base_flags as libc::c_ulong;
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            tgt_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::Internal,
                format!("mount(bind) {src_proc}->{target}: {}", std::io::Error::last_os_error()),
            )),
        );
        return;
    }
    drop(src_owned);
    if read_only {
        let remount_flags =
            (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_RDONLY) as libc::c_ulong;
        let rc = unsafe {
            libc::mount(
                none_c.as_ptr(),
                tgt_c.as_ptr(),
                std::ptr::null(),
                remount_flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            let _ = unsafe { libc::umount2(tgt_c.as_ptr(), libc::MNT_DETACH) };
            ack(
                state,
                client_fd,
                id,
                Err(ErrorReply::new(
                    ErrorCode::Internal,
                    format!("remount-ro {target}: {}", std::io::Error::last_os_error()),
                )),
            );
            return;
        }
    }
    state.dynamic_mounts.insert(name, target);
    ack(state, client_fd, id, Ok(()));
}

#[cfg(target_os = "linux")]
fn handle_remove_mount_by_name(state: &mut State, client_fd: RawFd, id: String, name: String) {
    let target = match state.dynamic_mounts.remove(&name) {
        Some(t) => t,
        None => {
            ack(
                state,
                client_fd,
                id,
                Err(ErrorReply::new(
                    ErrorCode::BadRequest,
                    format!("no such dynamic mount: {name:?}"),
                )),
            );
            return;
        }
    };
    let target_c = std::ffi::CString::new(target.as_str()).unwrap_or_default();
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        ack(
            state,
            client_fd,
            id,
            Err(ErrorReply::new(
                ErrorCode::Internal,
                format!("umount2({target}): {err}"),
            )),
        );
        return;
    }
    let _ = std::fs::remove_dir(&target);
    ack(state, client_fd, id, Ok(()));
}

#[cfg(not(target_os = "linux"))]
fn handle_add_mount_fd(
    state: &mut State,
    client_fd: RawFd,
    id: String,
    _name: String,
    _host_path: String,
    _target: String,
    _read_only: bool,
) {
    ack(
        state,
        client_fd,
        id,
        Err(ErrorReply::new(ErrorCode::Internal, "AddMountFd is Linux-only")),
    );
}

#[cfg(not(target_os = "linux"))]
fn handle_remove_mount_by_name(state: &mut State, client_fd: RawFd, id: String, _name: String) {
    ack(
        state,
        client_fd,
        id,
        Err(ErrorReply::new(ErrorCode::Internal, "RemoveMountByName is Linux-only")),
    );
}

#[cfg(target_os = "linux")]
fn mount_one(entry: &MountEntry) -> Result<OwnedFd, String> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};
    use std::time::{Duration, Instant};

    // Blocking AF_VSOCK dial — unlike `connect_vsock` in main.rs we do NOT
    // toggle O_NONBLOCK afterwards because the 9p kernel fs uses the fd
    // synchronously and would not appreciate EAGAIN on every transaction.
    let addr = VsockAddr::new(libc::VMADDR_CID_HOST, entry.vsock_port);
    let deadline = Instant::now() + Duration::from_secs(30);
    let fd: OwnedFd = loop {
        let f = socket(AddressFamily::Vsock, SockType::Stream, SockFlag::SOCK_CLOEXEC, None)
            .map_err(|e| format!("socket(AF_VSOCK): {e}"))?;
        match connect(f.as_raw_fd(), &addr) {
            Ok(()) => break f,
            Err(e) => {
                drop(f);
                if Instant::now() >= deadline {
                    return Err(format!("connect VSOCK port {}: {e}", entry.vsock_port));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };

    std::fs::create_dir_all(&entry.guest_path).map_err(|e| format!("mkdir {}: {e}", entry.guest_path))?;

    let mut flags: libc::c_ulong = (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong;
    if entry.read_only {
        flags |= libc::MS_RDONLY as libc::c_ulong;
    }
    let raw = fd.as_raw_fd();
    let data = format!(
        "trans=fd,rfdno={raw},wfdno={raw},msize=262144,aname={},cache=mmap,version=9p2000.L",
        entry.aname
    );

    mount_fs("nodev", &entry.guest_path, "9p", flags, &data)?;
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn mount_fs(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> Result<(), String> {
    let src = std::ffi::CString::new(source).map_err(|e| format!("source CString: {e}"))?;
    let tgt = std::ffi::CString::new(target).map_err(|e| format!("target CString: {e}"))?;
    let fst = std::ffi::CString::new(fstype).map_err(|e| format!("fstype CString: {e}"))?;
    let dat = std::ffi::CString::new(data).map_err(|e| format!("data CString: {e}"))?;
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            flags,
            dat.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(format!(
            "mount {source} on {target}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
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
    let slot = state.alloc_slot();
    let child_id = format!("c{}", slot + 1);
    let cwd_ref = cwd.as_deref();

    // Check if we can use SCM_RIGHTS for the master fd.
    let client_is_stream = state
        .clients
        .get(&client_fd)
        .map(|c| c.transport != Transport::SeqPacket)
        .unwrap_or(false);

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
            state.send_to_client(client_fd, &Frame::Reply(reply), None);
        }
        Ok(spawned) => {
            // For Pty mode over stream transport (VSOCK, Serial): the master
            // fd can't be sent via SCM_RIGHTS. Instead, we bridge I/O through
            // the protocol: register the master fd for reading (output pumping)
            // and set stdin_fd to the master so Write ops go to the PTY.
            let (effective_stdout, effective_stdin, effective_master, send_fd) =
                if let Some(mfd) = spawned.master_fd.as_ref().filter(|_| client_is_stream) {
                    // Dup the master for reading — register with mio as stdout.
                    let dup_fd = unsafe { libc::dup(mfd.as_raw_fd()) };
                    if dup_fd < 0 {
                        state.child_slots[slot] = None;
                        let reply = Reply::Spawn {
                            id,
                            ok: false,
                            child_id: None,
                            pid: None,
                            error: Some(ErrorReply::new(
                                ErrorCode::Internal,
                                format!("dup master fd: {}", std::io::Error::last_os_error()),
                            )),
                        };
                        state.send_to_client(client_fd, &Frame::Reply(reply), None);
                        return;
                    }
                    let dup_owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
                    // O_NONBLOCK is REQUIRED: the mio drain loop calls
                    // libc::read in a tight loop and breaks only on n<=0.
                    // A blocking master fd would hang inside drain_pipe
                    // after exhausting available bytes, freezing the
                    // single-threaded init request loop.
                    unsafe {
                        let flags = libc::fcntl(dup_fd, libc::F_GETFL);
                        if flags >= 0 {
                            libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                        }
                    }
                    // Use master as stdin so Write ops go to PTY input.
                    let mfd_dup2 = unsafe { libc::dup(mfd.as_raw_fd()) };
                    let stdin_owned = if mfd_dup2 >= 0 {
                        Some(unsafe { OwnedFd::from_raw_fd(mfd_dup2) })
                    } else {
                        None
                    };
                    (Some(dup_owned), stdin_owned, spawned.master_fd, None)
                } else {
                    // SeqPacket or Pipes: send master fd via SCM_RIGHTS as usual.
                    let send_fd = spawned.master_fd.as_ref().map(|f| f.as_raw_fd());
                    (spawned.stdout_fd, spawned.stdin_fd, spawned.master_fd, send_fd)
                };

            // Register pumpable fds with mio.
            if let Some(fd) = effective_stdout.as_ref() {
                let tok = Token(TOK_CHILD_BASE + slot * 2);
                let _ = registry.register(&mut SourceFd(&fd.as_raw_fd()), tok, Interest::READABLE);
            }
            if let Some(fd) = spawned.stderr_fd.as_ref() {
                let tok = Token(TOK_CHILD_BASE + slot * 2 + 1);
                let _ = registry.register(&mut SourceFd(&fd.as_raw_fd()), tok, Interest::READABLE);
            }
            let pid = spawned.pid;
            state.child_slots[slot] = Some(child_id.clone());
            let rec = ChildRecord {
                pid,
                pgid: pid,
                slot,
                kind,
                stdin_fd: effective_stdin,
                stdout_fd: effective_stdout,
                stderr_fd: spawned.stderr_fd,
                master_fd: effective_master,
                shutdown_pending: false,
                owner_fd: client_fd,
            };
            state.children.insert(child_id.clone(), rec);
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
            state.send_to_client(client_fd, &Frame::Reply(reply), send_fd);
        }
    }
}

/// Validate `user_id`: only ASCII letters, digits, underscore, and dash;
/// length 1..=32. Used by `Op::AddUser`/`Op::RemoveUser` because the id
/// is interpolated into a `sh -c` script.
fn is_valid_user_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// POSIX single-quote escape, used for splicing untrusted paths into a
/// `sh -c` script body.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn merge_env(base: &[(String, String)], overlay: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: HashMap<String, String> = base.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, v) in overlay {
        if PROTECTED_ENV.contains(&k.as_str()) {
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
    // Prefer the dynamic env dump written by bash after each exec
    // (`export -p > /.tps_env_<pid>`). This captures env vars set via
    // `export` at runtime, which /proc/<pid>/environ (frozen at execve) misses.
    let dump_path = format!("/.tps_env_{}", rec.pid);
    if let Ok(data) = std::fs::read_to_string(&dump_path)
        && let Some(env) = parse_export_p(&data)
    {
        return Some(env);
    }
    // Fall back to /proc/<pid>/environ (snapshot from execve time).
    let path = format!("/proc/{}/environ", rec.pid);
    let data = std::fs::read(&path).ok()?;
    Some(parse_proc_environ(&data))
}

/// Parse `export -p` output: `declare -x KEY="value"` lines.
/// Some vars have no value (e.g. `declare -x OLDPWD`); those are skipped.
fn parse_export_p(data: &str) -> Option<Vec<(String, String)>> {
    let mut env = Vec::new();
    for line in data.lines() {
        let line = line.trim();
        if !line.starts_with("declare -x ") {
            continue;
        }
        let rest = &line["declare -x ".len()..];
        let Some(eq) = rest.find('=') else {
            continue; // variable with no value, skip
        };
        let key = rest[..eq].to_string();
        let mut val = rest[eq + 1..].to_string();
        // Unquote: remove surrounding double or single quotes.
        if val.len() >= 2 {
            let first = val.as_bytes()[0];
            let last = val.as_bytes()[val.len() - 1];
            if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                val = val[1..val.len() - 1].to_string();
            }
        }
        env.push((key, val));
    }
    if env.is_empty() { None } else { Some(env) }
}

/// Parse NUL-separated `KEY=VALUE` pairs from /proc/<pid>/environ.
fn parse_proc_environ(data: &[u8]) -> Vec<(String, String)> {
    let mut env = Vec::new();
    for chunk in data.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(chunk)
            && let Some(eq) = s.find('=')
        {
            env.push((s[..eq].to_string(), s[eq + 1..].to_string()));
        }
    }
    env
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
fn _touch() {}

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
        Op::MountManifest { .. } => "MountManifest",
        Op::AddMount { .. } => "AddMount",
        Op::RemoveMount { .. } => "RemoveMount",
        Op::AddMountFd { .. } => "AddMountFd",
        Op::RemoveMountByName { .. } => "RemoveMountByName",
    }
}
