//! Host-Exec Bridge: lets guest commands transparently invoke a
//! host-side callback.
//!
//! ## How it works
//!
//! 1. Caller registers a set of "bridged" command names via
//!    [`crate::Sandbox::add_host_command`] /
//!    [`crate::Sandbox::set_host_commands`].
//! 2. Init (the guest PID 1) creates a hardlink at
//!    `/run/tokimo/host-bridge/<name>` pointing at the
//!    `tokimo-host-exec` guest binary, and prepends
//!    `/run/tokimo/host-bridge` to `PATH` for newly-spawned children.
//! 3. When a child invokes `<name>` from `PATH`, the kernel execs
//!    `tokimo-host-exec` (with `argv[0]` == the link basename). The
//!    binary connects back to the host over a platform-specific
//!    transport (Linux Unix-listener → SCM_RIGHTS relay; macOS vsock;
//!    Windows AF_HYPERV → service-side `DuplicateHandle` into the
//!    library process) and speaks the [`crate::host_exec_protocol`]
//!    wire protocol.
//! 4. Host-side, [`HostExecBridge::handle_one`] invokes the
//!    user-supplied [`HostExecCallback`] with a [`HostExecCtx`]
//!    describing the request. The callback returns a
//!    [`HostExecAction`] which the bridge executes (currently:
//!    `RunOnHost` spawns a process on the host and pumps stdio
//!    bidirectionally; `Reject` returns a non-zero exit code).
//!
//! ## Code layout
//!
//! `handle_one` and `run_on_host` are generic over [`BridgeStream`]
//! so the same per-connection state machine serves all three
//! platforms (the `UnixStream` path on Linux/macOS and the
//! `TcpStream` path on Windows). Platform-specific transport plumbing
//! lives in [`linux_relay`] and [`macos_listener`]; on Windows the
//! library spawns a subscriber thread in `start_vm` that wraps each
//! handle handed back by the service.
//!
//! Wire protocol: see [`crate::host_exec_protocol`].

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::api::{HostExecAction, HostExecCallback, HostExecCtx};
use crate::host_exec_protocol::wire::blocking::{read_frame, write_frame};
use crate::host_exec_protocol::{Frame, HOST_EXEC_PROTOCOL_VERSION};

pub mod protocol;
pub mod transport;

#[cfg(target_os = "linux")]
mod linux_relay;

#[cfg(target_os = "macos")]
mod macos_listener;

// ---------------------------------------------------------------------------
// Stream abstraction shared by all platforms
// ---------------------------------------------------------------------------

/// A bidirectional byte stream that can be cloned (so reader/writer
/// halves can run on independent threads) and shut down. Both
/// [`std::os::unix::net::UnixStream`] (Linux/macOS) and
/// [`std::net::TcpStream`] (Windows hvsock-as-Winsock) satisfy this
/// trait.
pub trait BridgeStream: Read + Write + Send + Sized + 'static {
    fn try_clone(&self) -> std::io::Result<Self>;
    fn shutdown_both(&self) -> std::io::Result<()>;
}

#[cfg(unix)]
impl BridgeStream for std::os::unix::net::UnixStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        std::os::unix::net::UnixStream::try_clone(self)
    }
    fn shutdown_both(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
}

#[cfg(target_os = "windows")]
impl BridgeStream for std::net::TcpStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        std::net::TcpStream::try_clone(self)
    }
    fn shutdown_both(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
}

// ---------------------------------------------------------------------------
// Platform-specific signal & exit-status helpers
// ---------------------------------------------------------------------------

#[inline]
fn deliver_signal(_pid: u32, _sig: i32) {
    #[cfg(unix)]
    // SAFETY: kill() is safe for any pid; failure is ignored.
    unsafe {
        libc::kill(_pid as i32, _sig);
    }
    // Windows has no equivalent of POSIX signals; Signal frames are
    // silently dropped (the remote shell that produced them is the
    // only thing affected).
}

#[inline]
fn extract_exit(status: &std::process::ExitStatus) -> (i32, Option<i32>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        (status.code().unwrap_or(-1), status.signal())
    }
    #[cfg(not(unix))]
    {
        (status.code().unwrap_or(-1), None)
    }
}

// ---------------------------------------------------------------------------
// HostExecBridge
// ---------------------------------------------------------------------------

/// Host-side bridge: owns the user callback and serves connections
/// from `tokimo-host-exec` clients running in the guest.
pub struct HostExecBridge {
    callback: Arc<RwLock<HostExecCallback>>,
    /// Shutdown flag for any listener / relay thread that's been
    /// associated with this bridge.
    shutdown: Arc<AtomicBool>,
}

impl HostExecBridge {
    pub fn new(callback: HostExecCallback) -> Self {
        Self {
            callback: Arc::new(RwLock::new(callback)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Replace the registered callback (used by
    /// [`crate::Sandbox::on_host_exec`] when called after `start_vm`).
    pub fn set_callback(&self, cb: HostExecCallback) {
        if let Ok(mut g) = self.callback.write() {
            *g = cb;
        }
    }

    /// Snapshot the current callback (cheap clone of the `Arc`).
    pub(crate) fn callback_snapshot(&self) -> HostExecCallback {
        self.callback.read().expect("host-exec callback poisoned").clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub(crate) fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Linux: start the SCM_RIGHTS relay reader thread.
    ///
    /// `relay_fd` is the host end of the SEQPACKET socketpair shared
    /// with init; init sends each accepted client fd via `sendmsg`
    /// with `SCM_RIGHTS`. The reader spawns one worker thread per
    /// received fd.
    #[cfg(target_os = "linux")]
    pub fn start_linux_relay(self: &Arc<Self>, relay_fd: std::os::fd::OwnedFd) {
        linux_relay::start(self.clone(), relay_fd);
    }

    /// macOS: start the vsock accept loop.
    #[cfg(target_os = "macos")]
    pub fn start_macos_listener(
        self: &Arc<Self>,
        listener: arcbox_vz::VirtioSocketListener,
        runtime: std::sync::Arc<tokio::runtime::Runtime>,
    ) -> std::io::Result<()> {
        macos_listener::start(self.clone(), listener, runtime)
    }

    /// Drive a single host-exec connection through the protocol state
    /// machine. Generic over the transport stream type so all three
    /// platforms share this code.
    pub fn handle_one<S: BridgeStream>(self: &Arc<Self>, mut rw: S) {
        // Hello handshake.
        let hello = match read_frame(&mut rw) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("host-exec: read hello failed: {e}");
                return;
            }
        };
        let client_proto = match hello {
            Frame::Hello { protocol } => protocol,
            other => {
                let _ = write_frame(
                    &mut rw,
                    &Frame::HelloAck {
                        protocol: HOST_EXEC_PROTOCOL_VERSION,
                        ok: false,
                        error: Some(format!("expected Hello, got {other:?}")),
                    },
                );
                return;
            }
        };
        let ack = if client_proto == HOST_EXEC_PROTOCOL_VERSION {
            Frame::HelloAck {
                protocol: HOST_EXEC_PROTOCOL_VERSION,
                ok: true,
                error: None,
            }
        } else {
            Frame::HelloAck {
                protocol: HOST_EXEC_PROTOCOL_VERSION,
                ok: false,
                error: Some(format!(
                    "host-exec protocol mismatch: client={client_proto} host={HOST_EXEC_PROTOCOL_VERSION}"
                )),
            }
        };
        if let Err(e) = write_frame(&mut rw, &ack) {
            tracing::warn!("host-exec: write hello ack failed: {e}");
            return;
        }
        if !matches!(ack, Frame::HelloAck { ok: true, .. }) {
            return;
        }

        // Spawn frame.
        let spawn = match read_frame(&mut rw) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("host-exec: read spawn failed: {e}");
                return;
            }
        };
        let (argv, env, cwd, _pty) = match spawn {
            Frame::Spawn { argv, env, cwd, pty } => (argv, env, cwd, pty),
            other => {
                let _ = write_frame(
                    &mut rw,
                    &Frame::SpawnAck {
                        ok: false,
                        error: Some(format!("expected Spawn, got {other:?}")),
                    },
                );
                return;
            }
        };

        let cb = self.callback_snapshot();
        let ctx = HostExecCtx {
            command: argv.first().cloned().unwrap_or_default(),
            argv: argv.clone(),
            env: env.clone(),
            cwd: cwd.clone(),
        };
        let action = (cb)(ctx);

        match action {
            HostExecAction::Reject { exit_code, message } => {
                // SpawnAck must come first — guest read_frame strictly expects it
                // as the first reply after Spawn. Stderr before SpawnAck is treated
                // as "unexpected spawn reply" and the message bytes get Debug-printed
                // as a raw Vec<u8>.
                let _ = write_frame(&mut rw, &Frame::SpawnAck { ok: true, error: None });
                if let Some(msg) = message.as_ref() {
                    let _ = write_frame(&mut rw, &Frame::Stderr(msg.as_bytes().to_vec()));
                }
                let _ = write_frame(
                    &mut rw,
                    &Frame::Exit {
                        code: exit_code,
                        signal: None,
                    },
                );
            }
            HostExecAction::RunOnHost {
                argv: run_argv,
                env: run_env,
                cwd: run_cwd,
            } => {
                let _ = write_frame(&mut rw, &Frame::SpawnAck { ok: true, error: None });
                run_on_host(rw, run_argv, run_env, run_cwd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// run_on_host: spawn a host-side child and pump stdio over `rw`
// ---------------------------------------------------------------------------

fn run_on_host<S: BridgeStream>(rw: S, argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String>) {
    use std::process::{Command, Stdio};

    let read_half = match rw.try_clone() {
        Ok(c) => c,
        Err(e) => {
            let mut w = rw;
            let _ = write_frame(
                &mut w,
                &Frame::Stderr(format!("host-exec: dup failed: {e}\n").into_bytes()),
            );
            let _ = write_frame(
                &mut w,
                &Frame::Exit {
                    code: 127,
                    signal: None,
                },
            );
            return;
        }
    };
    let write_half = rw;

    if argv.is_empty() {
        let mut w = write_half;
        let _ = write_frame(&mut w, &Frame::Stderr(b"host-exec: empty argv\n".to_vec()));
        let _ = write_frame(
            &mut w,
            &Frame::Exit {
                code: 127,
                signal: None,
            },
        );
        return;
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    for (k, v) in &env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd.as_deref() {
        cmd.current_dir(d);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let mut w = write_half;
            let _ = write_frame(
                &mut w,
                &Frame::Stderr(format!("host-exec: spawn failed: {e}\n").into_bytes()),
            );
            let _ = write_frame(
                &mut w,
                &Frame::Exit {
                    code: 127,
                    signal: None,
                },
            );
            return;
        }
    };
    tracing::trace!("host-exec: spawned host pid={} argv={:?}", child.id(), argv);

    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Writes to the stream are serialized via Mutex<S>. Reads happen
    // on their own clone, so reader/writer never contend.
    let write_arc = Arc::new(Mutex::new(write_half));

    // Reader thread: forward guest Stdin/Signal frames to the child.
    let stdin_arc = Arc::new(Mutex::new(stdin));
    let stdin_for_reader = stdin_arc.clone();
    let child_id = child.id();
    let mut read_half_owned = read_half;
    let reader = std::thread::Builder::new()
        .name("host-exec-reader".into())
        .spawn(move || {
            while let Ok(frame) = read_frame(&mut read_half_owned) {
                match frame {
                    Frame::Stdin(data) => {
                        if data.is_empty() {
                            *stdin_for_reader.lock().expect("stdin poisoned") = None;
                        } else {
                            let mut g = stdin_for_reader.lock().expect("stdin poisoned");
                            if let Some(s) = g.as_mut()
                                && s.write_all(&data).is_err()
                            {
                                *g = None;
                            }
                        }
                    }
                    Frame::Signal { sig } => deliver_signal(child_id, sig),
                    _ => {}
                }
            }
        })
        .expect("spawn host-exec-reader");

    // Stdout pump.
    let write_for_stdout = write_arc.clone();
    let stdout_pump = stdout.map(|mut s| {
        std::thread::Builder::new()
            .name("host-exec-stdout".into())
            .spawn(move || {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut g = write_for_stdout.lock().expect("write poisoned");
                            if write_frame(&mut *g, &Frame::Stdout(buf[..n].to_vec())).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("spawn host-exec-stdout")
    });

    // Stderr pump.
    let write_for_stderr = write_arc.clone();
    let stderr_pump = stderr.map(|mut s| {
        std::thread::Builder::new()
            .name("host-exec-stderr".into())
            .spawn(move || {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut g = write_for_stderr.lock().expect("write poisoned");
                            if write_frame(&mut *g, &Frame::Stderr(buf[..n].to_vec())).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("spawn host-exec-stderr")
    });

    let status = child.wait();

    if let Some(t) = stdout_pump {
        let _ = t.join();
    }
    if let Some(t) = stderr_pump {
        let _ = t.join();
    }

    let (code, sig) = match status {
        Ok(s) => extract_exit(&s),
        Err(_) => (-1, None),
    };
    tracing::trace!("host-exec: child exited code={code} sig={sig:?}");
    {
        let mut g = write_arc.lock().expect("write poisoned");
        let _ = write_frame(&mut *g, &Frame::Exit { code, signal: sig });
        // Shut down the write side so the peer's reader sees EOF, and
        // also so our own reader thread (which uses the cloned
        // descriptor) sees EOF on the recv side.
        let _ = g.shutdown_both();
    }
    let _ = reader.join();
}
