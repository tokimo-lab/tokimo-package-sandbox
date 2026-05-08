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
//!    binary connects back to the host over Linux Unix-listener →
//!    SCM_RIGHTS relay (or vsock on macOS) and speaks the
//!    [`crate::host_exec_protocol`] wire protocol.
//! 4. Host-side, [`HostExecBridge::handle_one`] invokes the
//!    user-supplied [`HostExecCallback`] with a [`HostExecCtx`]
//!    describing the request. The callback returns a
//!    [`HostExecAction`] which the bridge executes (currently:
//!    `RunOnHost` spawns a process on the host and pumps stdio
//!    bidirectionally; `Reject` returns a non-zero exit code).
//!
//! Wire protocol: see [`crate::host_exec_protocol`].

use std::sync::{Arc, RwLock};

use crate::api::{HostExecAction, HostExecCallback, HostExecCtx};

pub mod transport;

#[cfg(target_os = "linux")]
mod linux_relay;

#[cfg(target_os = "macos")]
mod macos_listener;

/// Host-side bridge: owns the user callback and serves connections
/// from `tokimo-host-exec` clients running in the guest.
pub struct HostExecBridge {
    callback: Arc<RwLock<HostExecCallback>>,
    /// Shutdown flag for the listener thread(s).
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl HostExecBridge {
    pub fn new(callback: HostExecCallback) -> Self {
        Self {
            callback: Arc::new(RwLock::new(callback)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        self.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn shutdown_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Linux: start the SCM_RIGHTS relay reader thread.
    ///
    /// `relay_fd` is the host end of the SEQPACKET socketpair shared
    /// with init; init sends each accepted client fd via `sendmsg`
    /// with `SCM_RIGHTS`. The reader spawns one worker thread per
    /// received fd that calls [`HostExecBridge::handle_one`].
    #[cfg(target_os = "linux")]
    pub fn start_linux_relay(self: &Arc<Self>, relay_fd: std::os::fd::OwnedFd) {
        linux_relay::start(self.clone(), relay_fd);
    }

    /// macOS: start the vsock listener using the pre-allocated
    /// `VirtioSocketListener` from the booted VM. Spawns one worker
    /// thread per accepted connection via `handle_one`.
    #[cfg(target_os = "macos")]
    pub fn start_vsock_listener(
        self: &Arc<Self>,
        listener: arcbox_vz::VirtioSocketListener,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> std::io::Result<()> {
        macos_listener::start(self.clone(), listener, runtime)
    }

    /// Drive a single client connection to completion. Reads the
    /// `Hello` + `Spawn` frames, invokes the callback, executes the
    /// returned [`HostExecAction`], and pumps stdio until exit.
    #[cfg(unix)]
    pub fn handle_one(self: &Arc<Self>, rw: std::os::unix::net::UnixStream) {
        // Split into separate read/write halves via dup so that the
        // reader thread blocking on recv does not block writers.
        let mut rw = rw;
        use crate::host_exec_protocol::wire::blocking::{read_frame, write_frame};
        use crate::host_exec_protocol::{Frame, HOST_EXEC_PROTOCOL_VERSION};

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
                if let Some(msg) = message.as_ref() {
                    let _ = write_frame(&mut rw, &Frame::Stderr(msg.as_bytes().to_vec()));
                }
                let _ = write_frame(&mut rw, &Frame::SpawnAck { ok: true, error: None });
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

    /// Windows: drive a single host-exec connection over a raw [`std::net::TcpStream`].
    ///
    /// After the service accepts an AF_HYPERV guest connection it
    /// `DuplicateHandle`s the socket into the library process and sends an
    /// `EV_HOST_EXEC_ACCEPTED` event.  The library converts the handle to a
    /// `TcpStream` (both are Winsock sockets) and calls this method.
    #[cfg(target_os = "windows")]
    pub fn handle_one_tcp(self: &Arc<Self>, rw: std::net::TcpStream) {
        use crate::host_exec_protocol::wire::blocking::{read_frame, write_frame};
        use crate::host_exec_protocol::{Frame, HOST_EXEC_PROTOCOL_VERSION};

        let mut rw = rw;

        let hello = match read_frame(&mut rw) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("host-exec(win): read hello: {e}");
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
            tracing::warn!("host-exec(win): write hello ack: {e}");
            return;
        }
        if !matches!(ack, Frame::HelloAck { ok: true, .. }) {
            return;
        }

        let spawn = match read_frame(&mut rw) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("host-exec(win): read spawn: {e}");
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
                if let Some(msg) = message.as_ref() {
                    let _ = write_frame(&mut rw, &Frame::Stderr(msg.as_bytes().to_vec()));
                }
                let _ = write_frame(&mut rw, &Frame::SpawnAck { ok: true, error: None });
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
                run_on_host_windows(rw, run_argv, run_env, run_cwd);
            }
        }
    }
}

#[cfg(unix)]
fn run_on_host(rw: std::os::unix::net::UnixStream, argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String>) {
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

    use crate::host_exec_protocol::Frame;
    use crate::host_exec_protocol::wire::blocking::{read_frame, write_frame};

    // Split into independent read/write halves. Reads on `read_half`
    // do not block writes on `write_half` — they share the same
    // socket but each has its own fd.
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

    // Writes are serialized via Mutex<UnixStream>. Reads happen on
    // their own dup'd fd, no contention.
    let write_arc = Arc::new(Mutex::new(write_half));

    // Reader thread: reads frames from guest using read_half (no lock
    // contention with writers).
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
                            if let Some(s) = g.as_mut() {
                                use std::io::Write;
                                if s.write_all(&data).is_err() {
                                    *g = None;
                                }
                            }
                        }
                    }
                    Frame::Signal { sig } => unsafe {
                        libc::kill(child_id as i32, sig);
                    },
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
                use std::io::Read;
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
                use std::io::Read;
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
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            (s.code().unwrap_or(-1), s.signal())
        }
        Err(_) => (-1, None),
    };
    tracing::trace!("host-exec: child exited code={code} sig={sig:?}");
    {
        let mut g = write_arc.lock().expect("write poisoned");
        let _ = write_frame(&mut *g, &Frame::Exit { code, signal: sig });
        // Shut down the write side so the peer's reader sees EOF, and
        // also so our own reader thread (which uses the dup'd fd) sees
        // EOF on the recv side.
        use std::net::Shutdown;
        let _ = g.shutdown(Shutdown::Both);
    }
    let _ = reader.join();
}

#[cfg(not(unix))]
fn run_on_host_windows(rw: std::net::TcpStream, argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String>) {
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

    use crate::host_exec_protocol::Frame;
    use crate::host_exec_protocol::wire::blocking::{read_frame, write_frame};

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
    tracing::trace!("host-exec(win): spawned host pid={} argv={:?}", child.id(), argv);

    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let write_arc = Arc::new(Mutex::new(write_half));

    // Reader thread: forward guest stdin frames to the child process.
    let stdin_arc = Arc::new(Mutex::new(stdin));
    let stdin_for_reader = stdin_arc.clone();
    let mut read_half_owned = read_half;
    let reader = std::thread::Builder::new()
        .name("host-exec-win-reader".into())
        .spawn(move || {
            while let Ok(frame) = read_frame(&mut read_half_owned) {
                match frame {
                    Frame::Stdin(data) => {
                        if data.is_empty() {
                            *stdin_for_reader.lock().expect("stdin poisoned") = None;
                        } else {
                            let mut g = stdin_for_reader.lock().expect("stdin poisoned");
                            if let Some(s) = g.as_mut() {
                                use std::io::Write;
                                if s.write_all(&data).is_err() {
                                    *g = None;
                                }
                            }
                        }
                    }
                    // Signal frames are silently dropped on Windows (no libc::kill).
                    _ => {}
                }
            }
        })
        .expect("spawn host-exec-win-reader");

    // Stdout pump.
    let write_for_stdout = write_arc.clone();
    let stdout_pump = stdout.map(|mut s| {
        std::thread::Builder::new()
            .name("host-exec-win-stdout".into())
            .spawn(move || {
                use std::io::Read;
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
            .expect("spawn host-exec-win-stdout")
    });

    // Stderr pump.
    let write_for_stderr = write_arc.clone();
    let stderr_pump = stderr.map(|mut s| {
        std::thread::Builder::new()
            .name("host-exec-win-stderr".into())
            .spawn(move || {
                use std::io::Read;
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
            .expect("spawn host-exec-win-stderr")
    });

    let status = child.wait();

    if let Some(t) = stdout_pump {
        let _ = t.join();
    }
    if let Some(t) = stderr_pump {
        let _ = t.join();
    }

    let code = match status {
        Ok(s) => s.code().unwrap_or(-1),
        Err(_) => -1,
    };
    tracing::trace!("host-exec(win): child exited code={code}");
    {
        use std::net::Shutdown;
        let mut g = write_arc.lock().expect("write poisoned");
        let _ = write_frame(&mut *g, &Frame::Exit { code, signal: None });
        let _ = g.shutdown(Shutdown::Both);
    }
    let _ = reader.join();
}
