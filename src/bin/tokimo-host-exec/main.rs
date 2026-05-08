//! `tokimo-host-exec` — guest-side stub binary for the Host-Exec Bridge.
//!
//! At runtime, `tokimo-sandbox-init` creates hardlinks under
//! `/run/tokimo/host-bridge/<name>` pointing at this binary. When the
//! sandboxed process executes one of those hardlinks (because PATH is
//! prepended with the bridge directory), `argv[0]` is the basename of
//! the link — i.e. the bridged command name.
//!
//! **Transport selection** (Linux guest only):
//! - If `TOKIMO_HOST_EXEC_VSOCK_PORT` is set (macOS/Windows VM mode):
//!   connect via AF_VSOCK to the host CID on that port.
//! - Otherwise (Linux bwrap mode): connect to `/run/tokimo/host-exec.sock`
//!   (a Unix listener served by init via SCM_RIGHTS relay).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tokimo-host-exec is Linux-only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(run() as i32);
}

#[cfg(target_os = "linux")]
fn run() -> u8 {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokimo_package_sandbox::host_exec_protocol::{Frame, HOST_EXEC_PROTOCOL_VERSION, wire::blocking};

    const SOCK: &str = "/run/tokimo/host-exec.sock";

    // Determine command name: basename of argv[0]. The link name is
    // what the bridged command should be.
    let argv: Vec<String> = std::env::args().collect();
    let cmd_name = PathBuf::from(argv.first().cloned().unwrap_or_default())
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Build full argv for the host: [cmd_name, ...rest].
    let mut full_argv = vec![cmd_name.clone()];
    full_argv.extend(argv.into_iter().skip(1));

    let env: Vec<(String, String)> = std::env::vars().collect();
    let cwd = std::env::current_dir().ok().map(|p| p.to_string_lossy().into_owned());

    // Connect: vsock if running inside a macOS/Windows VM, otherwise Unix socket.
    let stream: UnixStream = if let Ok(port_str) = std::env::var("TOKIMO_HOST_EXEC_VSOCK_PORT") {
        match port_str.parse::<u32>() {
            Ok(port) => {
                use std::os::fd::{FromRawFd, IntoRawFd};
                match tokimo_package_sandbox::vsock_util::connect_host(port) {
                    Ok(fd) => unsafe { UnixStream::from_raw_fd(fd.into_raw_fd()) },
                    Err(e) => {
                        eprintln!("tokimo-host-exec: vsock connect port {port}: {e}");
                        return 127;
                    }
                }
            }
            Err(_) => {
                eprintln!("tokimo-host-exec: invalid TOKIMO_HOST_EXEC_VSOCK_PORT={port_str:?}");
                return 127;
            }
        }
    } else {
        match UnixStream::connect(SOCK) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tokimo-host-exec: connect {SOCK}: {e}");
                return 127;
            }
        }
    };

    let mut writer = stream.try_clone().expect("clone");
    let mut reader = stream;

    // Hello handshake.
    if let Err(e) = blocking::write_frame(
        &mut writer,
        &Frame::Hello {
            protocol: HOST_EXEC_PROTOCOL_VERSION,
        },
    ) {
        eprintln!("tokimo-host-exec: hello: {e}");
        return 127;
    }
    match blocking::read_frame(&mut reader) {
        Ok(Frame::HelloAck { ok: true, .. }) => {}
        Ok(Frame::HelloAck { ok: false, error, .. }) => {
            eprintln!("tokimo-host-exec: hello rejected: {}", error.unwrap_or_default());
            return 127;
        }
        Ok(other) => {
            eprintln!("tokimo-host-exec: unexpected reply: {other:?}");
            return 127;
        }
        Err(e) => {
            eprintln!("tokimo-host-exec: hello reply: {e}");
            return 127;
        }
    }

    // Send Spawn.
    if let Err(e) = blocking::write_frame(
        &mut writer,
        &Frame::Spawn {
            argv: full_argv,
            env,
            cwd,
            pty: None,
        },
    ) {
        eprintln!("tokimo-host-exec: spawn: {e}");
        return 127;
    }
    match blocking::read_frame(&mut reader) {
        Ok(Frame::SpawnAck { ok: true, .. }) => {}
        Ok(Frame::SpawnAck { ok: false, error, .. }) => {
            eprintln!("tokimo-host-exec: spawn rejected: {}", error.unwrap_or_default());
            return 127;
        }
        Ok(other) => {
            eprintln!("tokimo-host-exec: unexpected spawn reply: {other:?}");
            return 127;
        }
        Err(e) => {
            eprintln!("tokimo-host-exec: spawn reply: {e}");
            return 127;
        }
    }

    let writer = Arc::new(Mutex::new(writer));

    // Pump stdin → Frame::Stdin. We keep the thread handle so we can
    // close stdin fd before exiting, which causes the blocking read to
    // return and the thread to exit cleanly.
    let writer_in = Arc::clone(&writer);
    let stdin_thread = thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let frame = Frame::Stdin(buf[..n].to_vec());
                    let mut w = writer_in.lock().unwrap();
                    if blocking::write_frame(&mut *w, &frame).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Read frames from host → stdout/stderr/exit.
    let mut exit_code: i32 = 0;
    loop {
        match blocking::read_frame(&mut reader) {
            Ok(Frame::Stdout(data)) => {
                let _ = std::io::stdout().write_all(&data);
                let _ = std::io::stdout().flush();
            }
            Ok(Frame::Stderr(data)) => {
                let _ = std::io::stderr().write_all(&data);
                let _ = std::io::stderr().flush();
            }
            Ok(Frame::Exit { code, .. }) => {
                exit_code = code;
                break;
            }
            Ok(_other) => {}
            Err(_) => break,
        }
    }

    // Close stdin fd so the stdin_thread's blocking read returns EOF.
    // Without this, the thread keeps reading and the process hangs on
    // join, which also stalls the parent shell's stdin pipe.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::close(std::io::stdin().as_raw_fd());
        }
    }
    drop(reader);
    drop(writer);
    drop(stdin_thread);
    (exit_code & 0xff) as u8
}
