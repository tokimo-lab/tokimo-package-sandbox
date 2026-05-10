//! PTY session handler for `tokimo-guest-agent`.
//!
//! Opens a pseudoterminal with `forkpty()`, executes a command in the child,
//! and streams bidirectional I/O as line-delimited JSON frames:
//! - Host writes: `Stdin`, `Resize`, `Close`
//! - Guest writes: `Stdout`, `Exit`, `Error`

use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// Inbound PTY control frame from the host.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PtyRequest {
    /// Write data to PTY stdin.
    Stdin { data: String },
    /// Resize the PTY window.
    Resize { cols: u16, rows: u16 },
    /// Close the PTY session (kills the child process).
    Close,
}

/// Outbound PTY event frame to the host.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PtyResponse {
    /// Data read from PTY stdout.
    Stdout { data: String },
    /// Child process exited.
    Exit { code: i32 },
    /// Error occurred.
    Error { msg: String },
}

/// Handle a PTY session: fork, exec, stream I/O.
///
/// Runs until the child exits or the connection is closed.
pub async fn handle_pty_connection(
    mut stream: tokio_vsock::VsockStream,
    argv: Vec<String>,
    cols: u16,
    rows: u16,
) -> anyhow::Result<()> {
    // Validate argv and create CStrings before forking
    if argv.is_empty() {
        let err_frame = serde_json::to_string(&PtyResponse::Error {
            msg: "empty argv".into(),
        })
        .unwrap();
        stream.write_all(err_frame.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        return Ok(());
    }

    // Validate CString conversion before forking
    for arg in &argv {
        if arg.as_bytes().contains(&0) {
            let err_frame = serde_json::to_string(&PtyResponse::Error {
                msg: format!("argument contains interior NUL byte: {:?}", arg),
            })
            .unwrap();
            stream.write_all(err_frame.as_bytes()).await?;
            stream.write_all(b"\n").await?;
            stream.flush().await?;
            return Ok(());
        }
    }

    // Open PTY with forkpty()
    let (master_fd, child_pid) = match unsafe { forkpty_blocking(cols, rows) } {
        Ok(result) => result,
        Err(e) => {
            let err_frame = serde_json::to_string(&PtyResponse::Error {
                msg: format!("forkpty failed: {e}"),
            })
            .unwrap();
            stream.write_all(err_frame.as_bytes()).await?;
            stream.write_all(b"\n").await?;
            stream.flush().await?;
            return Ok(());
        }
    };

    if child_pid == 0 {
        // Child process: exec the command
        exec_child(&argv);
        // exec never returns on success - this line is unreachable
    }

    // Parent process: manage PTY I/O
    run_pty_parent(stream, master_fd, child_pid).await
}

/// Run the parent side of a PTY session: bidirectional streaming + child reaping.
async fn run_pty_parent(
    stream: tokio_vsock::VsockStream,
    master_fd: RawFd,
    child_pid: libc::pid_t,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    // Channel for PTY output (master -> network)
    let (tx, mut rx) = mpsc::channel::<PtyResponse>(32);

    // Track whether child has exited and whether we already sent termination.
    let child_exited = Arc::new(AtomicBool::new(false));
    let kill_sent = Arc::new(AtomicBool::new(false));

    // Spawn task to read from PTY master
    let tx_clone = tx.clone();
    let read_task = tokio::spawn(async move {
        read_pty_loop(master_fd, tx_clone).await;
    });

    // Spawn task to reap child
    let tx_clone = tx.clone();
    let child_exited_clone = child_exited.clone();
    let reap_task = tokio::spawn(async move {
        reap_child(child_pid, tx_clone, child_exited_clone).await;
    });

    // Main loop: read host requests + forward PTY output
    loop {
        tokio::select! {
            // Host sent a request
            line_res = lines.next_line() => {
                match line_res {
                    Ok(Some(line)) => {
                        match handle_pty_request(&line, master_fd, child_pid, &child_exited, &kill_sent).await {
                            Ok(()) => {}
                            Err(e) => {
                                tracing::warn!("PTY request error: {e:#}");
                                let _ = tx.send(PtyResponse::Error { msg: e.to_string() }).await;
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        // Host closed connection
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("PTY read error: {e:#}");
                        break;
                    }
                }
            }

            // PTY output ready
            Some(resp) = rx.recv() => {
                let json = match serde_json::to_string(&resp).context("serialize PTY response") {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::error!("Failed to serialize PTY response: {e:#}");
                        break;
                    }
                };
                if let Err(e) = writer.write_all(json.as_bytes()).await {
                    tracing::error!("Failed to write PTY response: {e:#}");
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    tracing::error!("Failed to write newline: {e:#}");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    tracing::error!("Failed to flush writer: {e:#}");
                    break;
                }

                // Exit frame signals end of session
                if matches!(resp, PtyResponse::Exit { .. }) {
                    break;
                }
            }
        }
    }

    // Cleanup: terminate child if still running, then reap it.
    if !child_exited.load(Ordering::SeqCst) {
        if !kill_sent.swap(true, Ordering::SeqCst) {
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), reap_task).await;
    } else {
        let _ = reap_task.await;
    }

    // Close master FD to unblock the read task
    unsafe {
        libc::close(master_fd);
    }

    // Now abort the read task (fd is closed, so blocking read will fail)
    read_task.abort();
    let _ = read_task.await;

    Ok(())
}

/// Parse and handle one PTY control request from the host.
async fn handle_pty_request(
    line: &str,
    master_fd: RawFd,
    child_pid: libc::pid_t,
    child_exited: &AtomicBool,
    kill_sent: &AtomicBool,
) -> anyhow::Result<()> {
    let req: PtyRequest = serde_json::from_str(line).context("deserialize PTY request")?;

    match req {
        PtyRequest::Stdin { data } => write_to_fd(master_fd, data.as_bytes())?,
        PtyRequest::Resize { cols, rows } => resize_pty(master_fd, cols, rows)?,
        PtyRequest::Close => {
            if !child_exited.load(Ordering::SeqCst) && !kill_sent.swap(true, Ordering::SeqCst) {
                unsafe {
                    libc::kill(child_pid, libc::SIGTERM);
                }
            }
        }
    }

    Ok(())
}

/// Read from PTY master in a blocking task, send output to channel.
async fn read_pty_loop(master_fd: RawFd, tx: mpsc::Sender<PtyResponse>) {
    let result = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(master_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // EIO means child closed its side
                if err.raw_os_error() == Some(libc::EIO) {
                    break;
                }
                let _ = tx.blocking_send(PtyResponse::Error {
                    msg: format!("read PTY: {err}"),
                });
                break;
            }
            if n == 0 {
                break;
            }
            let data = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            if tx.blocking_send(PtyResponse::Stdout { data }).is_err() {
                break;
            }
        }
        tx
    })
    .await;

    match result {
        Ok(_tx_back) => {
            // Task completed successfully
        }
        Err(e) => {
            // Task panicked
            eprintln!("PTY read task panicked: {e}");
        }
    }
}

/// Wait for child process to exit, send Exit frame.
async fn reap_child(child_pid: libc::pid_t, tx: mpsc::Sender<PtyResponse>, child_exited: Arc<AtomicBool>) {
    let result = tokio::task::spawn_blocking(move || {
        let mut status: libc::c_int = 0;
        loop {
            let ret = unsafe { libc::waitpid(child_pid, &mut status, 0) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            break;
        }

        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        Ok(code)
    })
    .await;

    match result {
        Ok(Ok(code)) => {
            child_exited.store(true, Ordering::SeqCst);
            let _ = tx.send(PtyResponse::Exit { code }).await;
        }
        Ok(Err(e)) => {
            child_exited.store(true, Ordering::SeqCst);
            let _ = tx
                .send(PtyResponse::Error {
                    msg: format!("waitpid: {e}"),
                })
                .await;
        }
        Err(e) => {
            child_exited.store(true, Ordering::SeqCst);
            let _ = tx
                .send(PtyResponse::Error {
                    msg: format!("reap task: {e}"),
                })
                .await;
        }
    }
}

/// Fork and open a pseudoterminal. Returns `(master_fd, child_pid)`.
///
/// In the child, this returns `(0, 0)` and stdin/stdout/stderr are connected to the slave PTY.
/// In the parent, returns the master FD and child PID.
///
/// SAFETY: Must be called on a single-threaded context or before any threads are spawned.
unsafe fn forkpty_blocking(cols: u16, rows: u16) -> anyhow::Result<(RawFd, libc::pid_t)> {
    let mut master_fd: libc::c_int = -1;
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    ws.ws_col = cols;
    ws.ws_row = rows;

    let pid = unsafe { libc::forkpty(&mut master_fd, std::ptr::null_mut(), std::ptr::null_mut(), &ws) };

    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok((master_fd, pid))
}

/// Exec the command in the child. Never returns on success.
fn exec_child(argv: &[String]) -> ! {
    use std::ffi::CString;

    // CString validation already done in handle_pty_connection, but
    // handle it defensively here in case of programming error
    let c_argv: Vec<CString> = match argv
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("CString::new failed: {}", e);
            std::process::exit(127);
        }
    };
    let c_ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|s| s.as_ptr()).collect();
    let mut c_argv_null = c_ptrs;
    c_argv_null.push(std::ptr::null());

    unsafe {
        libc::execvp(c_argv_null[0], c_argv_null.as_ptr());
    }

    // exec failed
    let err = std::io::Error::last_os_error();
    eprintln!("exec {:?}: {}", argv[0], err);
    std::process::exit(127);
}

/// Write data to a file descriptor (PTY master).
fn write_to_fd(fd: RawFd, data: &[u8]) -> anyhow::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let n = unsafe { libc::write(fd, data[offset..].as_ptr() as *const libc::c_void, data.len() - offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        offset += n as usize;
    }
    Ok(())
}

/// Resize the PTY window via `ioctl(TIOCSWINSZ)`.
fn resize_pty(fd: RawFd, cols: u16, rows: u16) -> anyhow::Result<()> {
    let ws = libc::winsize {
        ws_col: cols,
        ws_row: rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}
