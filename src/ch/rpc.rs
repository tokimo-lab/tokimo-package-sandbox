//! Host-side RPC client for `tokimo-guest-agent` running inside a microVM.
//!
//! # Transport
//!
//! Cloud Hypervisor's `--vsock` flag exposes a *hybrid vsock* UDS socket on
//! the host.  To reach a vsock port inside the guest:
//!
//! 1. `UnixStream::connect(uds_path)` — connect to the CH socket.
//! 2. Send the ASCII handshake line `"CONNECT {port}\n"`.
//! 3. Read the response line; it starts with `"OK "` on success.
//! 4. From this point the stream is a transparent bidirectional byte pipe to
//!    the guest-side `AF_VSOCK` listener on the given port.
//!
//! # Protocol
//!
//! Line-delimited JSON (one request line in, N response lines out, then the
//! server closes the connection).  Request/response types mirror
//! [`exec::Request`] / [`exec::Response`] in `tokimo-guest-agent`; they are
//! re-declared here so the library does not depend on the binary crate.
//!
//! Request envelope (tagged `"type"`, snake_case):
//! - `{"type":"ping"}`
//! - `{"type":"spawn","argv":["cmd","arg1",...]}`
//!
//! Response envelope (tagged `"type"`, snake_case):
//! - `{"type":"pong"}`
//! - `{"type":"stdout","data":"base64OrPlainText"}`
//! - `{"type":"stderr","data":"..."}`
//! - `{"type":"exit","code":0}`
//! - `{"type":"error","msg":"..."}`
//!
//! # PTY Protocol
//!
//! PTY sessions run on a separate vsock port (default: one-shot port + 1).
//! Port allocation convention:
//! - Port N (default 1024): one-shot RPC (spawn_command, ping, etc.)
//! - Port N+1 (default 1025): long-lived PTY sessions
//!
//! PTY handshake:
//! 1. Host connects to PTY port, sends open request with argv/cols/rows
//! 2. Guest forks with forkpty(), returns success
//! 3. Bidirectional streaming begins (Stdin/Resize/Close -> Stdout/Exit/Error)
//!
//! PTY frames (tagged `"type"`, snake_case):
//! Host -> Guest:
//! - `{"type":"stdin","data":"text"}`
//! - `{"type":"resize","cols":80,"rows":24}`
//! - `{"type":"close"}`
//!
//! Guest -> Host:
//! - `{"type":"stdout","data":"text"}`
//! - `{"type":"exit","code":0}`
//! - `{"type":"error","msg":"..."}`

use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::{Error, Result};

// ── Protocol types ────────────────────────────────────────────────────────────

/// Outgoing RPC request (mirrors `tokimo-guest-agent::exec::Request`).
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request<'a> {
    Ping,
    Spawn {
        argv: &'a [String],
        env: &'a [(String, String)],
        cwd: Option<&'a str>,
    },
    QueryMount {
        path: &'a str,
    },
}

/// Incoming RPC response (mirrors `tokimo-guest-agent::exec::Response`).
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong,
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32 },
    Error { msg: String },
    MountStatus { path: String, mounted: bool },
}

// ── PTY protocol types ────────────────────────────────────────────────────────

/// Outgoing PTY control frame (host -> guest).
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PtyRequest<'a> {
    Stdin { data: &'a str },
    Resize { cols: u16, rows: u16 },
    Close,
}

/// Incoming PTY event frame (guest -> host).
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PtyFrame {
    Stdout { data: String },
    Exit { code: i32 },
    Error { msg: String },
}

// ── Hybrid vsock connector ────────────────────────────────────────────────────

/// Connect to a guest vsock port via CH's hybrid UDS socket.
///
/// Returns a `BufReader<UnixStream>` with the handshake line already
/// consumed; callers can call `.get_mut()` to write to the underlying
/// stream, and `.read_line()` / `.lines()` to read response frames.
async fn connect_guest_inner(uds_path: &Path, port: u32) -> Result<BufReader<UnixStream>> {
    let stream = UnixStream::connect(uds_path)
        .await
        .map_err(|e| Error::other(format!("connect to vsock UDS '{}': {e}", uds_path.display())))?;

    // Write the CH hybrid-vsock handshake before wrapping in BufReader.
    let mut stream = stream;
    AsyncWriteExt::write_all(&mut stream, format!("CONNECT {port}\n").as_bytes()).await?;
    AsyncWriteExt::flush(&mut stream).await?;

    // Read the "OK <port>" confirmation line.
    let mut br = BufReader::new(stream);
    let mut line = String::new();
    br.read_line(&mut line).await?;

    if !line.trim_start().starts_with("OK") {
        return Err(Error::protocol(format!(
            "CH hybrid-vsock handshake failed (expected 'OK …', got {line:?})"
        )));
    }

    Ok(br)
}

// ── GuestRpc ─────────────────────────────────────────────────────────────────

/// Stateless RPC client for `tokimo-guest-agent`.
///
/// Each call opens a fresh UDS connection (one connection = one RPC exchange),
/// matching the server's one-shot-per-connection model.
#[derive(Clone)]
pub struct GuestRpc {
    vsock_socket: std::path::PathBuf,
    port: u32,
}

impl GuestRpc {
    /// Construct from the CH vsock UDS path and the guest-agent port (typically 1024).
    pub fn new(vsock_socket: std::path::PathBuf, port: u32) -> Self {
        Self { vsock_socket, port }
    }

    /// Health-check: send `{"type":"ping"}`, expect `{"type":"pong"}`.
    pub async fn ping(&self) -> Result<()> {
        let mut br = connect_guest_inner(&self.vsock_socket, self.port).await?;

        let req = serde_json::to_string(&Request::Ping)?;
        br.get_mut().write_all(req.as_bytes()).await?;
        br.get_mut().write_all(b"\n").await?;
        br.get_mut().flush().await?;

        let mut line = String::new();
        br.read_line(&mut line).await?;
        let resp: Response = serde_json::from_str(line.trim())
            .map_err(|e| Error::protocol(format!("ping: deserialize response: {e} (raw: {line:?})")))?;

        match resp {
            Response::Pong => Ok(()),
            other => Err(Error::protocol(format!("ping: expected Pong, got {other:?}"))),
        }
    }

    /// Spawn `argv` on the guest, wait for the command to finish, and return
    /// all response frames in order (`Stdout*`, `Stderr*`, `Exit`).
    ///
    /// The guest-agent collects all output with `Command::output()` before
    /// sending any frames, so this is a run-to-completion RPC.  Interactive
    /// stdin is not supported with this model; use a dedicated shell channel
    /// in future iterations (TODO v3.x-interactive-shell).
    pub async fn spawn_command(&self, argv: &[String]) -> Result<Vec<Response>> {
        self.spawn_command_with_options(argv, &[], None).await
    }

    /// Spawn `argv` with optional environment and cwd overrides.
    pub async fn spawn_command_with_options(
        &self,
        argv: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<Vec<Response>> {
        let mut br = connect_guest_inner(&self.vsock_socket, self.port).await?;

        let req = serde_json::to_string(&Request::Spawn { argv, env, cwd })?;
        br.get_mut().write_all(req.as_bytes()).await?;
        br.get_mut().write_all(b"\n").await?;
        br.get_mut().flush().await?;

        let mut responses = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            let n = br.read_line(&mut line).await?;
            if n == 0 {
                break; // server closed connection — all frames delivered
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let resp: Response = serde_json::from_str(trimmed)
                .map_err(|e| Error::protocol(format!("spawn_command: deserialize frame: {e} (raw: {trimmed:?})")))?;
            responses.push(resp);
        }

        Ok(responses)
    }

    /// Query whether a path is mounted on the guest.
    ///
    /// Returns `Ok(true)` if the path appears in /proc/self/mountinfo,
    /// `Ok(false)` otherwise.
    pub async fn query_mount(&self, path: &str) -> Result<bool> {
        let mut br = connect_guest_inner(&self.vsock_socket, self.port).await?;

        let req = serde_json::to_string(&Request::QueryMount { path })?;
        br.get_mut().write_all(req.as_bytes()).await?;
        br.get_mut().write_all(b"\n").await?;
        br.get_mut().flush().await?;

        let mut line = String::new();
        br.read_line(&mut line).await?;
        let resp: Response = serde_json::from_str(line.trim())
            .map_err(|e| Error::protocol(format!("query_mount: deserialize response: {e} (raw: {line:?})")))?;

        match resp {
            Response::MountStatus { mounted, .. } => Ok(mounted),
            Response::Error { msg } => Err(Error::protocol(format!("query_mount: guest error: {msg}"))),
            other => Err(Error::protocol(format!(
                "query_mount: expected MountStatus, got {other:?}"
            ))),
        }
    }

    /// Open a PTY session on the guest.
    ///
    /// Connects to the PTY port (one-shot port + 1), sends an open request,
    /// and returns a `PtySession` for bidirectional streaming.
    ///
    /// The PTY port convention is: if the one-shot RPC port is N (default 1024),
    /// the PTY port is N+1 (default 1025). This separation allows the guest to
    /// run distinct vsock listeners with different protocol semantics.
    pub async fn open_pty(&self, argv: Vec<String>, cols: u16, rows: u16) -> Result<PtySession> {
        // PTY port is one-shot port + 1 by convention
        let pty_port = self.port + 1;

        let mut br = connect_guest_inner(&self.vsock_socket, pty_port).await?;

        // Send PTY open request
        #[derive(Serialize)]
        struct PtyOpenRequest<'a> {
            argv: &'a [String],
            cols: u16,
            rows: u16,
        }

        let open_req = PtyOpenRequest {
            argv: &argv,
            cols,
            rows,
        };
        let json = serde_json::to_string(&open_req)?;
        br.get_mut().write_all(json.as_bytes()).await?;
        br.get_mut().write_all(b"\n").await?;
        br.get_mut().flush().await?;

        Ok(PtySession { br })
    }
}

// ── PtySession ───────────────────────────────────────────────────────────────

/// A long-lived PTY session to a guest process.
///
/// Provides async methods for reading output frames, writing stdin data,
/// resizing the terminal window, and closing the session.
pub struct PtySession {
    br: BufReader<UnixStream>,
}

impl PtySession {
    /// Read the next frame from the PTY session.
    ///
    /// Returns `Ok(None)` if the connection was closed (guest exited).
    /// Returns `Ok(Some(frame))` with `Stdout`, `Exit`, or `Error` frames.
    pub async fn read_frame(&mut self) -> Result<Option<PtyFrame>> {
        let mut line = String::new();
        let n = self.br.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let frame: PtyFrame = serde_json::from_str(trimmed)
            .map_err(|e| Error::protocol(format!("PTY: deserialize frame: {e} (raw: {trimmed:?})")))?;

        Ok(Some(frame))
    }

    /// Write stdin data to the PTY.
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        let data_str = std::str::from_utf8(data).map_err(|e| Error::other(format!("PTY stdin must be UTF-8: {e}")))?;

        let req = serde_json::to_string(&PtyRequest::Stdin { data: data_str })?;
        self.br.get_mut().write_all(req.as_bytes()).await?;
        self.br.get_mut().write_all(b"\n").await?;
        self.br.get_mut().flush().await?;

        Ok(())
    }

    /// Resize the PTY window.
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        let req = serde_json::to_string(&PtyRequest::Resize { cols, rows })?;
        self.br.get_mut().write_all(req.as_bytes()).await?;
        self.br.get_mut().write_all(b"\n").await?;
        self.br.get_mut().flush().await?;

        Ok(())
    }

    /// Close the PTY session and wait for the guest to report child exit.
    pub async fn close(mut self) -> Result<()> {
        let req = serde_json::to_string(&PtyRequest::Close)?;
        self.br.get_mut().write_all(req.as_bytes()).await?;
        self.br.get_mut().write_all(b"\n").await?;
        self.br.get_mut().flush().await?;

        let mut line = String::new();
        loop {
            line.clear();
            let n = self.br.read_line(&mut line).await?;
            if n == 0 {
                return Ok(());
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let frame: PtyFrame = serde_json::from_str(trimmed)
                .map_err(|e| Error::protocol(format!("PTY close: deserialize frame: {e} (raw: {trimmed:?})")))?;
            match frame {
                PtyFrame::Stdout { .. } => {}
                PtyFrame::Exit { .. } => return Ok(()),
                PtyFrame::Error { msg } => return Err(Error::Guest(format!("PTY close: {msg}"))),
            }
        }
    }
}
