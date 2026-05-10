//! vsock RPC listener for `tokimo-guest-agent`.
//!
//! Binds `AF_VSOCK CID=VMADDR_CID_ANY:port`, accepts one connection per
//! spawned task, reads one line-delimited JSON request, dispatches to
//! `exec::handle_request`, and writes back line-delimited JSON response
//! frames before closing the connection.

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

use crate::exec::{Request, handle_request};

/// Run the one-shot vsock RPC loop.  Does not return under normal operation.
pub async fn run(port: u32) -> anyhow::Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .with_context(|| format!("bind vsock CID=ANY port={port}"))?;
    tracing::info!("tokimo-guest-agent: listening on vsock port {port}");

    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept")?;
        tracing::debug!("accepted connection from {peer:?}");
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                tracing::warn!("connection error from {peer:?}: {e:#}");
            }
        });
    }
}

/// Run the PTY vsock server loop.  Does not return under normal operation.
pub async fn run_pty(port: u32) -> anyhow::Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .with_context(|| format!("bind vsock CID=ANY port={port} (PTY)"))?;
    tracing::info!("tokimo-guest-agent: listening on vsock port {port} (PTY)");

    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept (PTY)")?;
        tracing::debug!("accepted PTY connection from {peer:?}");
        tokio::spawn(async move {
            if let Err(e) = handle_pty_connection_wrapper(stream).await {
                tracing::warn!("PTY connection error from {peer:?}: {e:#}");
            }
        });
    }
}

async fn handle_connection(stream: tokio_vsock::VsockStream) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    let Some(line) = lines.next_line().await.context("read request line")? else {
        return Ok(());
    };

    let req: Request = serde_json::from_str(&line).context("deserialize request")?;
    let responses = handle_request(req).await;

    for resp in responses {
        let json = serde_json::to_string(&resp).context("serialize response")?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;

    Ok(())
}

async fn handle_pty_connection_wrapper(mut stream: tokio_vsock::VsockStream) -> anyhow::Result<()> {
    // Read initial PTY open request (JSON line with argv, cols, rows)
    // Read byte-by-byte to avoid BufReader over-reading into its buffer
    const MAX_LINE_SIZE: usize = 16384;
    let mut line = Vec::new();

    loop {
        let mut byte = [0u8; 1];
        use tokio::io::AsyncReadExt;
        match stream.read(&mut byte).await {
            Ok(0) => {
                return Err(anyhow::anyhow!("PTY connection closed before open request"));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() >= MAX_LINE_SIZE {
                    return Err(anyhow::anyhow!("PTY open request exceeds max line size"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(anyhow::anyhow!("PTY connection closed before open request"));
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    if line.is_empty() {
        return Err(anyhow::anyhow!("PTY connection closed before open request"));
    }

    let line_str = String::from_utf8(line).context("PTY open request is not valid UTF-8")?;

    #[derive(serde::Deserialize)]
    struct PtyOpenRequest {
        argv: Vec<String>,
        cols: u16,
        rows: u16,
    }

    let open_req: PtyOpenRequest = serde_json::from_str(&line_str).context("deserialize PTY open request")?;

    crate::pty::handle_pty_connection(stream, open_req.argv, open_req.cols, open_req.rows).await
}
