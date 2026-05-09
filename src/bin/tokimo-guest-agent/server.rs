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

/// Run the vsock RPC loop.  Does not return under normal operation.
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
