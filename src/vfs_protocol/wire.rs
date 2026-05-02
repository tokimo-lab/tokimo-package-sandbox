//! Length-prefix framing helpers (async).
//!
//! Wire layout:
//!
//! ```text
//!   ┌───────────────┬───────────────────────────────────┐
//!   │ u32 LE length │ postcard-encoded Frame payload    │
//!   └───────────────┴───────────────────────────────────┘
//! ```
//!
//! `length` does not include the 4 bytes of the prefix itself.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Frame, MAX_FRAME_BYTES};

/// Read one frame. Returns `Ok(None)` on clean EOF before any bytes are
/// read; this is how the peer signals graceful close.
pub async fn read_frame<R>(reader: &mut R) -> io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} > {}", len, MAX_FRAME_BYTES),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    let frame: Frame = postcard::from_bytes(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard decode: {e}")))?;
    Ok(Some(frame))
}

/// Write one frame. Caller is responsible for serialising concurrent
/// writers (e.g. behind a `Mutex<TxHalf>`) — frames must be atomic on the
/// wire.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = postcard::to_allocvec(frame)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard encode: {e}")))?;
    if payload.len() > MAX_FRAME_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} > {}", payload.len(), MAX_FRAME_BYTES),
        ));
    }
    let len = (payload.len() as u32).to_le_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs_protocol::{PROTOCOL_VERSION, Req};

    #[tokio::test]
    async fn roundtrip_through_pipe() {
        let (a, b) = tokio::io::duplex(8192);
        let (a_r, mut aw) = tokio::io::split(a);
        let (mut br, b_w) = tokio::io::split(b);

        let frame = Frame::Request {
            req_id: 1,
            mount_id: 0,
            op: Req::GetAttr { nodeid: 1 },
        };

        let writer = tokio::spawn(async move {
            write_frame(&mut aw, &frame).await.unwrap();
            drop(aw);
        });
        let reader = tokio::spawn(async move {
            let f = read_frame(&mut br).await.unwrap().unwrap();
            assert!(matches!(
                f,
                Frame::Request {
                    op: Req::GetAttr { nodeid: 1 },
                    ..
                }
            ));
            assert!(read_frame(&mut br).await.unwrap().is_none());
        });
        drop(a_r);
        drop(b_w);
        writer.await.unwrap();
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn hello_handshake_sequence() {
        let (a, b) = tokio::io::duplex(4096);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);

        let client = tokio::spawn(async move {
            write_frame(
                &mut aw,
                &Frame::Hello {
                    proto_version: PROTOCOL_VERSION,
                    max_inflight: 32,
                    client_name: "test".into(),
                },
            )
            .await
            .unwrap();
            let ack = read_frame(&mut ar).await.unwrap().unwrap();
            assert!(matches!(ack, Frame::HelloAck { .. }));
        });
        let server = tokio::spawn(async move {
            let h = read_frame(&mut br).await.unwrap().unwrap();
            assert!(matches!(h, Frame::Hello { .. }));
            write_frame(
                &mut bw,
                &Frame::HelloAck {
                    proto_version: PROTOCOL_VERSION,
                    max_inflight: 32,
                },
            )
            .await
            .unwrap();
        });
        client.await.unwrap();
        server.await.unwrap();
    }
}
