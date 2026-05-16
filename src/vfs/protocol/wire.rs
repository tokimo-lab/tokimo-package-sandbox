//! Length-prefix framing helpers for the VFS wire protocol.
//!
//! ## Wire layout (v2 — bulk-bypass)
//!
//! ```text
//!   ┌───────────────┬───────────────┬─────────────────────┬────────────────┐
//!   │ u32 LE        │ u32 LE        │ postcard-encoded    │ raw bulk bytes │
//!   │ postcard_len  │ raw_len       │ Frame (postcard_len)│ (raw_len)      │
//!   └───────────────┴───────────────┴─────────────────────┴────────────────┘
//! ```
//!
//! Two sizes are encoded so the receiver can read the postcard part and
//! the raw bulk payload separately, avoiding the 2× memcpy that postcard
//! would otherwise do for `Vec<u8>` fields.
//!
//! Bulk-bearing variants:
//! - `Frame::Response { result: Res::Bytes(_) }` (file read response)
//! - `Frame::Request { op: Req::Write { data, .. } }` (file write request)
//!
//! For these, the postcard part carries the variant with `data` replaced
//! by an empty `Vec<u8>`, and the raw bytes follow on the wire.
//!
//! All other frames have `raw_len == 0` and serialise/deserialise
//! through postcard normally.
//!
//! Two flavours are provided:
//!
//! - top-level [`read_frame`] / [`write_frame`] — async, used by `vfs_host`
//!   and any tokio-based consumer.
//! - [`blocking`] submodule — same wire format, sync `Read`/`Write`,
//!   used by `tokimo-sandbox-fuse`.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Frame, MAX_FRAME_BYTES, Req, Res};

const HEADER_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Bulk extraction / splicing helpers (shared by sync + async).
// ---------------------------------------------------------------------------

/// If the frame carries a bulk payload (`Res::Bytes` / `Req::Write`),
/// return a borrowed reference to it. Returns `&[]` for non-bulk frames
/// or empty payloads.
fn bulk_slice(frame: &Frame) -> &[u8] {
    match frame {
        Frame::Response {
            result: Res::Bytes(d), ..
        } => d.as_slice(),
        Frame::Request {
            op: Req::Write { data, .. },
            ..
        } => data.as_slice(),
        _ => &[],
    }
}

/// Returns a `Frame` value with the bulk field replaced by an empty
/// `Vec<u8>`. Cheap (~80 bytes copied) since the bulk payload itself is
/// not cloned.
fn strip_bulk(frame: &Frame) -> Option<Frame> {
    match frame {
        Frame::Response {
            req_id,
            result: Res::Bytes(d),
        } if !d.is_empty() => Some(Frame::Response {
            req_id: *req_id,
            result: Res::Bytes(Vec::new()),
        }),
        Frame::Request {
            req_id,
            mount_id,
            op: Req::Write { fh, offset, data },
        } if !data.is_empty() => Some(Frame::Request {
            req_id: *req_id,
            mount_id: *mount_id,
            op: Req::Write {
                fh: *fh,
                offset: *offset,
                data: Vec::new(),
            },
        }),
        _ => None,
    }
}

/// Move the raw bulk payload back into the frame's `data` field if it
/// has one. No-op for non-bulk variants.
fn splice_bulk(frame: &mut Frame, raw: Vec<u8>) {
    match frame {
        Frame::Response {
            result: Res::Bytes(d), ..
        } => *d = raw,
        Frame::Request {
            op: Req::Write { data, .. },
            ..
        } => *data = raw,
        _ => {} // discard; should not happen in well-formed peers
    }
}

fn write_header(buf: &mut [u8; HEADER_LEN], postcard_len: u32, raw_len: u32) {
    buf[0..4].copy_from_slice(&postcard_len.to_le_bytes());
    buf[4..8].copy_from_slice(&raw_len.to_le_bytes());
}

fn parse_header(buf: &[u8; HEADER_LEN]) -> io::Result<(usize, usize)> {
    let postcard_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let raw_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let total = postcard_len.saturating_add(raw_len);
    if total > MAX_FRAME_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: postcard={postcard_len} raw={raw_len} (max {MAX_FRAME_BYTES})"),
        ));
    }
    if postcard_len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame postcard_len is zero"));
    }
    Ok((postcard_len, raw_len))
}

// ---------------------------------------------------------------------------
// Async (tokio)
// ---------------------------------------------------------------------------

/// Read one frame. Returns `Ok(None)` on clean EOF before any bytes are
/// read; this is how the peer signals graceful close.
pub async fn read_frame<R>(reader: &mut R) -> io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let (postcard_len, raw_len) = parse_header(&header)?;

    let mut postcard_buf = vec![0u8; postcard_len];
    reader.read_exact(&mut postcard_buf).await?;
    let mut frame: Frame = postcard::from_bytes(&postcard_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard decode: {e}")))?;

    if raw_len > 0 {
        let mut raw = vec![0u8; raw_len];
        reader.read_exact(&mut raw).await?;
        splice_bulk(&mut frame, raw);
    }

    Ok(Some(frame))
}

/// Write one frame. Caller is responsible for serialising concurrent
/// writers (e.g. behind a `Mutex<TxHalf>`) — frames must be atomic on the
/// wire.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bulk = bulk_slice(frame);
    let stripped = strip_bulk(frame);
    let frame_to_encode: &Frame = match stripped.as_ref() {
        Some(f) => f,
        None => frame,
    };

    let postcard_bytes = postcard::to_allocvec(frame_to_encode)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard encode: {e}")))?;
    if postcard_bytes.len() + bulk.len() > MAX_FRAME_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame too large: postcard={} raw={} (max {})",
                postcard_bytes.len(),
                bulk.len(),
                MAX_FRAME_BYTES
            ),
        ));
    }

    let mut header = [0u8; HEADER_LEN];
    write_header(&mut header, postcard_bytes.len() as u32, bulk.len() as u32);

    // Coalesce header + small postcard part into one buffer to avoid
    // emitting 3 separate small writes for non-bulk frames.
    let mut prefix = Vec::with_capacity(HEADER_LEN + postcard_bytes.len());
    prefix.extend_from_slice(&header);
    prefix.extend_from_slice(&postcard_bytes);
    writer.write_all(&prefix).await?;
    if !bulk.is_empty() {
        writer.write_all(bulk).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Blocking variant — same wire format, sync Read/Write
// ---------------------------------------------------------------------------

/// Sync (blocking) flavour of the same length-prefix + postcard codec.
/// Used by `tokimo-sandbox-fuse` which runs blocking inside the guest.
pub mod blocking {
    use std::io::{self, IoSlice, Read, Write};

    use super::{Frame, HEADER_LEN, MAX_FRAME_BYTES, bulk_slice, parse_header, splice_bulk, strip_bulk, write_header};

    /// Read one frame. Returns `Ok(None)` on clean EOF before any bytes
    /// are read for the header; this is how the peer signals graceful
    /// close.
    pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<Frame>> {
        let mut buf = Vec::new();
        read_frame_into(reader, &mut buf)
    }

    /// Like [`read_frame`] but reuses `buf` across calls to avoid
    /// per-frame heap allocation for the postcard part.
    pub fn read_frame_into<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<Option<Frame>> {
        let mut header = [0u8; HEADER_LEN];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let (postcard_len, raw_len) = parse_header(&header)?;

        buf.clear();
        buf.resize(postcard_len, 0);
        reader.read_exact(buf)?;
        let mut frame: Frame = postcard::from_bytes(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard decode: {e}")))?;

        if raw_len > 0 {
            let mut raw = vec![0u8; raw_len];
            reader.read_exact(&mut raw)?;
            splice_bulk(&mut frame, raw);
        }

        Ok(Some(frame))
    }

    /// Write one frame. Single syscall on most transports thanks to
    /// `write_vectored`.
    pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> io::Result<()> {
        let bulk = bulk_slice(frame);
        let stripped = strip_bulk(frame);
        let frame_to_encode: &Frame = match stripped.as_ref() {
            Some(f) => f,
            None => frame,
        };

        let postcard_bytes = postcard::to_allocvec(frame_to_encode)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard encode: {e}")))?;
        if postcard_bytes.len() + bulk.len() > MAX_FRAME_BYTES as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame too large: postcard={} raw={} (max {})",
                    postcard_bytes.len(),
                    bulk.len(),
                    MAX_FRAME_BYTES
                ),
            ));
        }

        let mut header = [0u8; HEADER_LEN];
        write_header(&mut header, postcard_bytes.len() as u32, bulk.len() as u32);

        // Coalesce header + small postcard part into one buffer.
        let mut prefix = Vec::with_capacity(HEADER_LEN + postcard_bytes.len());
        prefix.extend_from_slice(&header);
        prefix.extend_from_slice(&postcard_bytes);

        if bulk.is_empty() {
            writer.write_all(&prefix)?;
        } else {
            // writev: one syscall delivers header + postcard + bulk on
            // unix sockets / vsock / pipes.
            write_all_vectored(writer, &mut [IoSlice::new(&prefix), IoSlice::new(bulk)])?;
        }
        Ok(())
    }

    /// Stable-Rust replacement for the unstable `Write::write_all_vectored`.
    fn write_all_vectored<W: Write + ?Sized>(writer: &mut W, mut bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        // Strip leading empty slices (write_vectored requires non-empty).
        IoSlice::advance_slices(&mut bufs, 0);
        while !bufs.is_empty() {
            match writer.write_vectored(bufs) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole frame"));
                }
                Ok(n) => IoSlice::advance_slices(&mut bufs, n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // Touch MAX_FRAME_BYTES so unused-import warnings don't flag the import.
    #[allow(dead_code)]
    const _MAX: u32 = MAX_FRAME_BYTES;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs_protocol::{PROTOCOL_VERSION, Req, Res};

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

        let got = read_frame(&mut br).await.unwrap();
        writer.await.unwrap();
        assert!(matches!(
            got,
            Some(Frame::Request {
                op: Req::GetAttr { nodeid: 1 },
                ..
            })
        ));
        let _ = (a_r, b_w);
    }

    #[tokio::test]
    async fn handshake_frame_roundtrip() {
        let (a, b) = tokio::io::duplex(8192);
        let (a_r, mut aw) = tokio::io::split(a);
        let (mut br, b_w) = tokio::io::split(b);

        let frame = Frame::Hello {
            proto_version: PROTOCOL_VERSION,
            max_inflight: 64,
            client_name: "x".into(),
            mount_name: Some("m".into()),
        };

        let writer = tokio::spawn(async move {
            write_frame(&mut aw, &frame).await.unwrap();
            drop(aw);
        });

        let got = read_frame(&mut br).await.unwrap().unwrap();
        writer.await.unwrap();
        match got {
            Frame::Hello { proto_version, .. } => assert_eq!(proto_version, PROTOCOL_VERSION),
            other => panic!("{other:?}"),
        }
        let _ = (a_r, b_w);
    }

    #[tokio::test]
    async fn bulk_response_roundtrip() {
        let (a, b) = tokio::io::duplex(2 * 1024 * 1024);
        let (a_r, mut aw) = tokio::io::split(a);
        let (mut br, b_w) = tokio::io::split(b);

        let payload: Vec<u8> = (0..1_000_000).map(|i| (i % 251) as u8).collect();
        let frame = Frame::Response {
            req_id: 42,
            result: Res::Bytes(payload.clone()),
        };

        let writer = tokio::spawn(async move {
            write_frame(&mut aw, &frame).await.unwrap();
            drop(aw);
        });
        let got = read_frame(&mut br).await.unwrap().unwrap();
        writer.await.unwrap();
        match got {
            Frame::Response {
                req_id: 42,
                result: Res::Bytes(b),
            } => assert_eq!(b, payload),
            other => panic!("{other:?}"),
        }
        let _ = (a_r, b_w);
    }

    #[test]
    fn bulk_request_blocking_roundtrip() {
        use std::io::Cursor;

        let mut buf: Vec<u8> = Vec::new();
        let payload: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
        let frame = Frame::Request {
            req_id: 7,
            mount_id: 3,
            op: Req::Write {
                fh: 5,
                offset: 1024,
                data: payload.clone(),
            },
        };

        blocking::write_frame(&mut buf, &frame).unwrap();
        let mut cur = Cursor::new(buf);
        let got = blocking::read_frame(&mut cur).unwrap().unwrap();
        match got {
            Frame::Request {
                req_id: 7,
                mount_id: 3,
                op:
                    Req::Write {
                        fh: 5,
                        offset: 1024,
                        data,
                    },
            } => assert_eq!(data, payload),
            other => panic!("{other:?}"),
        }
    }
}
