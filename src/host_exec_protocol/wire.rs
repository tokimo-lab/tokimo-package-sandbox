//! Length-prefix framing for the host-exec wire protocol.
//!
//! Frame layout: `u32 LE postcard_len | postcard bytes`.
//! Max frame: 4 MiB.

use std::io;

use super::Frame;

pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Async (tokio) variant.
// ---------------------------------------------------------------------------

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host-exec frame length out of range: {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard decode: {e}")))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let bytes = postcard::to_allocvec(frame)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard encode: {e}")))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host-exec frame too large: {}", bytes.len()),
        ));
    }
    let len = (bytes.len() as u32).to_le_bytes();
    w.write_all(&len).await?;
    w.write_all(&bytes).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Blocking variant (std::io::Read / Write).
// ---------------------------------------------------------------------------

pub mod blocking {
    use std::io::{self, Read, Write};

    use super::{Frame, MAX_FRAME_BYTES};

    pub fn read_frame<R: Read + ?Sized>(r: &mut R) -> io::Result<Frame> {
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("host-exec frame length out of range: {len}"),
            ));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        postcard::from_bytes(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard decode: {e}")))
    }

    pub fn write_frame<W: Write + ?Sized>(w: &mut W, frame: &Frame) -> io::Result<()> {
        let bytes = postcard::to_allocvec(frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard encode: {e}")))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("host-exec frame too large: {}", bytes.len()),
            ));
        }
        let len = (bytes.len() as u32).to_le_bytes();
        w.write_all(&len)?;
        w.write_all(&bytes)?;
        Ok(())
    }
}
