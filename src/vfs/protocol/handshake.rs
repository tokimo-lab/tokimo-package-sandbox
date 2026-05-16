//! Hello handshake helpers for the VFS wire protocol.
//!
//! Encapsulates the `Frame::Hello` / `Frame::HelloAck` round-trip so that
//! call sites in [`crate::vfs_host`] (server, async) and
//! `tokimo-sandbox-fuse` (client, blocking) each reduce to a single call.
//!
//! # Protocol summary
//! 1. Client sends [`Frame::Hello`] with `proto_version`, `max_inflight`,
//!    `client_name`, and an optional `mount_name`.
//! 2. Server replies [`Frame::HelloAck`] with the negotiated version and
//!    `bound_mount_id` (set when `mount_name` resolved successfully).
//! 3. On any error the server still sends a `HelloAck` (with
//!    `bound_mount_id: None`) before returning `Err`.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

use super::wire;
use super::{Frame, PROTOCOL_VERSION};

// ---------------------------------------------------------------------------
// Server side (async)
// ---------------------------------------------------------------------------

/// Perform the server-side `Hello`/`HelloAck` exchange.
///
/// Reads [`Frame::Hello`] from `rx`, validates `proto_version`, resolves the
/// optional `mount_name` via `mount_lookup`, writes [`Frame::HelloAck`] to
/// `tx`, and returns `max_inflight`.
///
/// Returns `Ok(None)` when the peer closes cleanly before sending any bytes
/// (the caller should treat this as a normal EOF and exit the serve loop).
/// Returns `Err` on version mismatch, unknown mount, or I/O failure; in all
/// error cases a `HelloAck` with `bound_mount_id: None` is attempted before
/// returning.
///
/// `tx` is borrowed mutably for the duration of the call. During handshake
/// there are no concurrent writers yet, so holding the borrow is safe.
pub async fn server_handshake<R, W>(
    rx: &mut R,
    tx: &mut W,
    mount_lookup: impl Fn(&str) -> Option<u32>,
) -> io::Result<Option<u32>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(first) = wire::read_frame(rx).await? else {
        return Ok(None);
    };

    match first {
        Frame::Hello {
            proto_version,
            max_inflight,
            mount_name,
            ..
        } => {
            if proto_version != PROTOCOL_VERSION {
                let _ = wire::write_frame(
                    tx,
                    &Frame::HelloAck {
                        proto_version: PROTOCOL_VERSION,
                        max_inflight: 0,
                        bound_mount_id: None,
                    },
                )
                .await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "protocol mismatch: client={} server={}",
                        proto_version, PROTOCOL_VERSION
                    ),
                ));
            }

            let bound_mount_id = mount_name.as_deref().and_then(mount_lookup);
            if mount_name.is_some() && bound_mount_id.is_none() {
                let _ = wire::write_frame(
                    tx,
                    &Frame::HelloAck {
                        proto_version: PROTOCOL_VERSION,
                        max_inflight: 0,
                        bound_mount_id: None,
                    },
                )
                .await;
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("mount not registered: {:?}", mount_name),
                ));
            }

            wire::write_frame(
                tx,
                &Frame::HelloAck {
                    proto_version: PROTOCOL_VERSION,
                    max_inflight,
                    bound_mount_id,
                },
            )
            .await?;

            Ok(Some(max_inflight))
        }
        other => {
            tracing::warn!("vfs: first frame not Hello: {:?}", other);
            Err(io::Error::new(io::ErrorKind::InvalidData, "first frame not Hello"))
        }
    }
}

// ---------------------------------------------------------------------------
// Client side (blocking)
// ---------------------------------------------------------------------------

/// Perform the client-side `Hello`/`HelloAck` exchange (blocking).
///
/// Writes [`Frame::Hello`] to `rw`, reads and validates the server's
/// [`Frame::HelloAck`], and returns the `bound_mount_id` assigned by the
/// server.
///
/// # Errors
/// - I/O failure.
/// - Protocol version mismatch.
/// - Server did not bind `mount_name` (`bound_mount_id` was `None`).
pub fn client_handshake<RW>(rw: &mut RW, mount_name: &str, client_name: &str) -> io::Result<u32>
where
    RW: io::Read + io::Write,
{
    wire::blocking::write_frame(
        rw,
        &Frame::Hello {
            proto_version: PROTOCOL_VERSION,
            max_inflight: 64,
            client_name: client_name.to_string(),
            mount_name: Some(mount_name.to_string()),
        },
    )?;

    let ack =
        wire::blocking::read_frame(rw)?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no HelloAck"))?;

    match ack {
        Frame::HelloAck {
            proto_version,
            bound_mount_id,
            ..
        } => {
            if proto_version != PROTOCOL_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("proto mismatch: server={} client={}", proto_version, PROTOCOL_VERSION),
                ));
            }
            bound_mount_id.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "server did not bind mount_name"))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected HelloAck, got {other:?}"),
        )),
    }
}
