//! Windows named-pipe / HvSocket transport adapter for the unified
//! `InitClient`, plus the I/O adapters (`InitStdin`, `InitReader`,
//! `InitStream`) that wrap the client for use as standard I/O streams.

#![cfg(target_os = "windows")]

use std::io::{Read, Write};

use crate::Result;
use crate::init_client::{ChildEvents, InitClient, Inner, ReceivedFrame, Shared, TransportRecv, TransportSend};
use crate::protocol::types::Frame;
use crate::protocol::wire::{recv_frame_stream, send_frame_stream};

use super::ov_pipe::OvPipe;

// ---------------------------------------------------------------------------
// Transport halves
// ---------------------------------------------------------------------------

/// Outbound pipe / HvSocket send half.
pub struct PipeSend(pub(crate) Box<dyn Write + Send>);

/// Inbound pipe / HvSocket recv half.
pub struct PipeRecv(pub(crate) Box<dyn Read + Send>);

impl TransportSend for PipeSend {
    fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        send_frame_stream(&mut *self.0, frame)
    }
}

impl TransportRecv for PipeRecv {
    fn recv_frame(&mut self) -> Result<Option<ReceivedFrame>> {
        match recv_frame_stream(&mut *self.0) {
            Ok(None) => Ok(None),
            Ok(Some(frame)) => Ok(Some(ReceivedFrame { frame })),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete type alias exposed through `src/windows/init_client.rs`
// ---------------------------------------------------------------------------

// Re-export shared types so existing call sites compile unchanged.
pub use crate::init_client::{DrainedEvent, SpawnInfo};

impl crate::init_client::InitClient<PipeSend> {
    /// Build a client from the bidirectional `OvPipe`. The pipe is split via
    /// `try_clone()` (`DuplicateHandle` internally) so reader and writer share
    /// no I/O state.
    pub fn new(pipe: OvPipe) -> crate::Result<Self> {
        let read = pipe
            .try_clone()
            .map_err(|e| crate::Error::exec(format!("try_clone session pipe: {e}")))?;
        Self::with_transport(Box::new(pipe), Box::new(read))
    }

    /// Build a client from arbitrary transport halves.  Used by the Windows
    /// service to drive the in-VM init protocol over an HvSocket pair.
    pub fn with_transport(write_half: Box<dyn Write + Send>, read_half: Box<dyn Read + Send>) -> crate::Result<Self> {
        // VM mode: init is always PID 1.
        crate::init_client::InitClient::new(PipeSend(write_half), PipeRecv(read_half), true)
    }
}

// ---------------------------------------------------------------------------
// InitStdin — Write adapter forwarding bytes as Op::Write
// ---------------------------------------------------------------------------

/// `Write` adapter that turns bytes written to the long-lived shell's stdin
/// into `Op::Write` ops on the init protocol.
pub struct InitStdin {
    pub client: WinInitClient,
    pub child_id: String,
    pub closed: bool,
}

impl Write for InitStdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdin closed"));
        }
        self.client
            .write(&self.child_id, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InitReader — Read adapter draining buffered Stdout/Stderr events
// ---------------------------------------------------------------------------

/// Stream side selector for [`InitReader`].
#[derive(Clone, Copy, Debug)]
pub enum InitStream {
    Stdout,
    Stderr,
}

/// `Read` adapter that drains buffered child stream events.  Blocks the caller
/// (via the underlying `Condvar`) when no data is available, until a chunk
/// arrives, the child exits, or the connection dies.
pub struct InitReader {
    client: WinInitClient,
    child_id: String,
    side: InitStream,
    /// Carry-over bytes from the previous read when `buf` was smaller than
    /// the next available chunk.
    leftover: Vec<u8>,
}

impl InitReader {
    pub fn new(client: WinInitClient, child_id: String, side: InitStream) -> Self {
        Self {
            client,
            child_id,
            side,
            leftover: Vec::new(),
        }
    }
}

impl Read for InitReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.leftover.is_empty() {
            let n = buf.len().min(self.leftover.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }

        let (lock, cv) = &*self.client.inner.state;
        let mut g = lock
            .lock()
            .map_err(|_| std::io::Error::other("client state poisoned"))?;
        loop {
            let entry_has_data = g
                .children
                .get(&self.child_id)
                .map(|c| match self.side {
                    InitStream::Stdout => !c.stdout.is_empty(),
                    InitStream::Stderr => !c.stderr.is_empty(),
                })
                .unwrap_or(false);
            let exit_seen = g
                .children
                .get(&self.child_id)
                .map(|c| c.exit.is_some())
                .unwrap_or(false);

            if entry_has_data {
                let entry = g.children.entry(self.child_id.clone()).or_default();
                let chunks = match self.side {
                    InitStream::Stdout => std::mem::take(&mut entry.stdout),
                    InitStream::Stderr => std::mem::take(&mut entry.stderr),
                };
                drop(g);
                let mut concat = Vec::new();
                for c in chunks {
                    concat.extend_from_slice(&c);
                }
                let n = buf.len().min(concat.len());
                buf[..n].copy_from_slice(&concat[..n]);
                if n < concat.len() {
                    self.leftover.extend_from_slice(&concat[n..]);
                }
                return Ok(n);
            }

            if g.eof || exit_seen {
                // Drain any remaining events, then signal EOF.
                if let Some(c) = g.children.get_mut(&self.child_id) {
                    let chunks = match self.side {
                        InitStream::Stdout => std::mem::take(&mut c.stdout),
                        InitStream::Stderr => std::mem::take(&mut c.stderr),
                    };
                    if !chunks.is_empty() {
                        drop(g);
                        let mut concat = Vec::new();
                        for c in chunks {
                            concat.extend_from_slice(&c);
                        }
                        let n = buf.len().min(concat.len());
                        buf[..n].copy_from_slice(&concat[..n]);
                        if n < concat.len() {
                            self.leftover.extend_from_slice(&concat[n..]);
                        }
                        return Ok(n);
                    }
                }
                return Ok(0); // EOF
            }

            let g2 = cv.wait(g).map_err(|_| std::io::Error::other("client state poisoned"))?;
            g = g2;
        }
    }
}

// Type alias used by InitStdin / InitReader above — must be defined after
// impl block to avoid forward-reference issues inside this file.
type WinInitClient = InitClient<PipeSend>;

// Suppress dead-code lint for types used only through the public re-export.
const _: () = {
    let _ = std::mem::size_of::<Inner<PipeSend>>();
    let _ = std::mem::size_of::<Shared>();
    let _ = std::mem::size_of::<ChildEvents>();
};
