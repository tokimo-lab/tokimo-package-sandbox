//! Wire protocol spoken between the host and `tokimo-sandbox-init` (PID 1
//! inside the sandbox container).
//!
//! The protocol consists of length-prefixed JSON frames. Both SEQPACKET
//! (Linux Unix socket) and stream (VSOCK / virtio-serial) transports are
//! supported via two parallel framing helpers in [`wire`].
//!
//! - [`types`] — operation / reply / event enums and version constants
//! - [`wire`]  — frame encode / decode and transport read/write helpers

pub mod types;
pub mod wire;

pub use types::*;
pub use wire::*;
