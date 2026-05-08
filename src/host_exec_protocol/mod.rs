//! Wire protocol for the host-exec bridge channel.
//!
//! Simple postcard-framed protocol (see [`wire`] for the framing).
//! Used between `tokimo-host-exec` (guest binary) and `HostExecBridge`
//! (host).

use serde::{Deserialize, Serialize};

pub mod wire;

pub const HOST_EXEC_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    Hello {
        protocol: u32,
    },
    HelloAck {
        protocol: u32,
        ok: bool,
        error: Option<String>,
    },
    Spawn {
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        pty: Option<PtySize>,
    },
    SpawnAck {
        ok: bool,
        error: Option<String>,
    },
    Stdin(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Resize(PtySize),
    Signal {
        sig: i32,
    },
    Exit {
        code: i32,
        signal: Option<i32>,
    },
}
