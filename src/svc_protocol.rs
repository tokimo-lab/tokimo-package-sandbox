//! Host ↔ Service wire protocol (Windows-only, but defined unconditionally
//! so tests on other platforms can serde-roundtrip the frames).
//!
//! Persistent JSON-RPC over a Windows named pipe. Frame format:
//!
//! ```text
//! [4 bytes BE u32 length][JSON body]
//! ```
//!
//! Lifecycle: client connects → sends `Hello` → service replies with
//! `Hello` → arbitrary number of `Request`/`Response`/`Event`/`Notification`
//! frames in either direction → client closes.
//!
//! Request IDs are caller-allocated strings; the service echoes them in
//! `Response`. Events carry no id and are delivered to subscribers.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 4;

/// One frame on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Mutual handshake. Carries the wire protocol version and a peer name.
    Hello {
        version: u32,
        peer: String,
        /// Free-form caller info for debug logs.
        #[serde(default)]
        info: serde_json::Value,
    },

    /// Client → service request. `method` is the command name, `id` the
    /// caller-allocated correlation id, `params` the JSON payload.
    Request {
        id: String,
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },

    /// Service → client response. Either `result` or `error` is set.
    Response {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
    },

    /// Service → client event (no correlation id).
    Event {
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },

    /// Either direction; method name + params, no response expected.
    Notification {
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl RpcError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Method names
// ---------------------------------------------------------------------------

pub mod method {
    pub const PING: &str = "ping";
    pub const CONFIGURE: &str = "configure";
    pub const CREATE_VM: &str = "createVm";
    pub const START_VM: &str = "startVm";
    pub const STOP_VM: &str = "stopVm";
    pub const IS_RUNNING: &str = "isRunning";
    pub const IS_GUEST_CONNECTED: &str = "isGuestConnected";
    pub const IS_PROCESS_RUNNING: &str = "isProcessRunning";
    pub const WRITE_STDIN: &str = "writeStdin";
    pub const SHELL_ID: &str = "shellId";
    pub const SPAWN_SHELL: &str = "spawnShell";
    pub const CLOSE_SHELL: &str = "closeShell";
    pub const LIST_SHELLS: &str = "listShells";
    pub const SIGNAL_SHELL: &str = "signalShell";
    pub const RESIZE_SHELL: &str = "resizeShell";
    pub const SUBSCRIBE: &str = "subscribe";
    pub const CREATE_DISK_IMAGE: &str = "createDiskImage";
    pub const SET_DEBUG_LOGGING: &str = "setDebugLogging";
    pub const IS_DEBUG_LOGGING_ENABLED: &str = "isDebugLoggingEnabled";
    pub const SEND_GUEST_RESPONSE: &str = "sendGuestResponse";
    pub const ADD_MOUNT: &str = "addMount";
    pub const REMOVE_MOUNT: &str = "removeMount";

    // Management / introspection ops (additive, do not require a
    // PROTOCOL_VERSION bump — old clients simply don't call them).
    pub const LIST_SESSIONS: &str = "listSessions";
    pub const SESSION_INFO: &str = "sessionInfo";
    pub const STOP_SESSION: &str = "stopSession";

    // Event names (service → client)
    pub const EV_STDOUT: &str = "stdout";
    pub const EV_STDERR: &str = "stderr";
    pub const EV_EXIT: &str = "exit";
    pub const EV_ERROR: &str = "error";
    pub const EV_READY: &str = "ready";
    pub const EV_GUEST_CONNECTED: &str = "guestConnected";
    pub const EV_NETWORK_STATUS: &str = "networkStatus";
    pub const EV_API_REACHABILITY: &str = "apiReachability";
}

// ---------------------------------------------------------------------------
// Wire framing helpers (length-prefixed)
// ---------------------------------------------------------------------------

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Encode a frame as `[u32 BE length][JSON body]`.
pub fn encode_frame(frame: &Frame) -> std::io::Result<Vec<u8>> {
    let body = serde_json::to_vec(frame).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    Ok(buf)
}

/// Decode a frame from a byte slice that already contains exactly one
/// JSON body (no length prefix).
pub fn decode_body(body: &[u8]) -> std::io::Result<Frame> {
    serde_json::from_slice(body).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Typed param/result helpers
// ---------------------------------------------------------------------------

/// Wire result for `shellId` (and any other op returning a single JobId).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobIdResult {
    pub id: String,
}

/// Wire result for `listShells` — the set of currently-active shell JobIds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobIdListResult {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteStdinParams {
    pub id: String,
    pub data: Vec<u8>,
}

/// Parameters for `signalShell` — deliver a POSIX signal to a specific
/// shell's foreground process group, identified by the JobId returned
/// from `shellId` or `spawnShell`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalShellParams {
    pub id: String,
    pub sig: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdParams {
    pub id: String,
}

/// Parameters for `spawnShell` (PROTOCOL_VERSION 4). All fields are
/// optional; absent fields preserve the v3 default behaviour (pipes-mode
/// boot shell with the service's default argv/env/cwd).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpawnShellParams {
    /// PTY rows. When both `pty_rows` and `pty_cols` are `Some`, the
    /// service spawns the shell with a controlling PTY of that size.
    #[serde(default)]
    pub pty_rows: Option<u16>,
    /// PTY cols. See `pty_rows`.
    #[serde(default)]
    pub pty_cols: Option<u16>,
    /// argv override. `None` → service default (`/bin/bash`).
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    /// Env overlay applied on top of the session-wide env.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Initial cwd override. `None` → service default.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Parameters for `resizeShell`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResizeShellParams {
    pub id: String,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoolValue {
    pub value: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDiskImageParams {
    pub path: std::path::PathBuf,
    pub gib: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMountParams {
    pub share: crate::Mount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveMountParams {
    pub name: String,
}

/// Wire result for `listSessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSessionsResult {
    pub sessions: Vec<crate::SessionSummary>,
}

/// Parameters for `sessionInfo` / `stopSession`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNameParams {
    pub name: String,
}

/// Wire result for `sessionInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfoResult {
    /// `None` when the named session does not exist.
    #[serde(default)]
    pub details: Option<crate::SessionDetails>,
}

// ---------------------------------------------------------------------------
// Internal types shared with the svc binary
// ---------------------------------------------------------------------------

/// Rootfs strategy. Used by the svc's `vhdx_pool` to decide whether to clone
/// the read-only template into a per-session ephemeral file or lock onto a
/// caller-supplied persistent target.
///
/// This type is part of the in-process boundary between the lib (which
/// exposes it via `tokimo_package_sandbox::svc_protocol`) and the
/// `tokimo-sandbox-svc` binary, which keeps its own VHDX pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootfsSpec {
    /// Clone `template` to a unique per-session file; delete on teardown.
    Ephemeral { template: String },
    /// Use `target` directly (clone from `template` on first use). Locked
    /// for the lifetime of the lease — concurrent `acquire` for the same
    /// canonical target is rejected.
    Persistent { template: String, target: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStdio {
    pub id: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

// `serde_bytes` would be a nice-to-have but adds a dep. Inline impl:
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventExit {
    pub id: String,
    pub exit_code: i32,
    #[serde(default)]
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventError {
    #[serde(default)]
    pub id: Option<String>,
    pub message: String,
    #[serde(default)]
    pub fatal: bool,
}
