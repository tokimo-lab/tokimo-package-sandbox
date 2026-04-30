//! Wire protocol for the host ↔ in-sandbox init control channel.
//!
//! Transport: `SOCK_SEQPACKET` Unix domain socket (one packet = one message).
//! Encoding: UTF-8 JSON, optionally with a single fd attached as ancillary
//! `SCM_RIGHTS` (used for PTY master fd transfer in the `Spawn(Pty)` reply).
//!
//! Per `plan.md`, packet payload size is capped at 64 KiB; init slices shell
//! stdout/stderr to ~16 KiB chunks before emitting `Stdout` / `Stderr` events.

use serde::{Deserialize, Serialize};

/// Current protocol revision. Bumped on any breaking change to op / event
/// shape. Init's `Hello` reply MUST match the host's `Hello.protocol` exactly.
///
/// v2: added [`Op::MountManifest`] / [`Reply::MountManifest`] / [`FsType`]
///     for macOS multi-mount support.
pub const PROTOCOL_VERSION: u32 = 2;

/// Maximum payload size (in bytes) of a single SEQPACKET message.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Cap for a single Stdout/Stderr event emitted by init. Larger reads are
/// fragmented into multiple events to stay below `MAX_FRAME_BYTES`.
pub const STREAM_CHUNK_BYTES: usize = 16 * 1024;

/// Stdio mode requested when spawning a child.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum StdioMode {
    /// Connect stdin/stdout/stderr to anonymous pipes; init pumps bytes
    /// across the control channel via `Write` op + `Stdout`/`Stderr` events.
    Pipes,
    /// Allocate a PTY pair; the master fd is sent back to the host via
    /// `SCM_RIGHTS` in the same packet as the `SpawnReply`. Init does NOT
    /// pump bytes for PTY children — host owns the master directly.
    Pty { rows: u16, cols: u16 },
}

/// Host → init request. The `id` field is echoed verbatim into the reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Op {
    /// Mandatory first message. Init replies with its own `Hello` echoing
    /// `protocol` + `features` + the actual `init_pid` (must be 1).
    Hello {
        id: String,
        protocol: u32,
        #[serde(default)]
        features: Vec<String>,
    },
    /// Open a long-lived shell child (used by `Session` for the sentinel-
    /// based REPL protocol). Equivalent to `Spawn { stdio: Pipes }` but
    /// kept as a distinct op so init can apply shell-specific defaults if
    /// needed in the future.
    OpenShell {
        id: String,
        argv: Vec<String>,
        #[serde(default)]
        env_overlay: Vec<(String, String)>,
        #[serde(default)]
        cwd: Option<String>,
    },
    /// Spawn an arbitrary child.
    Spawn {
        id: String,
        argv: Vec<String>,
        #[serde(default)]
        env_overlay: Vec<(String, String)>,
        #[serde(default)]
        cwd: Option<String>,
        stdio: StdioMode,
        /// If set, init reads `/proc/<pid>/cwd` and `/proc/<pid>/environ`
        /// from the referenced child and uses them as the base environment
        /// and default cwd for the new child. Explicit `cwd` and
        /// `env_overlay` take precedence.
        #[serde(default)]
        inherit_from_child: Option<String>,
    },
    /// Write `data_b64` (base64-encoded) to the named child's stdin (pipes
    /// mode). For PTY children this is a no-op — host writes to the master
    /// fd directly.
    Write {
        id: String,
        child_id: String,
        data_b64: String,
    },
    /// Resize a PTY child: `ioctl(master, TIOCSWINSZ)` + `killpg(SIGWINCH)`.
    Resize {
        id: String,
        child_id: String,
        rows: u16,
        cols: u16,
    },
    /// Send a signal. `to_pgrp` defaults to true (use `killpg`).
    Signal {
        id: String,
        child_id: String,
        sig: i32,
        #[serde(default = "default_true")]
        to_pgrp: bool,
    },
    /// Wait for the child to exit. Reply carries exit code + signal.
    /// Until exit, no immediate reply is sent — the eventual `Exit` event
    /// is the completion signal. Multiple Wait calls are coalesced.
    Wait { id: String, child_id: String },
    /// Close stdin for the child (pipes) / close master fd (PTY).
    Close { id: String, child_id: String },
    /// Tear the whole sandbox down: send SIGTERM, then SIGKILL after a
    /// short grace, then exit init (which lets bwrap collapse the namespace).
    Shutdown {
        id: String,
        #[serde(default = "default_true")]
        kill_all: bool,
    },
    /// Create a per-user isolated workspace inside the shared init container.
    /// Init creates `/tmp/<user_id>` and `/work/<user_id>`, merges env with
    /// `TMPDIR`/`HOME` pointed at the per-user paths, then spawns a bash
    /// shell. The reply includes the shell's `child_id`.
    AddUser {
        id: String,
        user_id: String,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env_overlay: Vec<(String, String)>,
    },
    /// Remove a user: SIGKILL all children owned by the requesting client,
    /// then (eventually) clean up /tmp/<user_id>.
    RemoveUser { id: String, user_id: String },
    /// Dynamic bind mount inside the container. `source` must be a path
    /// already visible inside the container (e.g., pre-mounted host dir).
    /// `target` is the mount point created by init.
    BindMount {
        id: String,
        source: String,
        target: String,
        read_only: bool,
    },
    /// Unmount a previously bind-mounted path.
    Unmount { id: String, target: String },
    /// Mount a batch of host-provided shares into the guest at boot time.
    /// Currently used by macOS VZ (virtiofs tag-based shares) for multi-mount
    /// support equivalent to Linux `extra_mounts`. The host side wires up
    /// each share as a virtiofs device with a unique tag (`source`) and asks
    /// init to mount each at the requested `target`.
    MountManifest { id: String, entries: Vec<MountEntry> },
}

/// Filesystem type for a [`MountEntry`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FsType {
    /// VZ virtiofs share. `source` is the device tag set on the host
    /// (`VirtioFileSystemDeviceConfiguration::new(<tag>)`), `target` is the
    /// absolute guest path. Init does:
    /// `mount(source, target, "virtiofs", MS_NODEV|MS_NOSUID|<RO?>, NULL)`.
    Virtiofs,
}

/// One entry in [`Op::MountManifest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    /// Tag/share name visible to the guest mount call.
    pub source: String,
    /// Absolute guest path. Init will `mkdir -p` it before mounting.
    pub target: String,
    pub fs_type: FsType,
    #[serde(default)]
    pub read_only: bool,
}

fn default_true() -> bool {
    true
}

/// Init → host reply. `id` matches the originating `Op.id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Reply {
    /// Hello handshake reply. `init_pid` MUST be 1 (init self-asserts) — host
    /// MUST verify before sending any further op.
    Hello {
        id: String,
        ok: bool,
        protocol: u32,
        features: Vec<String>,
        init_pid: i32,
        #[serde(default)]
        error: Option<ErrorReply>,
    },
    /// Reply to `OpenShell` / `Spawn`. For PTY mode, the master fd is
    /// attached as `SCM_RIGHTS` ancillary in the same packet.
    Spawn {
        id: String,
        ok: bool,
        #[serde(default)]
        child_id: Option<String>,
        #[serde(default)]
        pid: Option<i32>,
        #[serde(default)]
        error: Option<ErrorReply>,
    },
    /// Generic ack for `Write` / `Resize` / `Signal` / `Close` / `Shutdown`.
    Ack {
        id: String,
        ok: bool,
        #[serde(default)]
        error: Option<ErrorReply>,
    },
    /// Reply to [`Op::MountManifest`]. On failure, `failed_index` points at
    /// the first entry that failed; remaining entries are not attempted.
    MountManifest {
        id: String,
        ok: bool,
        #[serde(default)]
        failed_index: Option<usize>,
        #[serde(default)]
        error: Option<ErrorReply>,
    },
}

/// Structured error code returned in `Reply.error`. Per plan §11.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReply {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidCwd,
    ExecNotFound,
    PermissionDenied,
    ForkFailed,
    EnvProtected,
    BadHandshake,
    UnknownChild,
    BadRequest,
    Internal,
}

impl ErrorReply {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Async event pushed from init to host. PTY children do not emit
/// Stdout/Stderr — host reads/writes the master fd directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    Stdout {
        child_id: String,
        data_b64: String,
    },
    Stderr {
        child_id: String,
        data_b64: String,
    },
    Exit {
        child_id: String,
        code: i32,
        signal: Option<i32>,
    },
}

/// One framed message on the wire. Either a request (host → init), reply
/// (init → host), or an unsolicited event (init → host). They all share
/// the same JSON envelope; the `_kind_envelope` discriminator keeps parsing
/// a single tagged enum on each side trivial.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "envelope")]
pub enum Frame {
    Op(Op),
    Reply(Reply),
    Event(Event),
}

/// Names of the features advertised in the `Hello` handshake. Both sides
/// hard-code the same list for v1 — versioning bumps `PROTOCOL_VERSION`.
pub fn default_features() -> Vec<String> {
    vec![
        "pipes".into(),
        "pty".into(),
        "resize".into(),
        "signal".into(),
        "killpg".into(),
        "openshell".into(),
        "adduser".into(),
        "removeuser".into(),
        "bindmount".into(),
        "unmount".into(),
        "mount_manifest".into(),
    ]
}
