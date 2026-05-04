//! Windows backend for the Sandbox public API.
//!
//! Architecture:
//!
//! ```text
//! Sandbox client                            tokimo-sandbox-svc.exe (LocalSystem)
//! ─────────────                            ───────────────────────────────────
//! WindowsBackend::connect()    ─pipe─►     accept connection on \\.\pipe\tokimo-sandbox-svc
//!   ├ open named pipe + Hello              read Hello, reply Hello
//!   ├ background reader thread             persistent loop dispatching JSON-RPC
//!   │  ↳ Response → pending oneshots         configure / createVm / startVm / …
//!   │  ↳ Event    → mpsc subscribers         startVm boots HCS + WinInitClient
//!   └ public API methods send Request,      forward exec/spawn/writeStdin/kill
//!     block on oneshot reply                via WinInitClient → guest init.
//! ```
//!
//! All Win32 calls go through `windows = "0.62"`; only `ComputeCore.dll`
//! (HCS API) is loaded dynamically (in the bin's `imp/hcs.rs`).
//!
//! Wire framing & types: see [`crate::svc_protocol`].

#![cfg(target_os = "windows")]

pub(crate) mod client;
pub mod init_client;
pub(crate) mod init_transport;
pub(crate) mod ov_pipe;
pub(crate) mod safe_path;
pub(crate) mod sandbox;

pub use safe_path::canonicalize_safe;

/// Named pipe used by the library to talk to `tokimo-sandbox-svc`. Kept in
/// sync with the constant in `src/bin/tokimo-sandbox-svc/imp/mod.rs`.
pub const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";
