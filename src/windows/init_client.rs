//! Compatibility shim: re-exports `InitClient<PipeSend>` as `WinInitClient`
//! and the associated I/O adapters from `init_transport`.
//!
//! The public path `tokimo_package_sandbox::init_client::WinInitClient` is
//! preserved via `pub use windows::init_client` in `src/lib.rs`.

#![cfg(target_os = "windows")]

pub use crate::init_client::{ChildEvents, DrainedEvent, SpawnInfo};
pub use crate::windows::init_transport::{InitReader, InitStdin, InitStream};

/// Windows init client — `InitClient<PipeSend>` behind the original name.
pub type WinInitClient = crate::init_client::InitClient<crate::windows::init_transport::PipeSend>;
