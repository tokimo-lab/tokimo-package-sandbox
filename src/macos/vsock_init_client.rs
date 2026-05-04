//! Compatibility shim: re-exports `InitClient<VsockSend>` under the original
//! `VsockInitClient` name used by `macos/sandbox.rs`.

pub use crate::init_client::SpawnInfo;
pub use crate::macos::init_transport::VsockSend;

/// macOS init client — `InitClient<VsockSend>` behind the original name.
pub type VsockInitClient = crate::init_client::InitClient<VsockSend>;
