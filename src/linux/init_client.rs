//! Compatibility shim: re-exports `InitClient<SeqpacketSend>` under the
//! original `InitClient` name used by `linux/sandbox.rs`.

#![cfg(target_os = "linux")]

pub use crate::init_client::DrainedEvent;
pub use crate::linux::init_transport::SeqpacketSend;

/// Linux init client — `InitClient<SeqpacketSend>` behind the original name.
pub type InitClient = crate::init_client::InitClient<SeqpacketSend>;
