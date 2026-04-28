//! Client-side interface to the tokimo-sandbox-svc Windows service.
//!
//! When the service is available, VM operations are delegated to it via
//! named pipe. This eliminates the need for the calling user to be in the
//! Hyper-V Administrators group.

pub mod client;
pub mod protocol;
