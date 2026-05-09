//! Cloud Hypervisor backend for the V3.0 PoC.
//!
//! Submodules:
//! - [`backend`]  — `ChBackend` struct + `SandboxBackend` impl.
//! - [`vmm`]      — VM lifecycle helpers (spawn / stop / query). V3.0-spawn.
//! - [`rpc`]      — Host-side guest-agent RPC client over hybrid vsock. V3.0-vsock.
//! - [`control`]  — vsock control plane placeholder (future: session handshake).

pub mod backend;
pub mod control;
pub mod rpc;
pub mod vmm;

pub use backend::ChBackend;
