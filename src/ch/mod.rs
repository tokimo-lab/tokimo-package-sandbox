//! Cloud Hypervisor backend for the V3.0 PoC.
//!
//! Submodules:
//! - [`backend`]  — `ChBackend` struct + `SandboxBackend` impl (all methods
//!   are `unimplemented!` stubs; see TODO markers for each step).
//! - [`vmm`]      — VM lifecycle helpers (spawn / stop / query). V3.0-spawn.
//! - [`control`]  — vsock control plane (RPC codec, session handshake). V3.0-vsock.

pub mod backend;
pub mod control;
pub mod vmm;

pub use backend::ChBackend;
