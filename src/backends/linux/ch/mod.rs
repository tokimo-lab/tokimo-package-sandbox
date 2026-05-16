//! Cloud Hypervisor backend.
//!
//! Submodules:
//! - [`backend`]  — `ChBackend` struct + `SandboxBackend` impl.
//! - [`vmm`]      — VM lifecycle helpers (spawn / stop / query).

pub mod backend;
pub mod probe;
pub mod vmm;

pub use backend::ChBackend;
pub use probe::{ChProbeResult, probe_ch};
