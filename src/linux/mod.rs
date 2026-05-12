//! Linux sandbox backends.
//!
//! Linux supports two backend implementations sharing the same `tokimo-sandbox-init`
//! guest binary:
//! - [`bwrap`] — namespace-only sandbox via `bubblewrap`.
//! - [`ch`]    — micro-VM sandbox via Cloud Hypervisor + virtiofsd.

pub(crate) mod bwrap;
pub mod ch;
