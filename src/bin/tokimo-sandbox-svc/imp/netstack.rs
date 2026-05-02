//! Userspace network stack — thin re-export of the cross-platform
//! implementation in [`tokimo_package_sandbox::netstack`].
//!
//! The actual smoltcp engine, ICMP backends, TCP/UDP flow management and
//! reply-frame builders live in the library so that macOS (vsock) and
//! Windows (hvsock) share a single source of truth. This file only exists
//! to provide a stable in-binary path (`crate::imp::netstack::spawn`) for
//! the rest of the svc binary.

pub use tokimo_package_sandbox::netstack::{EgressPolicy, spawn};
