//! Host-side cross-platform helpers.
//!
//! - [`pty`] — host-side PTY master allocation and raw-mode setup (Unix).
//! - [`common`] — Unix process spawn / stdio plumbing helpers shared by
//!   the Linux and macOS backends.
//! - [`net_observer`] — L7 HTTP(S) proxy + DNS policy used to enforce
//!   `NetworkPolicy::Observed` / `Gated` (Linux today; macOS in future).

#[cfg(unix)]
pub(crate) mod common;
pub(crate) mod net_observer;
#[cfg(target_os = "macos")]
pub(crate) mod pty;
