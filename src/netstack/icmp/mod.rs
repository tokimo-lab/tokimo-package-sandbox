//! OS-specific ICMP echo backend used by the netstack ICMP-proxy worker.
//!
//! Both functions are blocking; they should be called from a dedicated worker
//! thread. They return `true` iff at least one EchoReply was received within
//! `timeout`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[cfg(target_os = "windows")]
mod imp_windows;
#[cfg(target_os = "windows")]
pub(crate) use imp_windows::{send_echo_v4, send_echo_v6};

#[cfg(unix)]
mod imp_unix;
#[cfg(unix)]
pub(crate) use imp_unix::{send_echo_v4, send_echo_v6};

// Type re-exports so call sites don't need their own imports.
#[allow(dead_code)]
pub(super) type Ipv4 = Ipv4Addr;
#[allow(dead_code)]
pub(super) type Ipv6 = Ipv6Addr;
#[allow(dead_code)]
pub(super) type Dur = Duration;
