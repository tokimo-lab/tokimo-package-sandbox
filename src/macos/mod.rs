//! macOS sandbox: Virtualization.framework backend.
//!
//! Boots a lightweight Linux VM for Linux-grade isolation on macOS.
//! Requires a Linux kernel + initrd from tokimo-package-rootfs.

#![cfg(target_os = "macos")]

mod vz;
pub(crate) mod vz_session;
pub(crate) mod vz_vsock;

use crate::config::SandboxConfig;
use crate::{Error, ExecutionResult, Result};

pub(crate) fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    if !vz::is_available() {
        return Err(Error::validation(
            "Virtualization.framework not available (requires macOS 11+ on Apple Silicon or Intel VT-x)",
        ));
    }
    vz::run(cmd, cfg)
}

pub(crate) fn spawn_session_shell(cfg: &SandboxConfig) -> Result<crate::session::ShellHandle> {
    if !vz::is_available() {
        return Err(Error::validation(
            "Virtualization.framework not available (requires macOS 11+)",
        ));
    }
    vz_session::spawn_session_shell(cfg)
}
