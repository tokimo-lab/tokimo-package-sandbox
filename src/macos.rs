//! macOS sandbox: Virtualization.framework backend.
//!
//! Boots a lightweight Linux VM for Linux-grade isolation on macOS.
//! Requires a Linux kernel + initrd from tokimo-package-rootfs.

#![cfg(target_os = "macos")]

mod vz;

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

pub(crate) fn spawn_session_shell(_cfg: &SandboxConfig) -> Result<crate::session::ShellHandle> {
    Err(Error::validation(
        "Session shell is not yet supported on macOS VZ backend. \
         Use run() for one-shot command execution.",
    ))
}
