//! Cross-platform base rootfs validation.
//!
//! Validates that the user-supplied `base_rootfs` directory contains the
//! required VM artifacts for the current platform.

use std::path::Path;

use crate::error::{Error, Result};

/// Error prefix when the base rootfs directory is missing or incomplete.
pub const ROOTFS_NOT_FOUND_MSG: &str = "base_rootfs not found or incomplete. \
Run scripts/<platform>/fetch-vm.* to download the required artifacts \
(kernel from vm-kernel-* tag, rootfs from vm-rootfs-* tag).";

/// Validate that `base` contains the platform-required artifacts.
///
/// - Linux/macOS: `vmlinuz`, `initrd.img`, `rootfs/` (directory).
/// - Windows: `vmlinuz`, `initrd.img`, `rootfs.vhdx` (file).
pub fn validate_base_rootfs(base: &Path) -> Result<()> {
    if !base.is_dir() {
        return Err(Error::other(format!(
            "base_rootfs is not a directory: {}",
            base.display()
        )));
    }
    if !base.join("vmlinuz").is_file() {
        return Err(Error::other(format!("base_rootfs missing vmlinuz: {}", base.display())));
    }
    if !base.join("initrd.img").is_file() {
        return Err(Error::other(format!(
            "base_rootfs missing initrd.img: {}",
            base.display()
        )));
    }
    #[cfg(target_os = "windows")]
    {
        if !base.join("rootfs.vhdx").is_file() {
            return Err(Error::other(format!(
                "base_rootfs missing rootfs.vhdx: {}",
                base.display()
            )));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if !base.join("rootfs").is_dir() {
            return Err(Error::other(format!(
                "base_rootfs missing rootfs/ directory: {}",
                base.display()
            )));
        }
    }
    Ok(())
}
