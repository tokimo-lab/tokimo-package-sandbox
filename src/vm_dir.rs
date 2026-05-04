//! Cross-platform VM artifact directory discovery.
//!
//! Locates the directory containing `vmlinuz`, `initrd.img` and `rootfs/`.
//! Used by:
//!   - Linux backend (bwrap binds `rootfs/{usr,bin,sbin,lib,lib64}` into the sandbox)
//!   - macOS backend (VZ boots from these artifacts)
//!
//! Windows has its own discovery in `src/bin/tokimo-sandbox-svc/imp/mod.rs`
//! because the service runs as LocalSystem (no user `$HOME`) and uses
//! `rootfs.vhdx` instead of a `rootfs/` directory. The error wording is
//! kept in sync across all three platforms.
//!
//! Lookup order:
//!   1. `TOKIMO_VM_DIR` env var.
//!   2. `<repo>/vm/` walking up from `current_exe()` and `current_dir()`.
//!   3. `~/.tokimo/`.

use std::env;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Unified "rootfs missing" message used by every backend.
pub const ROOTFS_NOT_FOUND_MSG: &str = "rootfs not found. Place vmlinuz + initrd.img + rootfs/ in <repo>/vm/ \
or set TOKIMO_VM_DIR. Run scripts/<platform>/fetch-vm.* to download.";

pub fn find_vm_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("TOKIMO_VM_DIR") {
        let p = PathBuf::from(dir);
        if validate_vm_dir(&p) {
            return Ok(p);
        }
        return Err(Error::other(format!(
            "TOKIMO_VM_DIR={} is invalid. {}",
            p.display(),
            ROOTFS_NOT_FOUND_MSG
        )));
    }

    if let Ok(exe) = env::current_exe() {
        let mut cur: &Path = exe.as_path();
        for _ in 0..8 {
            if let Some(parent) = cur.parent() {
                let vm_dir = parent.join("vm");
                if validate_vm_dir(&vm_dir) {
                    return Ok(vm_dir);
                }
                cur = parent;
            } else {
                break;
            }
        }
    }

    if let Ok(cwd) = env::current_dir() {
        let mut cur: &Path = cwd.as_path();
        for _ in 0..8 {
            let vm_dir = cur.join("vm");
            if validate_vm_dir(&vm_dir) {
                return Ok(vm_dir);
            }
            if let Some(parent) = cur.parent() {
                cur = parent;
            } else {
                break;
            }
        }
    }

    if let Some(home) = env::var_os("HOME") {
        let p = PathBuf::from(home).join(".tokimo");
        if validate_vm_dir(&p) {
            return Ok(p);
        }
    }

    Err(Error::other(ROOTFS_NOT_FOUND_MSG))
}

pub fn validate_vm_dir(dir: &Path) -> bool {
    dir.join("vmlinuz").is_file() && dir.join("initrd.img").is_file() && dir.join("rootfs").is_dir()
}
