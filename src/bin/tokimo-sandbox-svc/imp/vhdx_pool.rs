//! Per-target rootfs VHDX leasing.
//!
//! The Windows session backend supports two rootfs policies:
//!
//! * **Ephemeral** — clone the read-only template VHDX into a unique
//!   per-session path, delete it on teardown.
//! * **Persistent** — caller picks a `target` path. First lease clones
//!   the template into `target` (preserving the VHDX dynamic format).
//!   Subsequent leases reuse `target` directly, so writes to `/usr`,
//!   `/etc`, `/var`, etc. survive. The target path is locked while a
//!   lease is alive so a second concurrent `acquire()` for the same
//!   canonical path fails with [`SvcError::Busy`].

#![cfg(target_os = "windows")]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use tokimo_package_sandbox::canonicalize_safe;
use tokimo_package_sandbox::svc_protocol::RootfsSpec;

/// Outcome categories returned to the caller as a typed error rather than
/// a stringly-typed code so the wire layer stays self-describing.
#[derive(Debug)]
pub enum PoolError {
    BadTemplate(String),
    BadTarget(String),
    Busy(PathBuf),
    Io(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::BadTemplate(s) => write!(f, "rootfs template invalid: {s}"),
            PoolError::BadTarget(s) => write!(f, "rootfs target invalid: {s}"),
            PoolError::Busy(p) => write!(f, "rootfs target already in use: {}", p.display()),
            PoolError::Io(s) => write!(f, "rootfs I/O error: {s}"),
        }
    }
}

fn registry() -> &'static Mutex<HashSet<PathBuf>> {
    static REG: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Active lease on a rootfs VHDX. Drop releases the lock; for ephemeral
/// leases the file is also deleted.
#[derive(Debug)]
pub struct VhdxLease {
    path: PathBuf,
    canonical: PathBuf,
    persistent: bool,
}

impl VhdxLease {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VhdxLease {
    fn drop(&mut self) {
        if let Ok(mut g) = registry().lock() {
            g.remove(&self.canonical);
        }
        if !self.persistent {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Acquire a rootfs lease.
///
/// * `Ephemeral { template }` clones `template` to a unique per-session
///   file inside `scratch_dir` named `.tokimo-rootfs-<vm_id>.vhdx`.
/// * `Persistent { template, target }` uses `target` directly, cloning
///   from `template` only on first use. The lock is keyed on the
///   canonicalized `target` path.
pub fn acquire(spec: &RootfsSpec, scratch_dir: &Path, vm_id: &str) -> Result<VhdxLease, PoolError> {
    match spec {
        RootfsSpec::Ephemeral { template } => acquire_ephemeral(Path::new(template), scratch_dir, vm_id),
        RootfsSpec::Persistent { template, target } => acquire_persistent(Path::new(template), Path::new(target)),
    }
}

fn acquire_ephemeral(template: &Path, scratch_dir: &Path, vm_id: &str) -> Result<VhdxLease, PoolError> {
    let template =
        canonicalize_safe(template).map_err(|e| PoolError::BadTemplate(format!("{}: {e}", template.display())))?;
    if !template.is_file() {
        return Err(PoolError::BadTemplate(format!(
            "template not a file: {}",
            template.display()
        )));
    }
    let dst = scratch_dir.join(format!(".tokimo-rootfs-{vm_id}.vhdx"));
    if dst.exists() {
        let _ = std::fs::remove_file(&dst);
    }
    std::fs::copy(&template, &dst)
        .map_err(|e| PoolError::Io(format!("clone {} -> {}: {e}", template.display(), dst.display())))?;
    let canonical = dst.clone();
    // Track the ephemeral file in the registry too — keeps the API
    // uniform and protects against a caller racing two ephemeral
    // sessions onto the same scratch_dir + vm_id (shouldn't happen but
    // doesn't hurt).
    {
        let mut g = registry().lock().expect("vhdx pool registry");
        if !g.insert(canonical.clone()) {
            // Extremely unlikely — the vm_id is a per-process unique
            // suffix. Treat as an internal error.
            return Err(PoolError::Busy(canonical));
        }
    }
    Ok(VhdxLease {
        path: dst,
        canonical,
        persistent: false,
    })
}

fn acquire_persistent(template: &Path, target: &Path) -> Result<VhdxLease, PoolError> {
    let template =
        canonicalize_safe(template).map_err(|e| PoolError::BadTemplate(format!("{}: {e}", template.display())))?;
    if !template.is_file() {
        return Err(PoolError::BadTemplate(format!(
            "template not a file: {}",
            template.display()
        )));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| PoolError::BadTarget(format!("create parent of {}: {e}", target.display())))?;
    }
    // Canonicalize target against parent + filename so that we can lock
    // even before the file exists.
    let canonical = canonicalize_target_path(target)?;
    {
        let mut g = registry().lock().expect("vhdx pool registry");
        if !g.insert(canonical.clone()) {
            return Err(PoolError::Busy(canonical));
        }
    }
    let lease_path = canonical.clone();
    if !lease_path.exists() {
        // First lease for this target — clone the template.
        if let Err(e) = std::fs::copy(&template, &lease_path) {
            // Release the lock we just took before bubbling up.
            if let Ok(mut g) = registry().lock() {
                g.remove(&canonical);
            }
            return Err(PoolError::Io(format!(
                "initial clone {} -> {}: {e}",
                template.display(),
                lease_path.display()
            )));
        }
    }
    Ok(VhdxLease {
        path: lease_path,
        canonical,
        persistent: true,
    })
}

/// Canonicalize a target path that may not yet exist by canonicalizing
/// the parent directory and re-joining the file name. Falls back to the
/// raw path when the parent is missing (which `acquire_persistent`
/// rejects earlier anyway).
fn canonicalize_target_path(target: &Path) -> Result<PathBuf, PoolError> {
    let parent = target
        .parent()
        .ok_or_else(|| PoolError::BadTarget(format!("no parent: {}", target.display())))?;
    let file = target
        .file_name()
        .ok_or_else(|| PoolError::BadTarget(format!("no file name: {}", target.display())))?;
    let parent = canonicalize_safe(parent).map_err(|e| PoolError::BadTarget(format!("{}: {e}", parent.display())))?;
    Ok(parent.join(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(p: &Path) {
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn ephemeral_clones_and_cleans_up() {
        let scratch = tempfile::tempdir().unwrap();
        let template = scratch.path().join("template.vhdx");
        touch(&template);
        let lease = acquire(
            &RootfsSpec::Ephemeral {
                template: template.to_string_lossy().into_owned(),
            },
            scratch.path(),
            "vm-1",
        )
        .unwrap();
        let p = lease.path().to_path_buf();
        assert!(p.exists());
        drop(lease);
        assert!(!p.exists(), "ephemeral lease must delete on drop");
    }

    #[test]
    fn persistent_initial_clone_then_reuse() {
        let scratch = tempfile::tempdir().unwrap();
        let template = scratch.path().join("template.vhdx");
        std::fs::write(&template, b"DATA").unwrap();
        let target = scratch.path().join("persist.vhdx");

        let spec = RootfsSpec::Persistent {
            template: template.to_string_lossy().into_owned(),
            target: target.to_string_lossy().into_owned(),
        };
        let l1 = acquire(&spec, scratch.path(), "v1").unwrap();
        let p = l1.path().to_path_buf();
        assert!(p.exists());
        drop(l1);
        assert!(p.exists(), "persistent lease must NOT delete on drop");

        // Modify so we can prove a second acquire reuses (does not re-clone).
        std::fs::write(&p, b"MUTATED").unwrap();
        let l2 = acquire(&spec, scratch.path(), "v2").unwrap();
        let bytes = std::fs::read(l2.path()).unwrap();
        assert_eq!(bytes, b"MUTATED");
        drop(l2);
    }

    #[test]
    fn persistent_busy_rejected() {
        let scratch = tempfile::tempdir().unwrap();
        let template = scratch.path().join("template.vhdx");
        touch(&template);
        let target = scratch.path().join("persist2.vhdx");

        let spec = RootfsSpec::Persistent {
            template: template.to_string_lossy().into_owned(),
            target: target.to_string_lossy().into_owned(),
        };
        let l1 = acquire(&spec, scratch.path(), "v1").unwrap();
        let err = acquire(&spec, scratch.path(), "v2").unwrap_err();
        assert!(matches!(err, PoolError::Busy(_)));
        drop(l1);
        // Now lock is released, second acquire should succeed.
        let _l2 = acquire(&spec, scratch.path(), "v3").unwrap();
    }

    #[test]
    fn ephemeral_rejects_missing_template() {
        let scratch = tempfile::tempdir().unwrap();
        let bogus = scratch.path().join("nope.vhdx");
        let err = acquire(
            &RootfsSpec::Ephemeral {
                template: bogus.to_string_lossy().into_owned(),
            },
            scratch.path(),
            "vm",
        )
        .unwrap_err();
        assert!(matches!(err, PoolError::BadTemplate(_)));
    }
}
