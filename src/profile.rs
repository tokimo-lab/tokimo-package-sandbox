//! Per-session rootfs profile materialisation.
//!
//! This module implements the on-disk layout used by sandbox callers
//! that want a hybrid container rootfs: a shared read-only base plus a
//! per-session writable copy of selected subdirectories
//! (`/etc /var /home /root`), with an optional overlay tree applied on
//! first boot and per-process UID/GID substitution in `etc/passwd` /
//! `etc/group`.
//!
//! The materialisation is **idempotent** — once the sentinel file
//! exists under the per-session root, subsequent calls return
//! immediately so user/AI edits inside the session persist across
//! reboots.
//!
//! ## Overlay
//!
//! Callers pass an explicit `Option<&Path>` for the overlay root.
//! - `None` → no overlay layer is applied (silent).
//! - `Some(p)` where `p` does not exist → silently skipped.
//! - `Some(p)` where `p` exists → recursively copied on top of the
//!   per-session subtree, **overwriting** any colliding files.
//!
//! Resolving the overlay path (env vars, dev fallbacks, etc.) is the
//! caller's responsibility; this crate is pure file-system logic.
//!
//! ## UID/GID substitution
//!
//! After base copy + overlay, the per-session `etc/passwd` and
//! `etc/group` files (if present) have `{{UID}}` / `{{GID}}`
//! placeholders replaced with the host process's real uid/gid so the
//! in-sandbox account owns the bind-mounted RW dirs.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Sentinel file written under the per-session root once
/// [`materialise_per_agent_rootfs`] has finished. Its presence short-
/// circuits subsequent calls.
pub const ROOTFS_READY_SENTINEL: &str = ".tokimo-rootfs-ready";

/// Per-session RW subdirectories copied from the shared base into the
/// per-session root on first boot.
pub const RW_SUBDIRS: &[&str] = &["etc", "var", "home", "root"];

/// Idempotent per-session rootfs materialisation:
///
/// 1. If the sentinel file exists under `agent_root` → return immediately.
/// 2. `mkdir -p agent_root`.
/// 3. Copy `base/<sub>` → `agent_root/<sub>` for each `sub` in
///    [`RW_SUBDIRS`] (skipping subs that don't exist in `base`).
/// 4. If `overlay` is `Some(p)` and `p` exists, recursively copy `p`
///    on top of `agent_root`, overwriting existing files. Otherwise
///    silently skip.
/// 5. UID/GID substitute `etc/passwd` and `etc/group`.
/// 6. Touch the sentinel.
pub fn materialise_per_agent_rootfs(base: &Path, agent_root: &Path, overlay: Option<&Path>) -> Result<(), String> {
    let sentinel = agent_root.join(ROOTFS_READY_SENTINEL);
    if sentinel.exists() {
        return Ok(());
    }

    fs::create_dir_all(agent_root).map_err(|e| format!("create {}: {e}", agent_root.display()))?;

    for sub in RW_SUBDIRS {
        let src = base.join(sub);
        if !src.exists() {
            continue;
        }
        let dst = agent_root.join(sub);
        copy_dir_recursive(&src, &dst)?;
    }

    if let Some(overlay) = overlay
        && overlay.exists()
    {
        apply_overlay(overlay, agent_root)?;
    }

    substitute_uid_gid(agent_root)?;

    fs::write(&sentinel, b"").map_err(|e| format!("write sentinel {}: {e}", sentinel.display()))?;
    Ok(())
}

fn apply_overlay(overlay: &Path, agent_root: &Path) -> Result<(), String> {
    copy_dir_recursive_overwrite(overlay, agent_root)
}

/// Substitute `{{UID}}` / `{{GID}}` placeholders in
/// `<agent_root>/etc/passwd` and `<agent_root>/etc/group` (if present).
fn substitute_uid_gid(agent_root: &Path) -> Result<(), String> {
    // SAFETY: getuid/getgid are infallible POSIX getters.
    #[allow(unsafe_code)]
    let uid = unsafe { libc::getuid() };
    #[allow(unsafe_code)]
    let gid = unsafe { libc::getgid() };
    let uid_s = uid.to_string();
    let gid_s = gid.to_string();

    for rel in ["etc/passwd", "etc/group"] {
        let p = agent_root.join(rel);
        if !p.exists() {
            continue;
        }
        let original = fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
        let replaced = original.replace("{{UID}}", &uid_s).replace("{{GID}}", &gid_s);
        if replaced != original {
            fs::write(&p, replaced).map_err(|e| format!("write {}: {e}", p.display()))?;
        }
    }
    Ok(())
}

/// Recursive copy `src` → `dst`. `dst` must not exist (initial copy).
/// Symlinks are preserved as symlinks. Permissions are preserved.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    copy_into_existing(src, dst, /* overwrite = */ false)
}

/// Recursive copy `src` → `dst`, overwriting existing files at `dst`.
/// Used by the overlay step.
fn copy_dir_recursive_overwrite(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    copy_into_existing(src, dst, /* overwrite = */ true)
}

fn copy_into_existing(src: &Path, dst: &Path, overwrite: bool) -> Result<(), String> {
    for entry in fs::read_dir(src).map_err(|e| format!("read_dir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("read_dir entry in {}: {e}", src.display()))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| format!("file_type {}: {e}", from.display()))?;

        if ft.is_symlink() {
            let target = fs::read_link(&from).map_err(|e| format!("readlink {}: {e}", from.display()))?;
            if to.exists() || to.symlink_metadata().is_ok() {
                if !overwrite {
                    continue;
                }
                let _ = fs::remove_file(&to);
            }
            std::os::unix::fs::symlink(&target, &to)
                .map_err(|e| format!("symlink {} -> {}: {e}", to.display(), target.display()))?;
        } else if ft.is_dir() {
            fs::create_dir_all(&to).map_err(|e| format!("mkdir {}: {e}", to.display()))?;
            copy_into_existing(&from, &to, overwrite)?;
        } else if ft.is_file() {
            if to.exists() && !overwrite {
                continue;
            }
            fs::copy(&from, &to).map_err(|e| format!("copy {} -> {}: {e}", from.display(), to.display()))?;
            let perm = entry
                .metadata()
                .map_err(|e| format!("metadata {}: {e}", from.display()))?
                .permissions();
            let mode = perm.mode();
            let _ = fs::set_permissions(&to, fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, content: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    #[test]
    fn materialise_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let agent = tmp.path().join("agent");

        write(
            &base.join("etc/passwd"),
            "tokimo:x:{{UID}}:{{GID}}::/home/tokimo:/bin/bash\n",
        );
        write(&base.join("etc/group"), "tokimo:x:{{GID}}:\n");
        write(&base.join("home/tokimo/.bashrc"), "export PS1='$ '\n");
        fs::create_dir_all(base.join("var/log")).unwrap();
        fs::create_dir_all(base.join("root")).unwrap();

        materialise_per_agent_rootfs(&base, &agent, None).unwrap();
        assert!(agent.join(ROOTFS_READY_SENTINEL).exists());
        assert!(agent.join("etc/passwd").exists());

        // Second call: should not error and should not re-copy (mark a
        // sentinel-marked file so we can detect re-copy).
        let marker = agent.join("etc/passwd");
        let stamp = b"USER_EDITED";
        fs::write(&marker, stamp).unwrap();
        materialise_per_agent_rootfs(&base, &agent, None).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), stamp);
    }

    #[test]
    fn uid_substitution_runs_on_first_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let agent = tmp.path().join("agent");

        write(
            &base.join("etc/passwd"),
            "tokimo:x:{{UID}}:{{GID}}::/home/tokimo:/bin/bash\n",
        );

        materialise_per_agent_rootfs(&base, &agent, None).unwrap();

        let out = fs::read_to_string(agent.join("etc/passwd")).unwrap();
        assert!(!out.contains("{{UID}}"), "uid placeholder remained: {out}");
        assert!(!out.contains("{{GID}}"), "gid placeholder remained: {out}");
    }

    #[test]
    fn overlay_overwrites_base_files() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let overlay = tmp.path().join("overlay");
        let agent = tmp.path().join("agent");

        write(&base.join("home/tokimo/.bashrc"), "BASE\n");
        write(&overlay.join("home/tokimo/.bashrc"), "OVERLAY\n");
        write(&base.join("home/tokimo/keep.txt"), "K\n");

        materialise_per_agent_rootfs(&base, &agent, Some(&overlay)).unwrap();

        assert_eq!(
            fs::read_to_string(agent.join("home/tokimo/.bashrc")).unwrap(),
            "OVERLAY\n"
        );
        assert_eq!(fs::read_to_string(agent.join("home/tokimo/keep.txt")).unwrap(), "K\n");
    }
}
