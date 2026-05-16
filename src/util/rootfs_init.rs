//! Rootfs initialisation: validate base template and ensure a writable
//! copy exists in the VM working directory.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::vm_dir::validate_base_rootfs;

/// Validate `base_rootfs` and ensure `vm_dir` contains a writable rootfs
/// copy.  If `vm_dir/rootfs/` (or `vm_dir/rootfs.vhdx` on Windows)
/// already exists it is reused — this is the persistence mechanism.
pub fn ensure_rootfs(base_rootfs: &Path, vm_dir: &Path) -> Result<()> {
    validate_base_rootfs(base_rootfs)?;

    fs::create_dir_all(vm_dir).map_err(|e| Error::other(format!("create vm_dir {}: {e}", vm_dir.display())))?;

    #[cfg(target_os = "windows")]
    {
        let target = vm_dir.join("rootfs.vhdx");
        if !target.is_file() {
            let src = base_rootfs.join("rootfs.vhdx");
            fs::copy(&src, &target).map_err(|e| {
                Error::other(format!(
                    "copy rootfs.vhdx {} -> {}: {e}",
                    src.display(),
                    target.display()
                ))
            })?;
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let target = vm_dir.join("rootfs");
        if !target.is_dir() {
            let src = base_rootfs.join("rootfs");
            copy_dir_recursive(&src, &target)?;
        }
    }

    Ok(())
}

/// Recursively copy a directory tree, preserving uid/gid/mode so that
/// `tokimo` (uid=1000) keeps owning `/home/tokimo`, `root` keeps owning
/// `/etc`, etc.  `fs::copy` only preserves the mode bits, never the
/// owner, so we restore it with `lchown` after each copy.
///
/// `lchown` to a uid/gid different from the caller requires
/// CAP_CHOWN, which an unprivileged user lacks.  We treat that case as
/// best-effort: the copy still succeeds, the file just inherits the
/// caller's uid.  Run this code as root (or invoke ensure_rootfs from a
/// privileged context) to get exact ownership preservation.
#[cfg(not(target_os = "windows"))]
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let src_meta = fs::symlink_metadata(src).map_err(|e| Error::other(format!("stat {}: {e}", src.display())))?;
    fs::create_dir_all(dst).map_err(|e| Error::other(format!("mkdir {}: {e}", dst.display())))?;
    // Restore directory mode + ownership (mkdir respects umask; we want
    // the source's mode bits exactly).
    let _ = fs::set_permissions(dst, fs::Permissions::from_mode(src_meta.mode()));
    let _ = lchown_best_effort(dst, src_meta.uid(), src_meta.gid());

    for entry in fs::read_dir(src).map_err(|e| Error::other(format!("read_dir {}: {e}", src.display())))? {
        let entry = entry.map_err(|e| Error::other(format!("read_dir entry: {e}")))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| Error::other(format!("file_type {}: {e}", src_path.display())))?;
        let entry_meta =
            fs::symlink_metadata(&src_path).map_err(|e| Error::other(format!("lstat {}: {e}", src_path.display())))?;
        if ft.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ft.is_symlink() {
            let target =
                fs::read_link(&src_path).map_err(|e| Error::other(format!("readlink {}: {e}", src_path.display())))?;
            std::os::unix::fs::symlink(&target, &dst_path)
                .map_err(|e| Error::other(format!("symlink {} -> {}: {e}", dst_path.display(), target.display())))?;
            let _ = lchown_best_effort(&dst_path, entry_meta.uid(), entry_meta.gid());
        } else {
            fs::copy(&src_path, &dst_path)
                .map_err(|e| Error::other(format!("copy {} -> {}: {e}", src_path.display(), dst_path.display())))?;
            let _ = lchown_best_effort(&dst_path, entry_meta.uid(), entry_meta.gid());
        }
    }
    Ok(())
}

/// `lchown(path, uid, gid)` that swallows EPERM so unprivileged callers
/// still get a working (if uid-mismatched) copy.
#[cfg(not(target_os = "windows"))]
fn lchown_best_effort(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: c is a valid NUL-terminated C string; lchown reads it and
    // never holds a pointer past the call.
    let rc = unsafe { libc::lchown(c.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
