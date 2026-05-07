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

/// Recursively copy a directory tree.
#[cfg(not(target_os = "windows"))]
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| Error::other(format!("mkdir {}: {e}", dst.display())))?;

    for entry in fs::read_dir(src).map_err(|e| Error::other(format!("read_dir {}: {e}", src.display())))? {
        let entry = entry.map_err(|e| Error::other(format!("read_dir entry: {e}")))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| Error::other(format!("file_type {}: {e}", src_path.display())))?;
        if ft.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ft.is_symlink() {
            let target =
                fs::read_link(&src_path).map_err(|e| Error::other(format!("readlink {}: {e}", src_path.display())))?;
            std::os::unix::fs::symlink(&target, &dst_path)
                .map_err(|e| Error::other(format!("symlink {} -> {}: {e}", dst_path.display(), target.display())))?;
        } else {
            fs::copy(&src_path, &dst_path)
                .map_err(|e| Error::other(format!("copy {} -> {}: {e}", src_path.display(), dst_path.display())))?;
        }
    }
    Ok(())
}
