//! Path sanitisation shared between built-in VFS backends.

use std::path::{Component, Path};

use crate::vfs_backend::{VfsError, VfsResult};

/// Reject `..`, absolute roots after the leading `/`, and any non-Normal
/// components. The bridge already guarantees this at the protocol layer,
/// but defence-in-depth: backends do their own check.
pub(super) fn sanitize(path: &Path) -> VfsResult<&Path> {
    for c in path.components() {
        match c {
            Component::RootDir | Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(VfsError::InvalidArgument(format!(
                    "path contains ..: {}",
                    path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(VfsError::InvalidArgument(format!(
                    "path has prefix: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(path)
}

/// Strip a leading `/` so we can join under a host root.
pub(super) fn relative_under(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

pub(super) fn local_stat_error(err: std::io::Error) -> VfsError {
    #[cfg(windows)]
    if err.raw_os_error() == Some(123) {
        return VfsError::NotFound;
    }
    VfsError::from(err)
}
