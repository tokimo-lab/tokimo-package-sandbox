//! Safe-path validation shared by the host library and the SYSTEM service.
//!
//! Mirrors what Claude Desktop's `cowork-svc` does: refuse to open a path if
//! it contains symlinks/junctions or has multiple hard links. This kills
//! whole classes of TOCTOU and reparse-point attacks where a low-privilege
//! caller convinces the SYSTEM service to write into a target it shouldn't.
//!
//! Use [`canonicalize_safe`] to obtain a `PathBuf` that is guaranteed to be:
//!   * absolute,
//!   * existing,
//!   * containing no reparse points (no symlinks, no junctions, no NTFS
//!     mount points) anywhere on the path,
//!   * with the leaf having `nNumberOfLinks == 1`.

#![cfg(target_os = "windows")]

use std::io;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    OPEN_EXISTING,
};
use windows::core::HSTRING;

/// Canonicalize `path`, then verify it is safe according to the policy
/// described above. Returns the canonical absolute path on success.
pub fn canonicalize_safe(path: &Path) -> io::Result<PathBuf> {
    let canon = std::fs::canonicalize(path)?;

    // Walk every component and ensure none of them is a reparse point.
    let mut walked = PathBuf::new();
    for c in canon.components() {
        walked.push(c);
        // Skip the disk designator step (`\\?\C:`) - GetFileInformation
        // doesn't accept it on its own.
        let probe = walked.as_path();
        if probe.parent().is_none() {
            continue;
        }
        let info = file_info(probe).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("path component {} not accessible: {e}", probe.display()),
            )
        })?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "path {} is a symlink or junction, refusing to open",
                    probe.display()
                ),
            ));
        }
    }

    // Final check on the leaf: must have exactly one hard link.
    let info = file_info(&canon)?;
    if info.nNumberOfLinks > 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} has {} hard links, refusing to open",
                canon.display(),
                info.nNumberOfLinks
            ),
        ));
    }

    Ok(canon)
}

fn file_info(path: &Path) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let wide = HSTRING::from(path.as_os_str());
    let handle: HANDLE = unsafe {
        CreateFileW(
            &wide,
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            // BACKUP_SEMANTICS so we can open directories;
            // OPEN_REPARSE_POINT so we get the reparse point itself, not its
            // target — required to detect symlinks/junctions reliably.
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let r = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let _ = unsafe { CloseHandle(handle) };
    r.map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
    Ok(info)
}
