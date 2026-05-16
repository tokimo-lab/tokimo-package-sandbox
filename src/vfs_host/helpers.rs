//! Internal helpers used by `vfs_host` op dispatchers.

use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::vfs_backend::{VfsError, VfsFileInfo, VfsResult};
use crate::vfs_protocol::{AttrOut, NodeKind, Req};

use super::MountEntry;

/// Returns true for ops that complete in tens of µs without doing real
/// I/O, so it's cheaper to await them inline than to allocate a new
/// tokio task. Heavy ops (Read/Write/ReadDir/ReadDirPlus do bulk
/// transfers or backend list/stat per entry) get spawned so they don't
/// stall the read loop.
pub(in crate::vfs_host) fn op_is_cheap(op: &Req) -> bool {
    matches!(
        op,
        Req::Forget { .. }
            | Req::GetAttr { .. }
            | Req::Lookup { .. }
            | Req::Open { .. }
            | Req::OpenDir { .. }
            | Req::Release { .. }
            | Req::ReleaseDir { .. }
            | Req::Flush { .. }
            | Req::Statfs { .. }
    )
}

#[cfg(unix)]
pub(in crate::vfs_host) fn apply_host_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
}

/// Persists `mode` (12 low bits) via the `$LXMOD` NTFS Extended Attribute —
/// a 4-byte little-endian `u32` containing `S_IFMT | perm_bits`, byte-compatible
/// with WSL2 DrvFs `metadata` mount option.
///
/// On NTFS volumes:
/// - Writes `$LXMOD` EA using `NtSetEaFile` (see `src/windows/ntfs_mode.rs`).
///   The EA value includes the high `S_IFMT` bits derived from the file type
///   (S_IFREG / S_IFDIR / S_IFLNK) ORed with the low 12 permission bits.
/// - The NTFS readonly attribute is **not** touched. Reason: Linux tools such
///   as git rely on `chmod 0444` not affecting subsequent directory-level
///   operations (creating loose objects, atomic rename/write). NTFS readonly
///   has tool-chain side effects (e.g. git fails with "insufficient permission
///   for adding an object to repository database .git/objects"). Explorer
///   display fidelity is a known limitation — `$LXMOD` EA carries the full
///   12-bit mode, which is authoritative for all sandbox stat() calls.
///
/// On non-NTFS volumes (FAT32, exFAT, network shares):
/// - `volume_supports_ea` returns false; mode cannot be persisted.
/// - Subsequent `stat` returns the fallback mode (0o755 for files/dirs,
///   0o777 for symlinks). The NTFS readonly bit is not touched here either.
#[cfg(windows)]
pub(in crate::vfs_host) fn apply_host_mode(path: &std::path::Path, mode: u32) {
    use crate::windows::ntfs_mode::{FileKind, volume_supports_ea, write_mode_ea};

    if !volume_supports_ea(path) {
        // Non-NTFS volume: mode cannot be persisted; stat() will return
        // fallback (0o755 file / 0o755 dir / 0o777 symlink).
        return;
    }
    let kind = match std::fs::symlink_metadata(path).map(|m| m.file_type()) {
        Ok(ft) if ft.is_dir() => FileKind::Dir,
        Ok(ft) if ft.is_symlink() => FileKind::Symlink,
        _ => FileKind::File,
    };
    if let Err(e) = write_mode_ea(path, mode & 0o7777, kind) {
        tracing::warn!(?path, error = %e, "write_mode_ea failed");
    }
}

#[cfg(not(any(unix, windows)))]
pub(in crate::vfs_host) fn apply_host_mode(_path: &std::path::Path, _mode: u32) {}

pub(in crate::vfs_host) fn attr_from(info: &VfsFileInfo) -> AttrOut {
    let kind = if info.is_symlink {
        NodeKind::Symlink
    } else if info.is_socket {
        NodeKind::Socket
    } else if info.is_fifo {
        NodeKind::Fifo
    } else if info.is_block_device {
        NodeKind::BlockDev
    } else if info.is_char_device {
        NodeKind::CharDev
    } else if info.is_dir {
        NodeKind::Dir
    } else {
        NodeKind::File
    };
    let mode = info.mode.unwrap_or(match kind {
        NodeKind::Dir => 0o755,
        NodeKind::Symlink => 0o777,
        NodeKind::Socket | NodeKind::Fifo => 0o666,
        NodeKind::BlockDev | NodeKind::CharDev => 0o600,
        NodeKind::File => 0o644,
    });
    let mtime = info
        .modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // On Linux the FuseHost runs in-process (bwrap path) so the calling
    // UID matches the host user — return real uid/gid so DefaultPermissions
    // allows writes. On macOS/Windows the FuseHost serves a Linux VM
    // where processes run as root — return 0/0 so root-owned files are
    // writable inside the guest.
    #[cfg(target_os = "linux")]
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    #[cfg(not(target_os = "linux"))]
    let (uid, gid) = (0u32, 0u32);
    AttrOut {
        size: info.size,
        blocks: info.size.div_ceil(512),
        mtime,
        mode,
        nlink: 1,
        uid,
        gid,
        kind,
        rdev: info.rdev,
    }
}

pub(in crate::vfs_host) async fn drain_staging_to_backend(
    mount: &MountEntry,
    path: &Path,
    staging_path: &Path,
    size: u64,
) -> VfsResult<()> {
    // Prefer streaming if available; otherwise read into memory + put.
    if let Some(stream) = mount.backend.as_put_stream() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let path_cl = staging_path.to_path_buf();
        let total = size;
        let pump = tokio::task::spawn_blocking(move || -> io::Result<()> {
            use std::io::Read;
            let mut f = std::fs::File::open(&path_cl)?;
            let mut remaining = total;
            let mut buf = vec![0u8; 256 * 1024];
            while remaining > 0 {
                let want = remaining.min(buf.len() as u64) as usize;
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    break;
                }
                let chunk = buf[..n].to_vec();
                if tx.blocking_send(chunk).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            Ok(())
        });
        let put_res = stream.put_stream(path, size, rx).await;
        let pump_res = pump.await.map_err(|e| VfsError::Io(e.to_string()))?;
        pump_res.map_err(VfsError::from)?;
        put_res?;
        return Ok(());
    }
    if let Some(p) = mount.backend.as_put() {
        let path_cl = staging_path.to_path_buf();
        let data = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> { std::fs::read(&path_cl) })
            .await
            .map_err(|e| VfsError::Io(e.to_string()))?
            .map_err(VfsError::from)?;
        // Truncate to declared size so over-allocated tempfile doesn't bleed.
        let data = if data.len() as u64 > size {
            data[..size as usize].to_vec()
        } else {
            data
        };
        return p.put(path, data).await;
    }
    Err(VfsError::NotImplemented("backend has no put / put_stream".into()))
}
