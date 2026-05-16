//! `meta_to_info`: convert raw filesystem metadata to [`VfsFileInfo`].

use crate::vfs_backend::VfsFileInfo;

/// Converts raw filesystem metadata into [`VfsFileInfo`].
///
/// **Unix**: reads `st_mode` directly via `PermissionsExt::mode()`.
///
/// **Windows**: reads the `$LXMOD` NTFS Extended Attribute (4-byte LE u32,
/// WSL2 DrvFs `metadata` format).  `$LXUID` / `$LXGID` are intentionally
/// NOT read — uid/gid are always derived from the calling process token.
///
/// Fallback ladder when `$LXMOD` EA is absent or the volume does not support EA:
///
/// | Scenario                               | Returned mode      |
/// |----------------------------------------|--------------------|
/// | NTFS + `$LXMOD` EA present             | EA value           |
/// | NTFS + no EA + regular file            | 0o644              |
/// | NTFS + no EA + directory               | 0o755              |
/// | NTFS + no EA + symlink                 | 0o777              |
/// | non-NTFS (FAT32/exFAT/network) + file  | 0o755 (keep +x)    |
/// | non-NTFS + directory                   | 0o755              |
/// | non-NTFS + symlink                     | 0o777              |
///
/// On the fallback path (EA missing or non-NTFS volume) the NTFS readonly
/// attribute is checked: if the file is read-only, `0o222` (write bits) is
/// cleared from the fallback mode. EA-hit paths are not affected by the
/// readonly bit — `$LXMOD` EA is the authoritative source.
#[cfg_attr(not(windows), allow(unused_variables))]
pub(super) fn meta_to_info(name: String, path: &std::path::Path, md: std::fs::Metadata) -> VfsFileInfo {
    // Unix: inspect the real file_type bits for socket/fifo/dev nodes.
    // Windows: derive the "logical" Unix type from `$LXMOD` EA so that
    // FUSE_MKNOD'd S_IFSOCK / S_IFIFO files round-trip across stat()
    // calls. Without this, an AF_UNIX socket bound on the host shows up
    // as a regular file on the next lookup and `connect()` fails with
    // ENOTSOCK in the guest.
    let (kind_mode, kind_rdev) = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let ft = md.file_type();
            let mut k = 0u32;
            if ft.is_socket() {
                k = 0o140000;
            } else if ft.is_fifo() {
                k = 0o010000;
            } else if ft.is_block_device() {
                k = 0o060000;
            } else if ft.is_char_device() {
                k = 0o020000;
            }
            // macOS: an unprivileged FUSE host can't create real
            // socket/FIFO inodes (mknod requires root), so we fall back
            // to a regular file with `com.tokimo.kind` xattr. Promote
            // the recorded kind here so consumers see `is_socket=true`.
            #[cfg(target_os = "macos")]
            if k == 0 && ft.is_file() {
                if let Some(b) = super::macos_xattr::get(path) {
                    if b == super::macos_xattr::KIND_SOCKET {
                        k = 0o140000;
                    } else if b == super::macos_xattr::KIND_FIFO {
                        k = 0o010000;
                    }
                }
            }
            (k, md.rdev() as u32)
        }
        #[cfg(windows)]
        {
            use crate::windows::ntfs_mode::{read_mode_ea_full, volume_supports_ea};
            let raw = if volume_supports_ea(path) {
                read_mode_ea_full(path).unwrap_or(0)
            } else {
                0
            };
            // S_IFMT = 0o170000
            let t = raw & 0o170000;
            (t, 0u32)
        }
        #[cfg(not(any(unix, windows)))]
        {
            (0u32, 0u32)
        }
    };
    let is_socket = kind_mode == 0o140000; // S_IFSOCK
    let is_fifo = kind_mode == 0o010000; // S_IFIFO
    let is_block_device = kind_mode == 0o060000; // S_IFBLK
    let is_char_device = kind_mode == 0o020000; // S_IFCHR

    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(md.permissions().mode() & 0o7777)
        }
        #[cfg(windows)]
        {
            use crate::windows::ntfs_mode::{read_mode_ea, volume_supports_ea};
            let ft_local = md.file_type();
            let writable = !md.permissions().readonly();
            // NTFS/ReFS volume: attempt to read $LXMOD EA; fall back to 0o644/0o755/0o777.
            let mode = if volume_supports_ea(path) {
                read_mode_ea(path).unwrap_or_else(|| {
                    let base = if md.is_dir() {
                        0o755
                    } else if ft_local.is_symlink() {
                        0o777
                    } else {
                        0o644
                    };
                    if writable { base } else { base & !0o222 }
                })
            // Non-NTFS volume (FAT32/exFAT/network): EA unavailable; keep +x for scripts.
            } else {
                let base = if md.is_dir() {
                    0o755
                } else if ft_local.is_symlink() {
                    0o777
                } else {
                    0o755
                };
                if writable { base } else { base & !0o222 }
            };
            Some(mode)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            None
        }
    };
    let ft = md.file_type();
    let is_symlink = ft.is_symlink();
    // is_dir takes precedence only for *real* directories — special
    // inodes (socket/fifo/dev) are not directories even though the
    // host metadata's "is_dir" can never be true for them anyway.
    let is_special = is_socket || is_fifo || is_block_device || is_char_device;
    let nlink: u32 = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            md.nlink() as u32
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            // Windows: number_of_links is unavailable on Metadata; FUSE
            // hosts on Windows don't expose link(2) as a fast path, so
            // a default of 1 is correct for non-hard-linked files.
            let _ = &md;
            1
        }
        #[cfg(not(any(unix, windows)))]
        {
            1
        }
    };
    // (dev, ino) drive `(mount_id, dev, ino)` dedup in the host
    // IdTable so two paths to the same inode (after `link(2)`) collapse
    // to one nodeid + one kernel-side page cache. Path-only backends
    // (Windows, MemFsVfs) leave both 0 and degrade to the legacy
    // path-keyed behaviour.
    let (ino, dev): (u64, u64) = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            (md.ino(), md.dev())
        }
        #[cfg(not(unix))]
        {
            (0, 0)
        }
    };
    VfsFileInfo {
        name,
        size: md.len(),
        is_dir: !is_symlink && !is_special && md.is_dir(),
        is_symlink,
        is_socket,
        is_fifo,
        is_block_device,
        is_char_device,
        modified: md.modified().ok(),
        mode,
        rdev: kind_rdev,
        nlink,
        ino,
        dev,
    }
}
