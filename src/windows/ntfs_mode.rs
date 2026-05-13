//! NTFS Extended Attribute `$LXMOD` read/write module.
//!
//! # Byte layout (empirically verified)
//!
//! User-verified on WSL2 + DrvFs (`metadata,umask=022`):
//!   - `chmod 0700`  → `$LXMOD = c0 81 00 00` = `0x000081c0` = `0o100700` (S_IFREG | 0o0700)
//!   - `chmod 04755` → `$LXMOD = ed 89 00 00` = `0x000089ed` = `0o104755` (S_IFREG | suid | 0o0755)
//!
//! Payload: 4-byte little-endian `u32 st_mode` containing S_IFMT high bits + 12-bit perm bits.
//! This is byte-for-byte compatible with WSL2 DrvFs — chmod from either side produces
//! identical EA bytes.
//!
//! # Design notes
//!
//! - Uses NTFS Extended Attributes (not Alternate Data Streams — ADS is frequently stripped by
//!   backup tools, antivirus, OneDrive, and cross-FS copies). EA survives `robocopy /COPYALL`.
//!   Inspect with: `fsutil file queryEA <path>`
//! - `$LXUID` / `$LXGID` are intentionally **not** written or read. The sandbox owns uid/gid.
//!   Writing them would cause WSL to reassign host file ownership to unexpected values.
//! - WSL DrvFs double-compatible: `$LXMOD` is a published Microsoft convention.
//! - Volume EA support cached per volume root to avoid per-stat `GetVolumeInformationW` calls.
//!
//! **Phase 1 note**: this module exposes the public API that Phase 2 will connect to
//! `meta_to_info` and `apply_host_mode`. Items are intentionally unused until then.

#![cfg(target_os = "windows")]
// Public API will be wired in Phase 2 (meta_to_info / apply_host_mode integration).
// Suppress dead_code until then so clippy stays clean.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use windows::Wdk::Storage::FileSystem::{NtQueryEaFile, NtSetEaFile};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetVolumeInformationW, GetVolumePathNameW, OPEN_EXISTING,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::core::HSTRING;

const STATUS_SUCCESS: i32 = 0;
const STATUS_NONEXISTENT_EA_ENTRY: i32 = 0xC0000051u32 as i32;
const STATUS_NO_EAS_ON_FILE: i32 = 0xC0000052u32 as i32;

/// The kind of filesystem object — used to select S_IFMT bits when writing `$LXMOD`.
pub enum FileKind {
    File,
    Dir,
    Symlink,
}

fn s_ifmt(kind: &FileKind) -> u32 {
    match kind {
        FileKind::File => 0o100000,
        FileKind::Dir => 0o040000,
        FileKind::Symlink => 0o120000,
    }
}

/// Read the `$LXMOD` EA from `path`.
///
/// Returns the low 12 permission bits (S_IFMT stripped).
/// Returns `None` when the EA is absent, the volume doesn't support EA, or an I/O error occurs.
pub fn read_mode_ea(path: &Path) -> Option<u32> {
    let handle = open_handle(path, GENERIC_READ.0).ok()?;
    let result = query_lxmod_ea(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

/// Write the `$LXMOD` EA to `path`.
///
/// `mode` is masked to the low 12 bits; S_IFMT bits are derived from `kind` and OR-ed in.
pub fn write_mode_ea(path: &Path, mode: u32, kind: FileKind) -> io::Result<()> {
    let handle = open_handle(path, GENERIC_READ.0 | GENERIC_WRITE.0)?;
    let result = set_lxmod_ea(handle, (mode & 0o7777) | s_ifmt(&kind));
    let _ = unsafe { CloseHandle(handle) };
    result
}

/// Returns `true` if the volume containing `path` supports Extended Attributes (NTFS or ReFS).
///
/// Results are cached per volume root to avoid repeated `GetVolumeInformationW` calls.
pub fn volume_supports_ea(path: &Path) -> bool {
    let volume_root = match get_volume_root(path) {
        Some(r) => r,
        None => return false,
    };
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&cached) = guard.get(&volume_root) {
            return cached;
        }
    }
    let supported = check_volume_ea_support(&volume_root);
    {
        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(volume_root, supported);
    }
    supported
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Open a file/directory handle.
///
/// `access` is a raw `u32` bitmask (e.g. `GENERIC_READ.0` or `GENERIC_READ.0 | GENERIC_WRITE.0`).
/// `FILE_FLAG_BACKUP_SEMANTICS` allows opening directories;
/// `FILE_FLAG_OPEN_REPARSE_POINT` prevents following symlinks (we open the link itself).
fn open_handle(path: &Path, access: u32) -> io::Result<HANDLE> {
    let wide = path_to_hstring(path);
    let handle = unsafe {
        CreateFileW(
            &wide,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
    Ok(handle)
}

/// Build a `FILE_GET_EA_INFORMATION` query list for a single EA name and call `NtQueryEaFile`.
/// Parses the returned `FILE_FULL_EA_INFORMATION` and extracts the 4-byte LE mode value.
fn query_lxmod_ea(handle: HANDLE) -> Option<u32> {
    // FILE_GET_EA_INFORMATION layout (variable-length):
    //   Offset  Size  Field
    //      0     4    NextEntryOffset (ULONG, 0 = last)
    //      4     1    EaNameLength (UCHAR, not counting null terminator)
    //      5     N+1  EaName (zero-terminated ASCII)
    // For "$LXMOD\0": N=6, total = 4 + 1 + 7 = 12 bytes.
    //
    // NT requires ULONG (4-byte) aligned buffers — use [u32] to guarantee alignment.
    let ea_name = b"$LXMOD\0"; // 7 bytes including null
    let mut query_aligned = [0u32; 3]; // 12 bytes, 4-byte aligned
    {
        let q = unsafe { std::slice::from_raw_parts_mut(query_aligned.as_mut_ptr().cast::<u8>(), 12) };
        // q[0..4] = NextEntryOffset = 0 (already zero)
        q[4] = 6u8; // EaNameLength = len("$LXMOD") without null
        q[5..12].copy_from_slice(ea_name);
    }

    // Output buffer — large enough for FILE_FULL_EA_INFORMATION + name + 4-byte value.
    // Use [u32; 16] = 64 bytes to guarantee 4-byte alignment.
    let mut out_aligned = [0u32; 16];
    let mut iosb = IO_STATUS_BLOCK::default();

    let status: NTSTATUS = unsafe {
        NtQueryEaFile(
            handle,
            &mut iosb,
            out_aligned.as_mut_ptr().cast(),
            (out_aligned.len() * 4) as u32,
            true, // ReturnSingleEntry
            Some(query_aligned.as_ptr().cast()),
            (query_aligned.len() * 4) as u32,
            None, // EaIndex
            true, // RestartScan
        )
    };

    match status.0 {
        STATUS_SUCCESS => {}
        STATUS_NO_EAS_ON_FILE | STATUS_NONEXISTENT_EA_ENTRY => return None,
        code => {
            tracing::warn!("NtQueryEaFile($LXMOD) returned NTSTATUS {:#010x}", code as u32);
            return None;
        }
    }

    // FILE_FULL_EA_INFORMATION layout (variable-length):
    //   Offset  Size  Field
    //      0     4    NextEntryOffset (ULONG)
    //      4     1    Flags (UCHAR)
    //      5     1    EaNameLength (UCHAR, not counting null terminator)
    //      6     2    EaValueLength (USHORT, LE)
    //      8     N+1  EaName (zero-terminated ASCII)
    //   8+N+1  VLen  EaValue
    let out_buf = unsafe { std::slice::from_raw_parts(out_aligned.as_ptr().cast::<u8>(), out_aligned.len() * 4) };
    let ea_name_len = out_buf[5] as usize;
    let ea_value_len = u16::from_le_bytes([out_buf[6], out_buf[7]]) as usize;

    if ea_value_len < 4 {
        tracing::warn!("$LXMOD EA value length is {} (expected 4)", ea_value_len);
        return None;
    }

    // Value starts immediately after the zero-terminated name.
    let value_offset = 8 + ea_name_len + 1;
    if value_offset + 4 > out_buf.len() {
        tracing::warn!("$LXMOD EA buffer overrun (offset {})", value_offset);
        return None;
    }

    let mode = u32::from_le_bytes([
        out_buf[value_offset],
        out_buf[value_offset + 1],
        out_buf[value_offset + 2],
        out_buf[value_offset + 3],
    ]);

    tracing::trace!("read_mode_ea: raw st_mode={:#010o}, perm={:#06o}", mode, mode & 0o7777);
    Some(mode & 0o7777)
}

/// Construct a `FILE_FULL_EA_INFORMATION` buffer for `$LXMOD` and call `NtSetEaFile`.
///
/// `mode` must already include the S_IFMT high bits (the caller is responsible for ORing them in).
fn set_lxmod_ea(handle: HANDLE, mode: u32) -> io::Result<()> {
    // FILE_FULL_EA_INFORMATION for "$LXMOD" with 4-byte value:
    //   Offset  Size  Content
    //      0     4    NextEntryOffset = 0
    //      4     1    Flags = 0
    //      5     1    EaNameLength = 6
    //      6     2    EaValueLength = 4 (LE)
    //      8     7    "$LXMOD\0"
    //     15     4    mode as LE u32
    //     19     1    padding to 4-byte alignment
    //
    // Use [u32; 5] = 20 bytes to guarantee the ULONG (4-byte) alignment NT requires.
    let mode_le = mode.to_le_bytes();
    let ea_name = b"$LXMOD\0"; // 7 bytes including null terminator
    let mut buf_aligned = [0u32; 5]; // 20 bytes, 4-byte aligned
    {
        let buf = unsafe { std::slice::from_raw_parts_mut(buf_aligned.as_mut_ptr().cast::<u8>(), 20) };
        // buf[0..4] = NextEntryOffset = 0 (already zero)
        // buf[4] = Flags = 0 (already zero)
        buf[5] = 6u8; // EaNameLength (not counting null)
        buf[6..8].copy_from_slice(&4u16.to_le_bytes()); // EaValueLength
        buf[8..15].copy_from_slice(ea_name); // EaName (zero-terminated)
        buf[15..19].copy_from_slice(&mode_le); // EaValue
        // buf[19] = 0 (padding, already zero)
    }

    let mut iosb = IO_STATUS_BLOCK::default();

    let status: NTSTATUS = unsafe {
        NtSetEaFile(
            handle,
            &mut iosb,
            buf_aligned.as_mut_ptr().cast(),
            (buf_aligned.len() * 4) as u32,
        )
    };

    if status.0 != STATUS_SUCCESS {
        return Err(io::Error::other(format!(
            "NtSetEaFile($LXMOD) failed with NTSTATUS {:#010x}",
            status.0 as u32
        )));
    }

    tracing::trace!("write_mode_ea: wrote st_mode={:#010o}", mode);
    Ok(())
}

/// Convert a `&Path` to an `HSTRING` suitable for Win32 wide-string APIs.
///
/// Adds the `\\?\` long-path prefix when the path length exceeds 260 characters to avoid
/// `MAX_PATH` truncation. Falls back to the plain path if conversion fails.
fn path_to_hstring(path: &Path) -> HSTRING {
    let s = path.as_os_str();
    // Add \\?\ prefix for long paths to bypass MAX_PATH limit
    if s.len() > 260 {
        let prefixed = format!("\\\\?\\{}", path.display());
        HSTRING::from(prefixed.as_str())
    } else {
        HSTRING::from(s)
    }
}

/// Obtain the volume root (e.g. `C:\`) for the volume containing `path`.
fn get_volume_root(path: &Path) -> Option<PathBuf> {
    let wide = path_to_hstring(path);
    let mut buf = [0u16; 261]; // MAX_PATH + 1
    let ok = unsafe { GetVolumePathNameW(&wide, &mut buf) };
    if let Err(e) = ok {
        tracing::warn!("GetVolumePathNameW failed for {}: {}", path.display(), e);
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
}

/// Query whether the volume at `volume_root` is NTFS or ReFS (both support EA).
fn check_volume_ea_support(volume_root: &Path) -> bool {
    let wide = path_to_hstring(volume_root);
    let mut fs_name_buf = [0u16; 32];
    let ok = unsafe {
        GetVolumeInformationW(
            &wide,
            None,                   // volume name — not needed
            None,                   // serial number — not needed
            None,                   // max component length — not needed
            None,                   // fs flags — not needed
            Some(&mut fs_name_buf), // file system name (e.g. "NTFS")
        )
    };
    if let Err(e) = ok {
        tracing::warn!("GetVolumeInformationW failed for {}: {}", volume_root.display(), e);
        return false;
    }
    let len = fs_name_buf.iter().position(|&c| c == 0).unwrap_or(fs_name_buf.len());
    let fs_name = String::from_utf16_lossy(&fs_name_buf[..len]);
    matches!(fs_name.as_str(), "NTFS" | "ReFS")
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn roundtrip_644() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"").unwrap();
        write_mode_ea(&file, 0o644, FileKind::File).expect("write EA");
        assert_eq!(read_mode_ea(&file), Some(0o644));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn roundtrip_full_perm() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"").unwrap();
        write_mode_ea(&file, 0o7777, FileKind::File).expect("write EA");
        assert_eq!(read_mode_ea(&file), Some(0o7777));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn roundtrip_4755_setuid() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"").unwrap();
        write_mode_ea(&file, 0o4755, FileKind::File).expect("write EA");
        assert_eq!(read_mode_ea(&file), Some(0o4755));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn roundtrip_2755_setgid() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"").unwrap();
        write_mode_ea(&file, 0o2755, FileKind::File).expect("write EA");
        assert_eq!(read_mode_ea(&file), Some(0o2755));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn roundtrip_1755_sticky() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"").unwrap();
        write_mode_ea(&file, 0o1755, FileKind::File).expect("write EA");
        assert_eq!(read_mode_ea(&file), Some(0o1755));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn read_missing_ea_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("no_ea.txt");
        std::fs::write(&file, b"").unwrap();
        // No EA written — must return None
        assert_eq!(read_mode_ea(&file), None);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn write_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        write_mode_ea(dir.path(), 0o755, FileKind::Dir).expect("write EA to dir");
        assert_eq!(read_mode_ea(dir.path()), Some(0o755));
    }

    /// Verify byte-level compatibility with WSL2 DrvFs.
    ///
    /// `chmod 0700` on a regular file produces `$LXMOD = c0 81 00 00` (0x000081c0 = S_IFREG|0o700).
    /// This test writes mode 0o700 + FileKind::File and then calls `fsutil file queryEA` to
    /// confirm the raw EA bytes match the WSL2-observed layout exactly.
    ///
    /// If `fsutil` is not available (restricted CI), the test prints a skip message and passes.
    #[test]
    #[cfg(target_os = "windows")]
    fn wsl_byte_compat() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lxmod_compat.txt");
        std::fs::write(&file, b"").unwrap();

        write_mode_ea(&file, 0o700, FileKind::File).expect("write EA");

        let output = std::process::Command::new("fsutil")
            .args(["file", "queryEA", file.to_str().unwrap()])
            .output();

        match output {
            Err(e) => {
                eprintln!("wsl_byte_compat: skipped — fsutil not available: {e}");
            }
            Ok(out) if !out.status.success() => {
                eprintln!(
                    "wsl_byte_compat: skipped — fsutil exited {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
                // WSL2 empirical result: chmod 0700 → $LXMOD = c0 81 00 00
                // (0x000081c0 = S_IFREG | 0o0700)
                assert!(
                    stdout.contains("c0 81 00 00"),
                    "expected '$LXMOD = c0 81 00 00' in fsutil output, got:\n{stdout}"
                );
            }
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn volume_supports_ntfs() {
        let dir = tempfile::tempdir().unwrap();
        assert!(volume_supports_ea(dir.path()), "temp dir should be on an NTFS volume");
    }
}
