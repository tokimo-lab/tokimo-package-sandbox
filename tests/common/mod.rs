//! Shared utilities for cross-platform sandbox integration tests.
//!
//! Handles platform detection, prerequisite checks, and automatic
//! download of rootfs artifacts on macOS.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Latest rootfs release known to work with this test suite.
const ROOTFS_VERSION: &str = "v1.4.0";
const ROOTFS_REPO: &str = "https://github.com/tokimo-lab/tokimo-package-rootfs";

/// Directory where artifacts are stored.
fn tokimo_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".tokimo")
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

pub fn is_linux() -> bool {
    std::env::consts::OS == "linux"
}

pub fn is_macos() -> bool {
    std::env::consts::OS == "macos"
}

// ---------------------------------------------------------------------------
// Prerequisite checks
// ---------------------------------------------------------------------------

/// Check if bwrap is installed (Linux only).
pub fn has_bwrap() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if Virtualization.framework is available (macOS only).
pub fn has_vz() -> bool {
    if !is_macos() {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        arcbox_vz::is_supported()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Check if VZ artifacts (kernel + initrd + rootfs) are present.
pub fn has_vz_artifacts() -> bool {
    let dir = tokimo_dir();
    let kernel = dir.join("kernel").join("vmlinuz");
    let initrd = dir.join("initrd.img");
    let rootfs = dir.join("rootfs");
    kernel.exists() && initrd.exists() && rootfs.exists()
}

/// Check if Windows sandbox artifacts (kernel + initrd + rootfs) are present.
pub fn has_windows_artifacts() -> bool {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let tokimo = PathBuf::from(&home).join(".tokimo");

    let kernel = std::env::var("TOKIMO_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|_| tokimo.join("kernel").join("vmlinuz"));
    let initrd = std::env::var("TOKIMO_INITRD")
        .map(PathBuf::from)
        .unwrap_or_else(|_| tokimo.join("initrd.img"));
    let rootfs = std::env::var("TOKIMO_ROOTFS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| tokimo.join("rootfs"));

    kernel.exists() && initrd.exists() && rootfs.exists()
}

/// Check if the tokimo-sandbox-svc named pipe is available.
pub fn has_windows_service() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::core::HSTRING;
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        let name = HSTRING::from("\\\\.\\pipe\\tokimo-sandbox-svc");
        unsafe { WaitNamedPipeW(&name, 100).as_bool() }
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Skip helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the test should be skipped. Prints a skip reason to
/// stderr.
///
/// On Linux: skips if bwrap is not installed.
/// On macOS: skips if VZ is unavailable or artifacts are missing.
/// On Windows: skips if kernel/initrd/rootfs artifacts are missing.
pub fn skip_unless_platform_ready() -> bool {
    if is_linux() {
        if !has_bwrap() {
            eprintln!("SKIP: bwrap not installed (apt install bubblewrap)");
            return true;
        }
    } else if is_macos() {
        if !has_vz() {
            eprintln!("SKIP: Virtualization.framework not available");
            return true;
        }
        if !has_vz_artifacts() {
            eprintln!("SKIP: VZ artifacts not found. Run download_vz_artifacts() first.");
            return true;
        }
    } else if cfg!(target_os = "windows") {
        if !has_windows_artifacts() {
            eprintln!(
                "SKIP: Windows sandbox artifacts missing. \
                 Place kernel at ~/.tokimo/kernel/vmlinuz, initrd at ~/.tokimo/initrd.img, \
                 and rootfs at ~/.tokimo/rootfs/. Or set TOKIMO_KERNEL/TOKIMO_INITRD/TOKIMO_ROOTFS env vars."
            );
            return true;
        }
        if !has_windows_service() {
            eprintln!(
                "SKIP: tokimo-sandbox-svc pipe not available. \
                 Run `tokimo-sandbox-svc --console` or install the service first."
            );
            return true;
        }
    } else {
        eprintln!("SKIP: unsupported platform ({})", std::env::consts::OS);
        return true;
    }
    false
}

/// Returns `true` if the test should be skipped because the platform
/// doesn't support persistent sandbox sessions (`Session::open`).
///
/// On Windows: sessions are not yet implemented (only `run()` one-shot).
pub fn skip_unless_session_supported() -> bool {
    if cfg!(target_os = "windows") {
        eprintln!("SKIP: Session not yet supported on Windows (use run() for one-shot)");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Automatic artifact download (macOS)
// ---------------------------------------------------------------------------

/// Download kernel + initrd + rootfs from GitHub releases.
///
/// Downloads `tokimo-os-{arch}.tar.zst` and `rootfs-{arch}.tar.zst`,
/// extracts them to `~/.tokimo/`. Skips if already present.
pub fn download_vz_artifacts() -> Result<(), String> {
    if !is_macos() {
        return Ok(());
    }
    if has_vz_artifacts() {
        eprintln!("VZ artifacts already present in {}", tokimo_dir().display());
        return Ok(());
    }

    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };

    let dir = tokimo_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {:?}: {e}", dir))?;

    // Download and extract tokimo-os (kernel + initrd).
    let os_url = format!("{ROOTFS_REPO}/releases/download/{ROOTFS_VERSION}/tokimo-os-{arch}.tar.zst");
    eprintln!("Downloading tokimo-os-{arch}.tar.zst...");
    let os_tar = download_to_temp(&os_url)?;
    extract_zst(&os_tar, &dir)?;

    // Download and extract rootfs.
    let rootfs_url = format!("{ROOTFS_REPO}/releases/download/{ROOTFS_VERSION}/rootfs-{arch}.tar.zst");
    eprintln!("Downloading rootfs-{arch}.tar.zst...");
    let rootfs_tar = download_to_temp(&rootfs_url)?;

    // rootfs tarball contains a nested rootfs.tar.
    let tmp = std::env::temp_dir().join("tokimo-rootfs-extract");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("mkdir: {e}"))?;
    extract_zst(&rootfs_tar, &tmp)?;

    // Find the rootfs.tar inside.
    let nested_tar = find_file(&tmp, "rootfs.tar").ok_or_else(|| "rootfs.tar not found in archive".to_string())?;
    let rootfs_dir = dir.join("rootfs");
    let _ = std::fs::remove_dir_all(&rootfs_dir);
    std::fs::create_dir_all(&rootfs_dir).map_err(|e| format!("mkdir: {e}"))?;
    extract_tar(&nested_tar, &rootfs_dir)?;
    std::fs::remove_dir_all(&tmp).ok();

    // Ensure /dev/null exists in rootfs.
    let dev_null = rootfs_dir.join("dev").join("null");
    if !dev_null.exists() {
        std::fs::create_dir_all(rootfs_dir.join("dev")).ok();
        std::fs::write(&dev_null, b"").ok();
    }

    eprintln!("VZ artifacts installed to {}", dir.display());
    Ok(())
}

fn download_to_temp(url: &str) -> Result<PathBuf, String> {
    let tmp = std::env::temp_dir().join(format!("tokimo-dl-{}", rand_suffix()));
    let status = Command::new("curl")
        .args(["-sL", "-o", tmp.to_str().unwrap(), url])
        .status()
        .map_err(|e| format!("curl: {e}"))?;
    if !status.success() {
        return Err(format!("curl exited with {status}"));
    }
    Ok(tmp)
}

fn extract_zst(archive: &Path, dest: &Path) -> Result<(), String> {
    let status = Command::new("zstd")
        .args(["-d", "-c"])
        .arg(archive)
        .stdout(std::process::Stdio::piped())
        .status()
        .map_err(|e| format!("zstd: {e}"))?;
    if !status.success() {
        // Try without -c option if it fails.
        let status = Command::new("tar")
            .arg("--zstd")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(dest)
            .arg("--strip-components=0")
            .status()
            .map_err(|e| format!("tar --zstd: {e}"))?;
        if !status.success() {
            return Err(format!("tar --zstd exited with {status}"));
        }
        return Ok(());
    }

    // Pipe zstd output to tar.
    let zstd_child = Command::new("zstd")
        .args(["-d", "-c"])
        .arg(archive)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("zstd spawn: {e}"))?;
    let tar_status = Command::new("tar")
        .arg("-xf")
        .arg("-")
        .arg("-C")
        .arg(dest)
        .stdin(zstd_child.stdout.unwrap())
        .status()
        .map_err(|e| format!("tar: {e}"))?;
    if !tar_status.success() {
        return Err(format!("tar exited with {tar_status}"));
    }
    Ok(())
}

fn extract_tar(archive: &Path, dest: &Path) -> Result<(), String> {
    let status = Command::new("tar")
        .args(["-xf"])
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .arg("--strip-components=1")
        .status()
        .map_err(|e| format!("tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar exited with {status}"));
    }
    Ok(())
}

fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let found = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.file_name().map(|n| n == name).unwrap_or(false) {
                return Some(path);
            }
            if path.is_dir() {
                if let Some(f) = find_file(&path, name) {
                    return Some(f);
                }
            }
        }
    }
    found
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{n:x}")
}
