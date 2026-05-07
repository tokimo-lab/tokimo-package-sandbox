//! Platform-specific host font directory discovery.
//!
//! Each platform's default font locations are probed at runtime. Only
//! directories that actually exist on the host are returned, so the caller
//! can safely mount all of them without error-handling per path.

use std::path::PathBuf;

/// A host font directory paired with a unique mount name for FUSE.
#[derive(Debug, Clone)]
pub struct FontDir {
    /// Unique mount name (used as the FUSE tag / logical name).
    pub mount_name: String,
    /// Absolute path on the host.
    pub host_path: PathBuf,
}

/// Discover font directories on the current host.
///
/// Returns only directories that exist. Mount names are stable and
/// collision-free (`"fonts-system"`, `"fonts-local"`, `"fonts-user"`).
pub fn discover_host_font_dirs() -> Vec<FontDir> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        push_if_exists(&mut dirs, "fonts-system", "/usr/share/fonts");
        push_if_exists(&mut dirs, "fonts-local", "/usr/local/share/fonts");
        if let Ok(home) = std::env::var("HOME") {
            push_if_exists(&mut dirs, "fonts-user", PathBuf::from(home).join(".local/share/fonts"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        push_if_exists(&mut dirs, "fonts-system", "/Library/Fonts");
        push_if_exists(&mut dirs, "fonts-system-core", "/System/Library/Fonts");
        if let Ok(home) = std::env::var("HOME") {
            push_if_exists(&mut dirs, "fonts-user", PathBuf::from(home).join("Library/Fonts"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(windir) = std::env::var("WINDIR") {
            let p = PathBuf::from(&windir).join("Fonts");
            push_if_exists(&mut dirs, "fonts-system", &p);
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(&local).join(r"Microsoft\Windows\Fonts");
            push_if_exists(&mut dirs, "fonts-user", &p);
        }
    }

    dirs
}

fn push_if_exists(dirs: &mut Vec<FontDir>, name: &str, path: impl Into<PathBuf>) {
    let path = path.into();
    if path.is_dir() {
        dirs.push(FontDir {
            mount_name: name.to_string(),
            host_path: path,
        });
    }
}
