//! Probe host readiness for the Cloud Hypervisor (CH) backend.
//!
//! `probe_ch()` does purely read-only filesystem / process-group checks and
//! never modifies system state.  Designed to be cheap enough to call at
//! startup.

use std::path::PathBuf;

pub struct ChProbeResult {
    /// `/dev/kvm` exists and is accessible (stat succeeds).
    pub kvm_dev: bool,
    /// `/dev/vhost-vsock` exists.
    pub vhost_vsock_dev: bool,
    /// Path to the `cloud-hypervisor` binary, if found.
    pub ch_binary: Option<PathBuf>,
    /// `/sys/module/kvm` exists — KVM module is loaded.
    pub kvm_module_loaded: bool,
    /// Current process' supplementary groups include the `kvm` group.
    pub user_in_kvm_group: bool,
    /// `virtiofsd` binary is available.
    pub virtiofsd_available: bool,
}

/// Run all availability checks and return a [`ChProbeResult`].
pub fn probe_ch() -> ChProbeResult {
    ChProbeResult {
        kvm_dev: std::fs::metadata("/dev/kvm").is_ok(),
        vhost_vsock_dev: std::fs::metadata("/dev/vhost-vsock").is_ok(),
        ch_binary: find_ch_binary(),
        kvm_module_loaded: std::fs::metadata("/sys/module/kvm").is_ok(),
        user_in_kvm_group: current_user_in_kvm_group(),
        virtiofsd_available: find_virtiofsd_binary().is_some(),
    }
}

impl ChProbeResult {
    /// Returns `true` when the CH backend can be used.
    ///
    /// Minimum requirements: KVM device accessible + vsock device present +
    /// a binary to invoke.
    pub fn is_ready(&self) -> bool {
        self.kvm_dev && self.vhost_vsock_dev && self.ch_binary.is_some()
    }

    /// A human-readable, one-item-per-line summary suitable for log output.
    pub fn report(&self) -> String {
        let check = |ok: bool| if ok { "✅" } else { "❌" };
        let binary_str = self
            .ch_binary
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not found".to_string());

        format!(
            "{} /dev/kvm accessible\n\
             {} /dev/vhost-vsock present\n\
             {} cloud-hypervisor binary: {}\n\
             {} /sys/module/kvm loaded\n\
             {} current user in kvm group\n\
             {} virtiofsd available\n\
             {} overall ready",
            check(self.kvm_dev),
            check(self.vhost_vsock_dev),
            check(self.ch_binary.is_some()),
            binary_str,
            check(self.kvm_module_loaded),
            check(self.user_in_kvm_group),
            check(self.virtiofsd_available),
            check(self.is_ready()),
        )
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Check if a path points to an executable file.
///
/// On Unix, verifies the file has executable permissions (mode & 0o111 != 0).
/// On non-Unix, falls back to checking if it's a file.
#[cfg(unix)]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &std::path::Path) -> bool {
    path.is_file()
}

/// Search for the `cloud-hypervisor` binary.
///
/// Priority order:
/// 1. `bin/cloud-hypervisor/current/bin/cloud-hypervisor` (project deps
///    convention: bin/<name>/current/bin/<binary_name>, matching yt-dlp /
///    lightpanda install layout produced by fetch.ts `kind = "binary"`).
/// 2. Each directory in `PATH`.
fn find_ch_binary() -> Option<PathBuf> {
    // 1. Project-local install (deps convention: bin/<name>/current/<host>/<bin>)
    //    Detect workspace root via CARGO_MANIFEST_DIR at build time — at runtime
    //    we use the executable's location as a heuristic.
    let project_path = locate_project_ch_binary();
    if let Some(ref p) = project_path
        && is_executable_file(p)
    {
        return project_path;
    }

    // 2. PATH search
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("cloud-hypervisor");
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn locate_project_ch_binary() -> Option<PathBuf> {
    // Walk up from the current exe to find the repo root (contains `bin/`).
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..8 {
        let candidate = dir
            .join("bin")
            .join("cloud-hypervisor")
            .join("current")
            .join("bin")
            .join("cloud-hypervisor");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
    None
}

/// Search for the `virtiofsd` binary.
///
/// Priority order:
/// 1. `bin/virtiofsd/current/virtiofsd` (project deps convention)
/// 2. Each directory in `PATH`.
fn find_virtiofsd_binary() -> Option<PathBuf> {
    // 1. Project-local install
    let project_path = locate_project_virtiofsd_binary();
    if let Some(ref p) = project_path
        && is_executable_file(p)
    {
        return project_path;
    }

    // 2. PATH search
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("virtiofsd");
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn locate_project_virtiofsd_binary() -> Option<PathBuf> {
    // Walk up from the current exe to find the repo root (contains `bin/`).
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..8 {
        let candidate = dir.join("bin").join("virtiofsd").join("current").join("virtiofsd");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
    None
}

/// Return `true` if the current process belongs to the `kvm` group.
///
/// Parses `/etc/group` for the `kvm:` entry and checks against the process'
/// effective GID and supplementary group list.
fn current_user_in_kvm_group() -> bool {
    let kvm_gid = kvm_group_gid();
    if kvm_gid.is_none() {
        return false;
    }
    let kvm_gid = kvm_gid.unwrap();

    // Check primary group first
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // effective GID
        if let Ok(meta) = std::fs::metadata("/proc/self")
            && meta.gid() == kvm_gid
        {
            return true;
        }
    }

    // Check supplementary groups via nix
    #[cfg(target_os = "linux")]
    {
        if let Ok(groups) = nix::unistd::getgroups() {
            return groups.iter().any(|g| g.as_raw() == kvm_gid);
        }
    }

    false
}

/// Parse `/etc/group` to find the numeric GID for the `kvm` group.
fn kvm_group_gid() -> Option<u32> {
    let content = std::fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        // Format: group_name:password:GID:user_list
        let mut parts = line.splitn(4, ':');
        let name = parts.next()?;
        if name != "kvm" {
            continue;
        }
        let _passwd = parts.next();
        let gid_str = parts.next()?;
        return gid_str.parse::<u32>().ok();
    }
    None
}
