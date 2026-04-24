//! Public configuration types for the sandbox.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Network policy inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No network access at all. On Linux this uses a private network namespace.
    Blocked,
    /// Share the host network namespace. The sandbox can reach everything
    /// the host can reach.
    AllowAll,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy::Blocked
    }
}

/// Resource limits applied to the sandboxed process.
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    /// Maximum resident set size, in megabytes.
    /// Enforced via RLIMIT_AS on Unix and by polling plus Job Object on Windows.
    pub max_memory_mb: u64,
    /// Wall-clock timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum file size the sandbox may create (RLIMIT_FSIZE on Unix).
    pub max_file_size_mb: u64,
    /// Maximum number of processes/threads the sandbox may spawn (RLIMIT_NPROC on Unix).
    pub max_processes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            timeout_secs: 30,
            max_file_size_mb: 64,
            max_processes: 128,
        }
    }
}

impl ResourceLimits {
    pub(crate) fn max_memory_bytes(&self) -> u64 {
        self.max_memory_mb.saturating_mul(1024 * 1024)
    }
}

/// A single bind mount request.
#[derive(Debug, Clone)]
pub struct Mount {
    /// Source path on the host.
    pub host: PathBuf,
    /// Destination path inside the sandbox. Defaults to `host` if `None`.
    pub guest: Option<PathBuf>,
    /// If true, the destination is read-only.
    pub read_only: bool,
}

impl Mount {
    pub fn ro(path: impl Into<PathBuf>) -> Self {
        Self {
            host: path.into(),
            guest: None,
            read_only: true,
        }
    }
    pub fn rw(path: impl Into<PathBuf>) -> Self {
        Self {
            host: path.into(),
            guest: None,
            read_only: false,
        }
    }
    pub fn guest(mut self, g: impl Into<PathBuf>) -> Self {
        self.guest = Some(g.into());
        self
    }
}

/// Sandbox configuration.
///
/// The only path that is writable by default is `work_dir`. Everything else
/// the command may touch must be exposed via `extra_mounts`.
///
/// On Linux the default layout inside the sandbox is:
///   * `/usr /lib /lib64 /bin /sbin` — read-only from host (so system tools work)
///   * `/tmp` — read-write, backed by `work_dir` on the host
///   * `/home /root` — empty
///   * `/proc /dev` — minimal
///   * Sensitive host dotfiles (`~/.ssh`, `~/.aws`, ...) are hidden by tmpfs
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// A human readable name used for logs only.
    pub name: String,
    /// The only writable location inside the sandbox. Mounted at `/tmp` on Linux
    /// (or the platform temp dir). Must exist and be a directory.
    pub work_dir: PathBuf,
    /// Extra host paths to expose inside the sandbox. Each is bind-mounted at
    /// the same path (or an explicit `guest` path).
    pub extra_mounts: Vec<Mount>,
    pub network: NetworkPolicy,
    pub limits: ResourceLimits,
    /// Environment variables passed to the child. `PATH` gets a sensible
    /// default if not provided.
    pub env: Vec<(OsString, OsString)>,
    /// Optional stdin passed to the child as UTF-8 bytes.
    pub stdin: Option<Vec<u8>>,
    /// Working directory of the child process inside the sandbox. If `None`,
    /// defaults to the guest path of `work_dir` (e.g. `/tmp` on Linux).
    pub cwd: Option<PathBuf>,
    /// If true, forward the child's stderr to our stderr in real time.
    pub stream_stderr: bool,
}

impl SandboxConfig {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            name: "sandbox".to_string(),
            work_dir: work_dir.into(),
            extra_mounts: Vec::new(),
            network: NetworkPolicy::default(),
            limits: ResourceLimits::default(),
            env: Vec::new(),
            stdin: None,
            cwd: None,
            stream_stderr: false,
        }
    }
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = n.into();
        self
    }
    pub fn network(mut self, n: NetworkPolicy) -> Self {
        self.network = n;
        self
    }
    pub fn limits(mut self, l: ResourceLimits) -> Self {
        self.limits = l;
        self
    }
    pub fn mount(mut self, m: Mount) -> Self {
        self.extra_mounts.push(m);
        self
    }
    pub fn mounts<I: IntoIterator<Item = Mount>>(mut self, it: I) -> Self {
        self.extra_mounts.extend(it);
        self
    }
    pub fn env<K: Into<OsString>, V: Into<OsString>>(mut self, k: K, v: V) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }
    pub fn envs<I, K, V>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        for (k, v) in it {
            self.env.push((k.into(), v.into()));
        }
        self
    }
    pub fn stdin(mut self, s: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(s.into());
        self
    }
    pub fn stdin_str(mut self, s: impl AsRef<str>) -> Self {
        self.stdin = Some(s.as_ref().as_bytes().to_vec());
        self
    }
    pub fn cwd(mut self, p: impl Into<PathBuf>) -> Self {
        self.cwd = Some(p.into());
        self
    }
    pub fn stream_stderr(mut self, on: bool) -> Self {
        self.stream_stderr = on;
        self
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if !self.work_dir.exists() {
            return Err(crate::Error::validation(format!(
                "work_dir does not exist: {}",
                self.work_dir.display()
            )));
        }
        if !self.work_dir.is_dir() {
            return Err(crate::Error::validation(format!(
                "work_dir is not a directory: {}",
                self.work_dir.display()
            )));
        }
        for m in &self.extra_mounts {
            if !m.host.exists() {
                return Err(crate::Error::validation(format!(
                    "mount host path does not exist: {}",
                    m.host.display()
                )));
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn guest_work_dir(&self) -> &Path {
        // Callers can override via cwd; this is just the default guest mapping.
        Path::new("/tmp")
    }
}
