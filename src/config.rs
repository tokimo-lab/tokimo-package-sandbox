//! Public configuration types for the sandbox.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::host::net_observer::{DnsPolicy, HostPattern, NetEventSink};

/// Network policy inside the sandbox.
#[derive(Clone, Default)]
pub enum NetworkPolicy {
    /// No network access at all. On Linux this uses a private network namespace.
    #[default]
    Blocked,
    /// Share the host network namespace. The sandbox can reach everything
    /// the host can reach.
    AllowAll,
    /// L7-observable: the sandbox runs in the host netns, but an in-process
    /// HTTP(S) proxy is started and the sandbox is pointed at it via
    /// `HTTP_PROXY` / `HTTPS_PROXY`. Every HTTP request and every CONNECT
    /// target (host, port, TLS SNI) is reported to `sink`. Nothing is ever
    /// blocked in this mode — `sink` is advisory only.
    ///
    /// Linux only. Works with tools that honor the `HTTP_PROXY` convention
    /// (curl, pip, python-requests, Node fetch, wget, go http, …). Sandboxed
    /// binaries that dial raw sockets bypass this path; for kernel-level
    /// enforcement see `docs/network-observability.md` Phase 1 (`Observed`
    /// via eBPF cgroup/connect).
    Observed { sink: Arc<dyn NetEventSink> },
    /// L7-observable **and** host allowlisted. Same proxy as `Observed`,
    /// but any request whose host is not in `allow_hosts`, or whose
    /// `sink.on_event` returns `Verdict::Deny`, gets `HTTP 403 Forbidden`.
    ///
    /// Linux only. `dns_policy` is advisory in the current implementation
    /// (the proxy resolves upstream hosts directly) and is carried for API
    /// compatibility with the upcoming slirp4netns path.
    Gated {
        sink: Arc<dyn NetEventSink>,
        allow_hosts: Vec<HostPattern>,
        dns_policy: DnsPolicy,
    },
}

impl std::fmt::Debug for NetworkPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkPolicy::Blocked => f.write_str("Blocked"),
            NetworkPolicy::AllowAll => f.write_str("AllowAll"),
            NetworkPolicy::Observed { .. } => f.write_str("Observed { .. }"),
            NetworkPolicy::Gated {
                allow_hosts,
                dns_policy,
                ..
            } => f
                .debug_struct("Gated")
                .field("allow_hosts", allow_hosts)
                .field("dns_policy", dns_policy)
                .finish_non_exhaustive(),
        }
    }
}

/// Resource limits applied to the sandboxed process.
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    /// Memory limit in megabytes.
    ///
    /// On Unix this is currently enforced as an address-space cap
    /// (`RLIMIT_AS`) plus best-effort RSS polling for one-shot runs. Set to
    /// `0` to skip the memory cap; useful for mmap-heavy runtimes such as Go,
    /// Node, and JVM until a real per-sandbox resource backend is available.
    pub max_memory_mb: u64,
    /// Wall-clock timeout in seconds — used both as the default per-command
    /// timeout for one-shot spawns and as the basis for RLIMIT_CPU
    /// (`timeout_secs + 5`). Set to `0` to skip the RLIMIT_CPU cap; useful
    /// for long-lived agent sessions where each `run_oneshot` call passes
    /// its own per-call timeout and RLIMIT_CPU would otherwise SIGXCPU-kill
    /// CPU-bound children (compilers, linkers) that legitimately exceed the
    /// session's nominal default.
    pub timeout_secs: u64,
    /// Maximum file size the sandbox may create (RLIMIT_FSIZE on Unix).
    /// Set to `0` to skip the cap; useful for coding agents that download
    /// large toolchains (Zig/Rust/Node SDKs) where a hard FSIZE limit causes
    /// SIGXFSZ during tar extraction of binaries larger than the cap.
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
    #[cfg(unix)]
    pub(crate) fn max_memory_bytes(&self) -> u64 {
        self.max_memory_mb.saturating_mul(1024 * 1024)
    }

    #[cfg(unix)]
    pub(crate) fn has_memory_limit(&self) -> bool {
        self.max_memory_mb > 0
    }

    #[cfg(unix)]
    pub(crate) fn has_file_size_limit(&self) -> bool {
        self.max_file_size_mb > 0
    }

    #[cfg(unix)]
    pub(crate) fn has_cpu_time_limit(&self) -> bool {
        self.timeout_secs > 0
    }
}

/// Controls the default system layout that the sandbox prepares before
/// applying `extra_mounts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SystemLayout {
    /// Bind read-only `/usr /lib /lib64 /bin /sbin` and a curated set of
    /// `/etc` files from the host, plus create empty `/home` and `/root`
    /// directories. This is the historical behavior and works well for
    /// quick one-shot sandboxes that want to reuse the host's tooling.
    #[default]
    HostShared,
    /// Skip all default host bind mounts and directory stubs. The caller is
    /// responsible for providing a complete rootfs via `extra_mounts`
    /// (typically by pointing read-only mounts at a packaged rootfs and
    /// per-instance read-write mounts at writable subtrees).
    CallerProvided,
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
    /// Controls whether the sandbox prepares a host-shared default layout
    /// (`/usr`, `/lib`, `/etc/*`, …) before applying `extra_mounts`. Defaults
    /// to [`SystemLayout::HostShared`] for backward compatibility.
    pub system_layout: SystemLayout,
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
    /// Caller-provided root filesystem path. Semantics per backend:
    ///
    /// * **macOS VZ**: host directory shared via virtiofs as the guest rootfs
    ///   (mounted by `init.sh` before chroot). Caller is responsible for
    ///   per-agent isolation (give each agent its own copy).
    /// * **Windows HCS**: caller-supplied target VHDX path used as the
    ///   session rootfs. On first use the file is created by cloning the
    ///   VM rootfs template; on subsequent uses it is reused, so writes to
    ///   `/usr`, `/etc`, `/var`, etc. survive across `Session::open` calls.
    ///   The path is exclusive: a second concurrent `Session::open` for the
    ///   same target fails with a clear error. `None` = default ephemeral
    ///   behaviour.
    /// * **Linux**: currently unused — may be hooked into [`SystemLayout`]
    ///   in the future.
    ///
    /// `None` falls back to backend-specific defaults (env vars, `work_dir`,
    /// `~/.tokimo/rootfs`, …). The library does **not** track agent identity
    /// or perform cloning — that is the caller's responsibility.
    pub rootfs_dir: Option<PathBuf>,
}

impl SandboxConfig {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            name: "sandbox".to_string(),
            work_dir: work_dir.into(),
            extra_mounts: Vec::new(),
            network: NetworkPolicy::default(),
            limits: ResourceLimits::default(),
            system_layout: SystemLayout::default(),
            env: Vec::new(),
            stdin: None,
            cwd: None,
            stream_stderr: false,
            rootfs_dir: None,
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
    pub fn system_layout(mut self, layout: SystemLayout) -> Self {
        self.system_layout = layout;
        self
    }
    pub fn rootfs_dir(mut self, p: impl Into<PathBuf>) -> Self {
        self.rootfs_dir = Some(p.into());
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
