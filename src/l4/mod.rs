//! L4 network observer — catches any `connect()` / `sendto()` syscall made
//! inside the sandbox, regardless of whether the guest respects
//! `HTTP_PROXY`. Complements the L7 proxy in `net_observer` so raw TCP/UDP
//! traffic (telnet, nc, Python `socket.socket()`) is also reported to
//! `NetEventSink`.
//!
//! Two backends share the same `L4Observer` facade:
//!
//! * `seccomp_notify` — rootless. Installs a seccomp filter with
//!   `SECCOMP_FILTER_FLAG_NEW_LISTENER` in the bwrap-child's `pre_exec`,
//!   hands the listener fd back to the parent via SCM_RIGHTS, and runs a
//!   notify loop in a parent thread. **Observability only** — even in
//!   `Gated` mode the allow/deny verdict is best-effort (TOCTOU on the
//!   user-space `sockaddr*`; see `seccomp_unotify(2)`).
//! * `ebpf` (feature `ebpf`, not compiled by default) — privileged, low
//!   overhead. Attaches to `cgroup/connect4` etc. via aya. Scaffold only on
//!   this host; requires `CAP_BPF` + `bpf-linker`.
//!
//! Backend selection is automatic: eBPF if the feature is compiled in AND
//! the runtime has permission, otherwise seccomp.

#![cfg(target_os = "linux")]

use crate::net_observer::{HostPattern, Layer, NetEvent, NetEventSink, Proto, Verdict};
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

pub(crate) mod seccomp_notify;
pub(crate) mod seccomp_trace;

#[cfg(feature = "ebpf")]
pub(crate) mod ebpf;

/// Backend-agnostic config passed by `linux.rs` when wiring an L4 observer.
#[derive(Clone)]
pub(crate) struct L4Config {
    pub sink: Arc<dyn NetEventSink>,
    pub allow_hosts: Vec<HostPattern>,
    /// true for `Gated`; false for `Observed`.
    pub enforce_allow: bool,
}

impl L4Config {
    /// Decide the verdict for an L4 event. `Gated` denies by default unless
    /// the remote IP looks like localhost OR the sink explicitly overrides,
    /// since L4 has no hostname — allowlist matching is advisory for now.
    pub fn decide(&self, ev: &NetEvent) -> Verdict {
        let sink_verdict = self.sink.on_event(ev);
        if !self.enforce_allow {
            return Verdict::Allow; // Observed: never deny, whatever sink says.
        }
        match sink_verdict {
            Verdict::Deny(r) => Verdict::Deny(r),
            Verdict::Allow => {
                // Gated: if the sink didn't speak up, allow loopback + any
                // host matching the allowlist by IP literal; everything else
                // is denied. Name-based policy still enforced at L7.
                if let Some(sa) = ev.remote {
                    if sa.ip().is_loopback() {
                        return Verdict::Allow;
                    }
                    let ip_str = sa.ip().to_string();
                    if self.allow_hosts.iter().any(|p| p.matches(&ip_str)) {
                        return Verdict::Allow;
                    }
                }
                Verdict::Deny("L4 gated: host not in allowlist".into())
            }
        }
    }
}

/// Runtime-side handle for an L4 observer. Dropping it shuts the backend
/// down (closes listener fd, joins thread).
pub(crate) struct L4Handle {
    _inner: Box<dyn L4Backend>,
}

pub(crate) trait L4Backend: Send {}

impl L4Backend for seccomp_notify::SeccompNotifyHandle {}
impl L4Backend for seccomp_trace::SeccompTraceHandle {}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Backend {
    SeccompNotify,
    SeccompTrace,
    #[cfg(feature = "ebpf")]
    Ebpf,
}

/// Preparation step: called BEFORE `Command::spawn`. Returns a pair of
/// (child-side install data, parent-side pending state). The caller:
///
/// 1. Captures `install` in its `pre_exec` closure and invokes
///    `child_install(install)` there.
/// 2. After `Command::spawn` returns, calls `finalize(pending, cfg)` to
///    kick off the parent-side listener thread.
pub(crate) fn prepare(cfg: L4Config) -> std::io::Result<(ChildInstall, Pending)> {
    #[cfg(feature = "ebpf")]
    if ebpf::is_supported() {
        return ebpf::prepare(cfg);
    }
    match seccomp_notify::prepare(cfg.clone()) {
        Ok(v) => Ok(v),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            tracing::info!(
                "l4: seccomp-notify unsupported ({}), falling back to seccomp-trace",
                e
            );
            seccomp_trace::prepare(cfg)
        }
        Err(e) => Err(e),
    }
}

/// Child-side install payload. `Copy` so it can be moved into a `pre_exec`
/// closure without lifetime entanglements.
#[derive(Copy, Clone)]
pub(crate) struct ChildInstall {
    pub child_fd: RawFd,
    pub backend: Backend,
}

/// Parent-side pending state. Not Send-safe to clone; consume via `finalize`.
pub(crate) enum Pending {
    SeccompNotify(seccomp_notify::Pending),
    SeccompTrace(seccomp_trace::Pending),
    #[cfg(feature = "ebpf")]
    Ebpf(ebpf::Pending),
}

/// Async-signal-safe installer. Call from `pre_exec`.
///
/// # Safety
/// Must be called exactly once, in the child, after fork and before exec.
pub(crate) unsafe fn child_install(ci: ChildInstall) -> std::io::Result<()> {
    match ci.backend {
        Backend::SeccompNotify => seccomp_notify::child_install(ci.child_fd),
        Backend::SeccompTrace => seccomp_trace::child_install(),
        #[cfg(feature = "ebpf")]
        Backend::Ebpf => Ok(()),
    }
}

/// Parent-side finalizer. Spawns the notify-loop thread.
///
/// `child_pid` is only consulted by the trace backend; notify/ebpf
/// ignore it. The returned `Option<Receiver<ExitStatus>>` is `Some` only
/// for the trace backend — when present, the caller MUST use it instead
/// of `Child::wait()` (the tracer thread reaps the child).
pub(crate) fn finalize(
    pending: Pending,
    cfg: L4Config,
    child_pid: i32,
) -> std::io::Result<(L4Handle, Option<std::sync::mpsc::Receiver<std::process::ExitStatus>>)> {
    match pending {
        Pending::SeccompNotify(p) => {
            let h = seccomp_notify::start_parent(p, cfg)?;
            Ok((L4Handle { _inner: Box::new(h) }, None))
        }
        Pending::SeccompTrace(p) => {
            let (h, rx) = seccomp_trace::start_parent(p, cfg, child_pid)?;
            Ok((L4Handle { _inner: Box::new(h) }, Some(rx)))
        }
        #[cfg(feature = "ebpf")]
        Pending::Ebpf(p) => {
            let h = ebpf::start_parent(p, cfg)?;
            Ok((L4Handle { _inner: Box::new(h) }, None))
        }
    }
}

// ---- helpers shared across backends ------------------------------------

pub(crate) fn build_event(
    remote: SocketAddr,
    proto: Proto,
    pid: u32,
    comm: Option<String>,
) -> NetEvent {
    NetEvent {
        ts: std::time::SystemTime::now(),
        pid: Some(pid),
        comm,
        layer: Layer::L4,
        protocol: proto,
        remote: Some(remote),
        host: None,
        port: Some(remote.port()),
        sni: None,
        http_method: None,
        http_path: None,
        http_url: None,
        dns_query: None,
        dns_answers: vec![],
    }
}

/// Close-idempotent `close(fd)`.
pub(crate) fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

/// `AtomicBool` helper used by all backends for cooperative shutdown.
pub(crate) type Shutdown = Arc<AtomicBool>;

pub(crate) fn new_shutdown() -> Shutdown {
    Arc::new(AtomicBool::new(false))
}

pub(crate) fn is_shutdown(s: &Shutdown) -> bool {
    s.load(Ordering::SeqCst)
}

pub(crate) fn _set_shutdown(s: &Shutdown) {
    s.store(true, Ordering::SeqCst);
}

pub(crate) fn _join_silently(h: Option<JoinHandle<()>>) {
    if let Some(h) = h {
        let _ = h.join();
    }
}
