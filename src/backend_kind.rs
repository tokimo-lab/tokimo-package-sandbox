//! `SANDBOX_BACKEND` env enum — selects which sandbox implementation to use.
//!
//! Semantics:
//!
//! - **Env unset** → [`SandboxBackendKind::Auto`]: the platform picks the
//!   best-available backend, gracefully degrading from ch → bwrap on Linux.
//!   If no backend is available, `Sandbox::connect()` returns an error.
//! - **`SANDBOX_BACKEND=<value>`** → caller is *forcing* a specific backend.
//!   No degradation: if the requested backend is not available, the call
//!   fails. Use this only in dev / CI when you want to test a specific path.
//!
//! | Value      | Meaning                                                   |
//! |------------|-----------------------------------------------------------|
//! | (unset)    | Auto: ch → bwrap fallback (Linux); platform default otherwise |
//! | `disabled` | Explicit fail (no sandbox; equivalent to SAFEBOX_DISABLE=1 if honoured) |
//! | `bwrap`    | Linux bubblewrap + seccomp; fail if unavailable           |
//! | `ch`       | Cloud Hypervisor microVM; fail if unavailable             |

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackendKind {
    /// Platform decides; degrades through available backends.
    Auto,
    Disabled,
    Bwrap,
    Ch,
}

/// Concrete backend currently driving a [`Sandbox`](crate::Sandbox).
///
/// Unlike [`SandboxBackendKind`] — which describes the caller's *request*
/// (and includes `Auto`) — `ActiveBackend` always names the specific
/// backend implementation actually in use. Returned by
/// [`Sandbox::active_backend`](crate::Sandbox::active_backend) so callers
/// (and CI logs) can confirm which path was selected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActiveBackend {
    /// Linux: `bubblewrap` + seccomp; no VM.
    Bwrap,
    /// Linux: Cloud Hypervisor micro-VM.
    Ch,
    /// macOS: Apple Virtualization.framework micro-VM.
    Macos,
    /// Windows: Hyper-V (HCS) micro-VM via `tokimo-sandbox-svc`.
    Windows,
}

impl ActiveBackend {
    /// Lowercase identifier (matches the `serde` form).
    pub const fn as_str(self) -> &'static str {
        match self {
            ActiveBackend::Bwrap => "bwrap",
            ActiveBackend::Ch => "ch",
            ActiveBackend::Macos => "macos",
            ActiveBackend::Windows => "windows",
        }
    }
}

impl std::fmt::Display for ActiveBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read `SANDBOX_BACKEND` from the environment and return the selected backend.
///
/// - Unset → [`SandboxBackendKind::Auto`] (the platform layer will then probe
///   backends in priority order and pick the first that works).
/// - Explicit value → that backend; no fallback applied.
/// - Unknown values → warn + Auto.
/// - Matching is case-insensitive.
pub fn detect_backend() -> SandboxBackendKind {
    let raw = std::env::var("SANDBOX_BACKEND").unwrap_or_default();
    let kind = match raw.trim().to_lowercase().as_str() {
        "" => SandboxBackendKind::Auto,
        "disabled" => SandboxBackendKind::Disabled,
        "bwrap" => SandboxBackendKind::Bwrap,
        "ch" => SandboxBackendKind::Ch,
        other => {
            tracing::warn!(value = other, "SANDBOX_BACKEND has unrecognised value; using Auto");
            SandboxBackendKind::Auto
        }
    };
    tracing::info!(?kind, "sandbox backend selected");
    kind
}
