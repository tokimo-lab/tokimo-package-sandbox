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

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackendKind {
    /// Platform decides; degrades through available backends.
    Auto,
    Disabled,
    Bwrap,
    Ch,
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
