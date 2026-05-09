//! `SANDBOX_BACKEND` env enum — selects which sandbox implementation to use.
//!
//! | Value      | Meaning                                               |
//! |------------|-------------------------------------------------------|
//! | `disabled` | No isolation (V2 default, equivalent to SAFEBOX_DISABLE=1) |
//! | `bwrap`    | Linux bubblewrap + seccomp (existing path)            |
//! | `ch`       | Cloud Hypervisor microVM (V3.0 PoC)                   |

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackendKind {
    Disabled,
    Bwrap,
    Ch,
}

/// Read `SANDBOX_BACKEND` from the environment and return the selected backend.
///
/// - Unknown / missing values default to [`SandboxBackendKind::Disabled`].
/// - Matching is case-insensitive.
pub fn detect_backend() -> SandboxBackendKind {
    let raw = std::env::var("SANDBOX_BACKEND").unwrap_or_default();
    let kind = match raw.trim().to_lowercase().as_str() {
        "disabled" => SandboxBackendKind::Disabled,
        "bwrap" => SandboxBackendKind::Bwrap,
        "ch" => SandboxBackendKind::Ch,
        other => {
            if !other.is_empty() {
                tracing::warn!(
                    value = other,
                    "SANDBOX_BACKEND has unrecognised value; defaulting to disabled"
                );
            }
            SandboxBackendKind::Disabled
        }
    };
    tracing::info!(?kind, "sandbox backend selected");
    kind
}
