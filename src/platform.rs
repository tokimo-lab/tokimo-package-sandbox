//! Platform dispatch: select the default `SandboxBackend` for the current OS.

use std::sync::Arc;

use crate::backend::SandboxBackend;
use crate::error::Result;

#[cfg(not(target_os = "linux"))]
pub(crate) fn backend_for_kind(_kind: crate::backend_kind::SandboxBackendKind) -> Result<Arc<dyn SandboxBackend>> {
    default_backend()
}

#[cfg(target_os = "windows")]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    let b = crate::windows::sandbox::WindowsBackend::connect()?;
    Ok(Arc::new(b))
}

// ---------------------------------------------------------------------------
// Linux / macOS: wrap the real backend in `SharedBackend` so multiple
// `Sandbox::connect()` calls within the same process can share a VM by
// `session_id`, mirroring the Windows service's behaviour.  See
// `src/shared_backend.rs` for the design and the list of remaining
// gaps vs the Windows model (cross-process reconnect, surviving client
// crashes — both require an out-of-process daemon).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn backend_for_kind(kind: crate::backend_kind::SandboxBackendKind) -> Result<Arc<dyn SandboxBackend>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use crate::backend_kind::SandboxBackendKind;
    use crate::linux::bwrap::sandbox::LinuxBackend;
    use crate::shared_backend::{Registry, SharedBackend};

    // Shared bwrap registry — initialised once per process.
    static BWRAP_REG: OnceLock<Registry<LinuxBackend>> = OnceLock::new();
    fn bwrap_backend() -> Result<Arc<dyn SandboxBackend>> {
        let reg = BWRAP_REG.get_or_init(|| Mutex::new(HashMap::new()));
        fn factory() -> Result<Arc<LinuxBackend>> {
            Ok(Arc::new(LinuxBackend::new()?))
        }
        Ok(Arc::new(SharedBackend::new(reg, factory)))
    }

    // Shared ch registry — initialised once per process.
    static CH_REG: OnceLock<Registry<crate::linux::ch::backend::ChBackend>> = OnceLock::new();
    fn ch_backend() -> Result<Arc<dyn SandboxBackend>> {
        // Fail fast when the host clearly can't run a VM (no KVM, no
        // vsock, missing bundled binaries) so `SandboxBackendKind::Auto`
        // can degrade to bwrap without paying the cost of a doomed boot.
        let probe = crate::linux::ch::probe::probe_ch();
        if !probe.is_ready() {
            return Err(crate::error::Error::not_supported(format!(
                "cloud-hypervisor backend not ready:\n{}",
                probe.report()
            )));
        }
        let reg = CH_REG.get_or_init(|| Mutex::new(HashMap::new()));
        fn factory() -> Result<Arc<crate::linux::ch::backend::ChBackend>> {
            Ok(Arc::new(crate::linux::ch::backend::ChBackend::new()?))
        }
        Ok(Arc::new(SharedBackend::new(reg, factory)))
    }

    match kind {
        SandboxBackendKind::Auto => {
            // Try Cloud Hypervisor first, then degrade to bwrap. If both
            // fail, propagate the bwrap error (the more user-actionable one).
            match ch_backend() {
                Ok(b) => Ok(b),
                Err(ch_err) => {
                    tracing::info!(
                        ch_error = %ch_err,
                        "Auto: ch backend unavailable, falling back to bwrap"
                    );
                    match bwrap_backend() {
                        Ok(b) => Ok(b),
                        Err(bwrap_err) => Err(crate::error::Error::not_supported(format!(
                            "no sandbox backend available on this host\n  ch:    {ch_err}\n  bwrap: {bwrap_err}"
                        ))),
                    }
                }
            }
        }
        // Explicit force: no fallback. Caller asked for this specific backend.
        SandboxBackendKind::Ch => ch_backend(),
        SandboxBackendKind::Bwrap => bwrap_backend(),
        SandboxBackendKind::Disabled => Err(crate::error::Error::not_supported(
            "sandbox backend is disabled (SANDBOX_BACKEND=disabled)",
        )),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    use crate::backend_kind::detect_backend;
    backend_for_kind(detect_backend())
}

#[cfg(target_os = "macos")]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use crate::macos::sandbox::MacosBackend;
    use crate::shared_backend::{Registry, SharedBackend};

    static REG: OnceLock<Registry<MacosBackend>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(HashMap::new()));

    fn factory() -> Result<Arc<MacosBackend>> {
        Ok(Arc::new(MacosBackend::new()?))
    }
    Ok(Arc::new(SharedBackend::new(reg, factory)))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    Err(crate::error::Error::not_supported(
        "no Sandbox backend available for this platform",
    ))
}
