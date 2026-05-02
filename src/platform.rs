//! Platform dispatch: select the default `SandboxBackend` for the current OS.

use std::sync::Arc;

use crate::backend::SandboxBackend;
use crate::error::Result;

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
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use crate::linux::sandbox::LinuxBackend;
    use crate::shared_backend::{Registry, SharedBackend};

    static REG: OnceLock<Registry<LinuxBackend>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(HashMap::new()));

    fn factory() -> Result<Arc<LinuxBackend>> {
        Ok(Arc::new(LinuxBackend::new()?))
    }
    Ok(Arc::new(SharedBackend::new(reg, factory)))
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
