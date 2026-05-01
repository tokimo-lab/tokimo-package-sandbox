//! Platform dispatch: select the default `SandboxBackend` for the current OS.

use std::sync::Arc;

use crate::backend::SandboxBackend;
use crate::error::Result;

#[cfg(target_os = "windows")]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    let b = crate::windows::sandbox::WindowsBackend::connect()?;
    Ok(Arc::new(b))
}

#[cfg(target_os = "linux")]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    let b = crate::linux::sandbox::LinuxBackend::new()?;
    Ok(Arc::new(b))
}

#[cfg(target_os = "macos")]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    let b = crate::macos::sandbox::MacosBackend::new()?;
    Ok(Arc::new(b))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub(crate) fn default_backend() -> Result<Arc<dyn SandboxBackend>> {
    Err(crate::error::Error::not_supported(
        "no Sandbox backend available for this platform",
    ))
}
