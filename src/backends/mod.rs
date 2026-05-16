#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod shared;
pub mod svc_protocol;
#[cfg(target_os = "windows")]
pub(crate) mod windows;
