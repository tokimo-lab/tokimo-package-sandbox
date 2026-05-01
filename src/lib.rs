//! tokimo-package-sandbox — cross-platform native sandbox.
//!
//! Public API: a single [`Sandbox`] handle exposing 17 commands inspired
//! by Claude `cowork-svc.exe`. See the [`api`] module for details.
//!
//! ```no_run
//! use tokimo_package_sandbox::{Sandbox, ConfigureParams, ExecOpts};
//! let sb = Sandbox::connect().unwrap();
//! sb.configure(ConfigureParams {
//!     user_data_name: "demo".into(),
//!     session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
//!     memory_mb: 4096,
//!     cpu_count: 4,
//!     ..Default::default()
//! }).unwrap();
//! sb.create_vm().unwrap();
//! sb.start_vm().unwrap();
//! let r = sb.exec(&["uname", "-a"], ExecOpts::default()).unwrap();
//! println!("{}", r.stdout_str());
//! sb.stop_vm().unwrap();
//! ```

mod api;
mod backend;
mod error;
mod platform;
pub mod session_registry;

pub mod protocol;
pub mod svc_protocol;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

pub use api::{
    ConfigureParams, Event, ExecOpts, ExecResult, JobId, NetworkPolicy, Plan9Share, Sandbox,
};
pub use backend::SandboxBackend;
pub use error::{Error, Result};

#[cfg(target_os = "windows")]
pub use windows::canonicalize_safe;
#[cfg(target_os = "windows")]
pub use windows::init_client;
