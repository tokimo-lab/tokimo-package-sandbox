//! Cross-platform init-client abstraction for [`super::Workspace`].
//!
//! Wraps the Linux [`InitClient`][crate::linux::init_client::InitClient] and the macOS
//! [`VsockInitClient`][crate::macos::vz_vsock::VsockInitClient] behind a common
//! enum so `Workspace` doesn't need to be generic.

use std::sync::Arc;
use std::time::Duration;

use crate::Result;

// ---------------------------------------------------------------------------
// AnyInitClient
// ---------------------------------------------------------------------------

/// Platform-agnostic wrapper around the host-side init control client.
///
/// On Linux this is [`InitClient`]; on macOS it's `VsockInitClient`.
/// Both speak the same wire protocol — only the transport differs.
#[allow(missing_docs)]
pub(crate) enum AnyInitClient {
    #[cfg(target_os = "linux")]
    Linux(Arc<crate::linux::init_client::InitClient>),
    #[cfg(target_os = "macos")]
    MacOs(Arc<crate::macos::vz_vsock::VsockInitClient>),
}

/// Opaque handle to a running child, returned by
/// [`AnyInitClient::spawn_pipes_inherit_async`].
pub(crate) enum AnyChildHandle {
    #[cfg(target_os = "linux")]
    Linux(crate::linux::init_client::ChildHandle),
    #[cfg(target_os = "macos")]
    MacOs(crate::macos::vz_vsock::ChildHandle),
}

/// Result of a Spawn / OpenShell / AddUser op.
pub(crate) struct AnySpawnInfo {
    pub child_id: String,
}

impl AnyInitClient {
    // -- hello, add_user, remove_user ---------------------------------------

    pub fn hello(&self) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => {
                c.hello()?;
            }
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => {
                c.hello()?;
            }
        }
        Ok(())
    }

    pub fn add_user(&self, user_id: &str, env_overlay: &[(String, String)], cwd: Option<&str>) -> Result<AnySpawnInfo> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => {
                let info = c.add_user(user_id, env_overlay, cwd)?;
                Ok(AnySpawnInfo {
                    child_id: info.child_id,
                })
            }
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => {
                let info = c.add_user(user_id, env_overlay, cwd)?;
                Ok(AnySpawnInfo {
                    child_id: info.child_id,
                })
            }
        }
    }

    pub fn remove_user(&self, user_id: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => c.remove_user(user_id),
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => c.remove_user(user_id),
        }
    }

    // -- spawn --------------------------------------------------------------

    pub fn spawn_pipes_inherit(
        &self,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        inherit_from_child: Option<&str>,
    ) -> Result<AnySpawnInfo> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => {
                let info = c.spawn_pipes_inherit(argv, env_overlay, cwd, inherit_from_child)?;
                Ok(AnySpawnInfo {
                    child_id: info.child_id,
                })
            }
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => {
                let info = c.spawn_pipes_inherit(argv, env_overlay, cwd, inherit_from_child)?;
                Ok(AnySpawnInfo {
                    child_id: info.child_id,
                })
            }
        }
    }

    pub fn spawn_pipes_inherit_async(
        &self,
        argv: &[&str],
        env_overlay: &[(String, String)],
        cwd: Option<&str>,
        inherit_from_child: Option<&str>,
    ) -> Result<AnyChildHandle> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => {
                let h = c.spawn_pipes_inherit_async(argv, env_overlay, cwd, inherit_from_child)?;
                Ok(AnyChildHandle::Linux(h))
            }
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => {
                let h = c.spawn_pipes_inherit_async(argv, env_overlay, cwd, inherit_from_child)?;
                Ok(AnyChildHandle::MacOs(h))
            }
        }
    }

    // -- mounts -------------------------------------------------------------

    pub fn bind_mount(&self, source: &str, target: &str, read_only: bool) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => c.bind_mount(source, target, read_only),
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => c.bind_mount(source, target, read_only),
        }
    }

    pub fn unmount(&self, target: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => c.unmount(target),
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => c.unmount(target),
        }
    }

    // -- signal -------------------------------------------------------------

    pub fn signal(&self, child_id: &str, sig: i32, to_pgrp: bool) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => c.signal(child_id, sig, to_pgrp),
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => c.signal(child_id, sig, to_pgrp),
        }
    }

    // -- clone (for internal Arc duplication) -------------------------------

    pub fn clone_arc(&self) -> Self {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(c) => Self::Linux(Arc::clone(c)),
            #[cfg(target_os = "macos")]
            Self::MacOs(c) => Self::MacOs(Arc::clone(c)),
        }
    }
}

impl AnyChildHandle {
    pub fn wait_with_timeout(&self, timeout: Duration) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(h) => h.wait_with_timeout(timeout),
            #[cfg(target_os = "macos")]
            Self::MacOs(h) => h.wait_with_timeout(timeout),
        }
    }
}
