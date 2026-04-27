//! Multi-user [`Workspace`] — a shared bwrap container with per-user isolation.
//!
//! A single `Workspace` holds one `tokimo-sandbox-init` container. Each user
//! gets an independent [`InitClient`] connection + bash shell with isolated
//! `$TMPDIR`, cwd, and process lifecycle.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use tokimo_package_sandbox::{SandboxConfig, Workspace, UserConfig};
//!
//! let ws = Workspace::open(&SandboxConfig::new("/tmp/ws"))?;
//! ws.add_user(&UserConfig::new("alice"))?;
//! let out = ws.exec("alice", "echo hello", Duration::from_secs(10))?;
//! assert_eq!(out.stdout.trim(), "hello");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Mount, NetworkPolicy, ResourceLimits, SandboxConfig};
use crate::init_client::InitClient;
use crate::linux::{SpawnedInit, spawn_init_workspace};
use crate::session::ExecOutput;
use crate::{Error, Result};

/// Configuration for a multi-user [`Workspace`].
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Host directory used as the container's writable root.
    pub work_dir: PathBuf,
    /// Mounts shared by all users.
    pub shared_mounts: Vec<Mount>,
    /// Network policy applied to the container.
    pub network: NetworkPolicy,
    /// Resource limits applied to the container.
    pub limits: ResourceLimits,
    /// Environment variables set for all users (can be overridden per-user).
    pub env: Vec<(String, String)>,
}

impl WorkspaceConfig {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
            shared_mounts: Vec::new(),
            network: NetworkPolicy::default(),
            limits: ResourceLimits::default(),
            env: Vec::new(),
        }
    }

    pub fn network(mut self, n: NetworkPolicy) -> Self {
        self.network = n;
        self
    }

    pub fn limits(mut self, l: ResourceLimits) -> Self {
        self.limits = l;
        self
    }

    pub fn mount(mut self, m: Mount) -> Self {
        self.shared_mounts.push(m);
        self
    }

    fn to_sandbox_config(&self) -> SandboxConfig {
        SandboxConfig::new(&self.work_dir)
            .network(self.network.clone())
            .limits(self.limits)
            .mounts(self.shared_mounts.clone())
            .envs(self.env.clone())
    }
}

/// Per-user configuration for [`Workspace::add_user`].
#[derive(Debug, Clone)]
pub struct UserConfig {
    pub user_id: String,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub exec_timeout: Duration,
}

impl UserConfig {
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            cwd: None,
            env: Vec::new(),
            exec_timeout: Duration::from_secs(30),
        }
    }

    pub fn cwd(mut self, p: impl Into<PathBuf>) -> Self {
        self.cwd = Some(p.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.exec_timeout = d;
        self
    }
}

/// Handle to a single user inside a [`Workspace`].
pub struct UserHandle {
    pub user_id: String,
    client: Arc<InitClient>,
    shell_id: String,
    timeout: Duration,
}

/// A shared sandbox container hosting multiple isolated users.
///
/// Created via [`Workspace::open`]. Users are added dynamically via
/// [`Workspace::add_user`]; each gets an independent bash shell with
/// isolated `$TMPDIR` and working directory.
pub struct Workspace {
    spawned: SpawnedInit,
    users: HashMap<String, UserHandle>,
    host_sock: PathBuf,
}

impl Workspace {
    /// Launch a shared sandbox container. No users are added yet —
    /// call [`Workspace::add_user`] for each.
    pub fn open(cfg: &WorkspaceConfig) -> Result<Self> {
        let sandbox_cfg = cfg.to_sandbox_config();
        let mut spawned = spawn_init_workspace(&sandbox_cfg)?;
        let host_sock = spawned.host_control_dir.path().join("control.sock");

        // Wait for init to bind the control socket.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !host_sock.exists() {
            if let Ok(Some(status)) = spawned.child.try_wait() {
                let mut stderr = String::new();
                if let Some(ref mut pipe) = spawned.child.stderr {
                    use std::io::Read;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                return Err(Error::exec(format!(
                    "init exited with {status} before binding control socket at {}; stderr: {stderr}",
                    host_sock.display()
                )));
            }
            if std::time::Instant::now() > deadline {
                return Err(Error::exec(format!(
                    "control socket never appeared at {}",
                    host_sock.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        Ok(Self {
            spawned,
            users: HashMap::new(),
            host_sock,
        })
    }

    /// Add a user. Connects a new [`InitClient`] to the running init,
    /// sends `AddUser`, and records the resulting shell `child_id`.
    pub fn add_user(&mut self, cfg: &UserConfig) -> Result<()> {
        let client = Arc::new(InitClient::connect(&self.host_sock)?);
        client.hello()?;

        let env_overlay: Vec<(String, String)> = cfg
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let cwd = cfg.cwd.as_ref().map(|p| p.to_string_lossy().into_owned());
        let info = client.add_user(&cfg.user_id, &env_overlay, cwd.as_deref())?;

        let handle = UserHandle {
            user_id: cfg.user_id.clone(),
            client,
            shell_id: info.child_id,
            timeout: cfg.exec_timeout,
        };
        self.users.insert(cfg.user_id.clone(), handle);
        Ok(())
    }

    /// Remove a user: kills all their processes and disconnects their client.
    pub fn remove_user(&mut self, user_id: &str) -> Result<()> {
        if let Some(handle) = self.users.remove(user_id) {
            handle.client.remove_user(user_id)?;
            // Drop the handle explicitly to close the socket, then give the
            // init event loop a tick to process the EOF + disconnect before
            // the next user connects. Without this, a rapid add_user after
            // remove may race with the init's poll batch ordering.
            drop(handle);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }

    /// Execute a command in the user's bash environment. Uses cwd/env
    /// inheritance from the user's shell. On timeout, only the spawned
    /// child is killed — the user's bash and other users are unaffected.
    pub fn exec(&self, user_id: &str, cmd: &str, timeout: Duration) -> Result<ExecOutput> {
        let user = self.users.get(user_id).ok_or_else(|| {
            Error::exec(format!("user {user_id} not found"))
        })?;
        let handle = user.client.spawn_pipes_inherit_async(
            &["/bin/bash", "-c", cmd],
            &[],
            None,
            Some(&user.shell_id),
        )?;
        let (stdout, stderr, code) = handle.wait_with_timeout(timeout)?;
        Ok(ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
        })
    }

    /// Execute a command using the user's default timeout.
    pub fn exec_default(&self, user_id: &str, cmd: &str) -> Result<ExecOutput> {
        let timeout = self.users.get(user_id)
            .map(|u| u.timeout)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        self.exec(user_id, cmd, timeout)
    }

    /// Spawn a background job in the user's environment. Returns the job's
    /// `child_id` for later tracking / kill.
    pub fn spawn(&self, user_id: &str, cmd: &str) -> Result<String> {
        let user = self.users.get(user_id).ok_or_else(|| {
            Error::exec(format!("user {user_id} not found"))
        })?;
        let info = user.client.spawn_pipes_inherit(
            &["/bin/bash", "-c", cmd],
            &[],
            None,
            Some(&user.shell_id),
        )?;
        Ok(info.child_id)
    }

    /// Re-create the user's bash shell after it died (e.g., due to timeout
    /// or accidental kill). The new shell inherits the same user config.
    pub fn respawn_shell(&mut self, user_id: &str) -> Result<()> {
        let handle = self.users.get(user_id).ok_or_else(|| {
            Error::exec(format!("user {user_id} not found"))
        })?;
        let info = handle.client.add_user(user_id, &[], None)?;
        // We need to update the shell_id. Since UserHandle doesn't have
        // interior mutability, rebuild the handle.
        let new_handle = UserHandle {
            user_id: handle.user_id.clone(),
            client: handle.client.clone(),
            shell_id: info.child_id,
            timeout: handle.timeout,
        };
        self.users.insert(user_id.to_string(), new_handle);
        Ok(())
    }

    /// Dynamically bind-mount a path for a specific user. `source` must
    /// already be visible inside the container.
    pub fn add_mount(&self, user_id: &str, source: &str, target: &str, read_only: bool) -> Result<()> {
        let user = self.users.get(user_id).ok_or_else(|| {
            Error::exec(format!("user {user_id} not found"))
        })?;
        user.client.bind_mount(source, target, read_only)
    }

    /// Unmount a previously bind-mounted path for a specific user.
    pub fn remove_mount(&self, user_id: &str, target: &str) -> Result<()> {
        let user = self.users.get(user_id).ok_or_else(|| {
            Error::exec(format!("user {user_id} not found"))
        })?;
        user.client.unmount(target)
    }

    /// Kill a specific child process by id.
    pub fn kill(&self, user_id: &str, child_id: &str) -> Result<()> {
        let user = self.users.get(user_id).ok_or_else(|| {
            Error::exec(format!("user {user_id} not found"))
        })?;
        user.client.signal(child_id, libc::SIGKILL, true)
    }

    /// Return the number of active users.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Shut down the entire container and all users.
    pub fn close(mut self) -> Result<()> {
        // Remove all users.
        let user_ids: Vec<String> = self.users.keys().cloned().collect();
        for uid in &user_ids {
            let _ = self.remove_user(uid);
        }
        // SpawnedInit is dropped when `self` goes out of scope,
        // triggering bwrap PDEATHSIG cleanup.
        Ok(())
    }

    /// Access the underlying [`InitClient`] for a user (for advanced use).
    pub fn client(&self, user_id: &str) -> Option<&Arc<InitClient>> {
        self.users.get(user_id).map(|h| &h.client)
    }

    /// Get the shell `child_id` for a user.
    pub fn shell_id(&self, user_id: &str) -> Option<&str> {
        self.users.get(user_id).map(|h| h.shell_id.as_str())
    }
}
