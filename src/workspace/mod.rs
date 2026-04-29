//! Multi-user [`Workspace`] — a shared sandbox container with per-user isolation.
//!
//! A single `Workspace` holds one `tokimo-sandbox-init` container. Each user
//! gets an independent init-client connection + bash shell with isolated
//! `$TMPDIR`, cwd, and process lifecycle.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use tokimo_package_sandbox::{WorkspaceConfig, Workspace, UserConfig};
//!
//! let mut ws = Workspace::open(&WorkspaceConfig::new("/tmp/ws"))?;
//! ws.add_user(&UserConfig::new("alice"))?;
//! let out = ws.exec("alice", "echo hello", Duration::from_secs(10))?;
//! assert_eq!(out.stdout.trim(), "hello");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![cfg(any(target_os = "linux", target_os = "macos"))]

mod any_init;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use self::any_init::AnyInitClient;
use crate::config::{Mount, NetworkPolicy, ResourceLimits, SandboxConfig};
use crate::session::ExecOutput;
use crate::{Error, Result};

/// Platform-specific container state.
///
/// On Linux this is the bwrap child process + host control directory.
/// On macOS this is the persistent VM runner.
enum AnyContainer {
    #[cfg(target_os = "linux")]
    Linux {
        #[allow(dead_code)]
        spawned: crate::linux::SpawnedInit,
        host_sock: PathBuf,
    },
    #[cfg(target_os = "macos")]
    MacOs {
        #[allow(dead_code)]
        runner: crate::macos::vz_session::VzSessionRunner,
        client: Arc<crate::macos::vz_vsock::VsockInitClient>,
    },
}

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
    client: AnyInitClient,
    shell_id: String,
    timeout: Duration,
    /// Effective env of the user's shell, tracked by the host so we can pass
    /// it as `env_overlay` for exec/spawn. Updated after `export` commands.
    /// Wrapped in `RefCell` because `Workspace::exec` takes `&self`.
    env: RefCell<Vec<(String, String)>>,
}

/// A shared sandbox container hosting multiple isolated users.
pub struct Workspace {
    container: AnyContainer,
    users: HashMap<String, UserHandle>,
}

impl Workspace {
    /// Launch a shared sandbox container. No users are added yet —
    /// call [`Workspace::add_user`] for each.
    pub fn open(cfg: &WorkspaceConfig) -> Result<Self> {
        let sandbox_cfg = cfg.to_sandbox_config();
        let container = open_container(&sandbox_cfg)?;
        Ok(Self {
            container,
            users: HashMap::new(),
        })
    }

    /// Add a user. Connects a new init client, sends `AddUser`, and records
    /// the resulting shell `child_id`.
    pub fn add_user(&mut self, cfg: &UserConfig) -> Result<()> {
        let client = workspace_connect(&self.container)?;
        client.hello()?;

        let env_overlay: Vec<(String, String)> = cfg.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let cwd = cfg.cwd.as_ref().map(|p| p.to_string_lossy().into_owned());
        let info = client.add_user(&cfg.user_id, &env_overlay, cwd.as_deref())?;

        // Build the effective env that init sets for this user's shell.
        // Init sets: base_env + env_overlay, with TMPDIR and HOME overridden.
        let mut user_env: Vec<(String, String)> = env_overlay;
        user_env.retain(|(k, _)| k != "TMPDIR" && k != "HOME");
        user_env.push(("TMPDIR".into(), format!("/tmp/{}", cfg.user_id)));
        user_env.push(("HOME".into(), format!("/home/{}", cfg.user_id)));

        let handle = UserHandle {
            user_id: cfg.user_id.clone(),
            client,
            shell_id: info.child_id.clone(),
            timeout: cfg.exec_timeout,
            env: RefCell::new(user_env),
        };
        self.users.insert(cfg.user_id.clone(), handle);
        Ok(())
    }

    /// Remove a user: kills all their processes and disconnects their client.
    pub fn remove_user(&mut self, user_id: &str) -> Result<()> {
        if let Some(handle) = self.users.remove(user_id) {
            handle.client.remove_user(user_id)?;
            drop(handle);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }

    /// Execute a command in the user's bash environment. Uses cwd/env
    /// inheritance from the user's shell. On timeout, only the spawned
    /// child is killed — the user's bash and other users are unaffected.
    ///
    /// Env modifications via `export KEY=VALUE` are tracked on the host and
    /// passed as `env_overlay` to subsequent calls. This complements the
    /// init's `inherit_from_child` mechanism (which reads the frozen
    /// `/proc/<pid>/environ` snapshot).
    pub fn exec(&self, user_id: &str, cmd: &str, timeout: Duration) -> Result<ExecOutput> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        let env = user.env.borrow();
        let handle =
            user.client
                .spawn_pipes_inherit_async(&["/bin/bash", "-c", cmd], &env, None, Some(&user.shell_id))?;
        drop(env);
        let (stdout, stderr, code) = handle.wait_with_timeout(timeout)?;
        // Track env modifications from `export KEY=VALUE` so they carry over
        // to subsequent exec/spawn calls.
        if let Some(new_env) = Self::parse_export_cmd(cmd) {
            let mut env = user.env.borrow_mut();
            for (k, _) in &new_env {
                env.retain(|(ek, _)| ek != k);
            }
            env.extend(new_env);
        }
        Ok(ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
        })
    }

    /// Parse `export KEY=VALUE` from a command string.
    /// Returns `None` if no export is detected.
    fn parse_export_cmd(cmd: &str) -> Option<Vec<(String, String)>> {
        let cmd = cmd.trim();
        let rest = cmd.strip_prefix("export ")?;
        // Simple split on whitespace for the common `export KEY=VALUE` case.
        let mut env = Vec::new();
        for part in rest.split_whitespace() {
            if let Some(eq) = part.find('=') {
                let key = part[..eq].to_string();
                let mut val = part[eq + 1..].to_string();
                // Strip surrounding quotes if present.
                if val.len() >= 2 {
                    let first = val.as_bytes()[0];
                    let last = val.as_bytes()[val.len() - 1];
                    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                        val = val[1..val.len() - 1].to_string();
                    }
                }
                env.push((key, val));
            }
        }
        if env.is_empty() { None } else { Some(env) }
    }

    /// Execute a command using the user's default timeout.
    pub fn exec_default(&self, user_id: &str, cmd: &str) -> Result<ExecOutput> {
        let timeout = self
            .users
            .get(user_id)
            .map(|u| u.timeout)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        self.exec(user_id, cmd, timeout)
    }

    /// Spawn a background job in the user's environment. Returns the job's
    /// `child_id` for later tracking / kill.
    pub fn spawn(&self, user_id: &str, cmd: &str) -> Result<String> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        let env = user.env.borrow();
        let info = user
            .client
            .spawn_pipes_inherit(&["/bin/bash", "-c", cmd], &env, None, Some(&user.shell_id))?;
        Ok(info.child_id)
    }

    /// Re-create the user's bash shell after it died.
    pub fn respawn_shell(&mut self, user_id: &str) -> Result<()> {
        let handle = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        let info = handle.client.add_user(user_id, &[], None)?;
        let new_handle = UserHandle {
            user_id: handle.user_id.clone(),
            client: handle.client.clone_arc(),
            shell_id: info.child_id,
            timeout: handle.timeout,
            env: RefCell::new(handle.env.borrow().clone()),
        };
        self.users.insert(user_id.to_string(), new_handle);
        Ok(())
    }

    /// Dynamically bind-mount a path for a specific user.
    pub fn add_mount(&self, user_id: &str, source: &str, target: &str, read_only: bool) -> Result<()> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        user.client.bind_mount(source, target, read_only)
    }

    /// Unmount a previously bind-mounted path for a specific user.
    pub fn remove_mount(&self, user_id: &str, target: &str) -> Result<()> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        user.client.unmount(target)
    }

    /// Kill a specific child process by id.
    pub fn kill(&self, user_id: &str, child_id: &str) -> Result<()> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::exec(format!("user {user_id} not found")))?;
        user.client.signal(child_id, libc::SIGKILL, true)
    }

    /// Return the number of active users.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Shut down the entire container and all users.
    pub fn close(mut self) -> Result<()> {
        let user_ids: Vec<String> = self.users.keys().cloned().collect();
        for uid in &user_ids {
            let _ = self.remove_user(uid);
        }
        Ok(())
    }

    /// Get the shell `child_id` for a user.
    pub fn shell_id(&self, user_id: &str) -> Option<&str> {
        self.users.get(user_id).map(|h| h.shell_id.as_str())
    }
}

// ---------------------------------------------------------------------------
// Platform-specific container lifecycle
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn open_container(cfg: &SandboxConfig) -> Result<AnyContainer> {
    let mut spawned = crate::linux::spawn_init_workspace(cfg)?;
    let host_sock = spawned.host_control_dir.path().join("control.sock");

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

    Ok(AnyContainer::Linux { spawned, host_sock })
}

#[cfg(target_os = "macos")]
fn open_container(cfg: &SandboxConfig) -> Result<AnyContainer> {
    let runner = crate::macos::vz_session::boot_session_vm(cfg)?;
    let client = runner.client().clone();
    Ok(AnyContainer::MacOs { runner, client })
}

#[cfg(target_os = "linux")]
fn workspace_connect(container: &AnyContainer) -> Result<AnyInitClient> {
    match container {
        AnyContainer::Linux { host_sock, .. } => {
            let client = Arc::new(crate::linux::init_client::InitClient::connect(host_sock)?);
            Ok(AnyInitClient::Linux(client))
        }
        #[cfg(target_os = "macos")]
        _ => unreachable!(),
    }
}

#[cfg(target_os = "macos")]
fn workspace_connect(container: &AnyContainer) -> Result<AnyInitClient> {
    match container {
        AnyContainer::MacOs { client, .. } => Ok(AnyInitClient::MacOs(Arc::clone(client))),
        #[cfg(target_os = "linux")]
        _ => unreachable!(),
    }
}
