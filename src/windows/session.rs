//! Windows-side persistent sandbox session — boots a long-lived HCS Hyper-V
//! micro-VM through `tokimo-sandbox-svc`, opens a bash shell inside it via
//! the init control protocol (tunneled over COM1 + named pipe), and exposes
//! the standard cross-platform [`ShellHandle`] used by [`Session`].
//!
//! ```text
//! Session::open(cfg)
//!   ├─ client::open_session()  ──▶  service boots VM in session mode
//!   │                                   │
//!   │     named pipe tunnel ◀────────── COM1 (raw bytes, init protocol)
//!   │                                   │
//!   ├─ WinInitClient::new(pipe)         ▼
//!   ├─ client.hello()                init binary (PID 1 in guest)
//!   ├─ client.open_shell(bash)
//!   ├─ ShellHandle:
//!   │     stdin = InitStdin (Op::Write)
//!   │     stdout/stderr = InitReader (drains Shared.children[id])
//!   │     keepalive = (client, pipe-via-client)
//! ```
//!
//! [`Session`]: crate::session::Session
//! [`ShellHandle`]: crate::session::ShellHandle

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::config::SandboxConfig;
use crate::session::{JobOutput, ShellHandle};
use crate::{Error, NetworkPolicy, Result};

use super::client;
use super::init_client::{InitReader, InitStdin, InitStream, SpawnInfo, WinInitClient};

const DEFAULT_MEMORY_MB: u64 = 2048;
const DEFAULT_CPUS: usize = 2;

pub(crate) fn spawn_session_shell(cfg: &SandboxConfig) -> Result<ShellHandle> {
    // Translate / validate network policy first.
    let network = match cfg.network {
        NetworkPolicy::Blocked => super::protocol::SvcNetwork::Blocked,
        NetworkPolicy::AllowAll => super::protocol::SvcNetwork::AllowAll,
        _ => {
            return Err(Error::validation(
                "NetworkPolicy::Observed / Gated are not implemented on Windows. Use Blocked or AllowAll.",
            ));
        }
    };

    let kernel = super::find_kernel()?;
    let initrd = super::find_initrd()?;
    let rootfs_template = super::find_rootfs_vhdx()?;
    let workspace = super::ensure_workspace(cfg)?;

    let memory_mb: u64 = std::env::var("TOKIMO_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MB);
    let cpu_count: usize = std::env::var("TOKIMO_CPUS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CPUS);

    // Build the V2 RootfsSpec from the caller's persistent_rootfs choice.
    let rootfs = match &cfg.persistent_rootfs {
        Some(target) => super::protocol::RootfsSpec::Persistent {
            template: rootfs_template.to_string_lossy().into_owned(),
            target: target.to_string_lossy().into_owned(),
        },
        None => super::protocol::RootfsSpec::Ephemeral {
            template: rootfs_template.to_string_lossy().into_owned(),
        },
    };

    // Build the V2 shares list. Slot 0 is always the workspace mounted RW
    // at /mnt/work. Subsequent slots come from cfg.extra_mounts in order.
    let mut shares: Vec<super::protocol::ShareSpec> = Vec::with_capacity(1 + cfg.extra_mounts.len());
    shares.push(super::protocol::ShareSpec {
        host_path: workspace.to_string_lossy().into_owned(),
        guest_path: "/mnt/work".into(),
        read_only: false,
        name: "s0".into(),
    });
    for (i, m) in cfg.extra_mounts.iter().enumerate() {
        let guest = m
            .guest
            .clone()
            .unwrap_or_else(|| m.host.clone())
            .to_string_lossy()
            .into_owned();
        shares.push(super::protocol::ShareSpec {
            host_path: m.host.to_string_lossy().into_owned(),
            guest_path: guest,
            read_only: m.read_only,
            // Plan9 share names are limited to a short alnum identifier; the
            // protocol's `aname` is what the guest mounts so the meaningful
            // identifier is in `guest_path`. A simple `s<N>` is sufficient.
            name: format!("s{}", i + 1),
        });
    }

    // Open service-side session — returns the named pipe that's now a
    // raw byte tunnel to the guest's init HvSocket service, plus the
    // per-share vsock ports the guest will dial.
    let (pipe, _init_port, share_ports) =
        client::open_session(&kernel, &initrd, rootfs, shares.clone(), memory_mb, cpu_count, network)?;

    if share_ports.len() != shares.len() {
        return Err(Error::exec(format!(
            "service returned {} share ports for {} shares",
            share_ports.len(),
            shares.len()
        )));
    }

    let init = WinInitClient::new(pipe)?;
    init.hello()?;

    // Tell the guest to dial each share's vsock port and 9p-mount it.
    let mount_entries: Vec<crate::protocol::types::MountEntry> = shares
        .iter()
        .zip(share_ports.iter())
        .map(|(s, port)| crate::protocol::types::MountEntry {
            vsock_port: *port,
            guest_path: s.guest_path.clone(),
            aname: s.name.clone(),
            read_only: s.read_only,
        })
        .collect();
    init.send_mount_manifest(mount_entries)?;

    // Build the env overlay.
    let mut env_overlay: Vec<(String, String)> = Vec::new();
    for (k, v) in &cfg.env {
        env_overlay.push((k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()));
    }

    let info: SpawnInfo = init.open_shell(&["/bin/bash", "--noprofile", "--norc"], &env_overlay, Some("/mnt/work"))?;
    let child_id = info.child_id;

    // Build ShellHandle.
    let stdin: Box<dyn std::io::Write + Send> = Box::new(InitStdin {
        client: init.clone(),
        child_id: child_id.clone(),
        closed: false,
    });
    let stdout: Box<dyn std::io::Read + Send> =
        Box::new(InitReader::new(init.clone(), child_id.clone(), InitStream::Stdout));
    let stderr: Box<dyn std::io::Read + Send> =
        Box::new(InitReader::new(init.clone(), child_id.clone(), InitStream::Stderr));

    // try_wait: shell child exited?
    let tw_client = init.clone();
    let tw_cid = child_id.clone();
    let try_wait = Box::new(move || -> bool { tw_client.is_dead() || tw_client.child_exited(&tw_cid) });

    // kill: SIGKILL the shell.
    let kill_client = init.clone();
    let kill_cid = child_id.clone();
    let kill = Box::new(move || {
        let _ = kill_client.signal(&kill_cid, 9, true);
    });

    // run_oneshot: reuse init's pipes-mode children.
    let oneshot_client = init.clone();
    let run_oneshot: crate::session::RunOneshotFn = Box::new(
        move |cmd: &str, timeout: Duration| -> Result<crate::session::ExecOutput> {
            let (out, err, code) =
                oneshot_client.run_oneshot(&["/bin/bash", "-c", cmd], &[], Some("/mnt/work"), timeout)?;
            Ok(crate::session::ExecOutput {
                stdout: String::from_utf8_lossy(&out).into_owned(),
                stderr: String::from_utf8_lossy(&err).into_owned(),
                exit_code: code,
            })
        },
    );

    // spawn_async: like macOS — backgrounded child that inherits cwd/env from the shell.
    let spawn_client = init.clone();
    let spawn_shell_cid = child_id.clone();
    let spawn_async: crate::session::SpawnAsyncFn = Box::new(move |_job_id: u64, cmd: &str| {
        let info = spawn_client.spawn_pipes_inherit(&["/bin/bash", "-c", cmd], &[], None, Some(&spawn_shell_cid))?;
        Ok(Box::new(WinJobOutput {
            client: spawn_client.clone(),
            child_id: info.child_id,
        }) as Box<dyn JobOutput>)
    });

    let keepalive: Box<dyn std::any::Any + Send> = Box::new(SessionKeepalive {
        _client: init,
        _workspace: workspace,
    });

    Ok(ShellHandle {
        stdin,
        stdout,
        stderr,
        try_wait,
        kill,
        keepalive,
        open_pty: None,
        run_oneshot: Some(Arc::new(run_oneshot)),
        spawn_async: Some(Arc::new(spawn_async)),
        shell_exit_code: Box::new(|| None),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct SessionKeepalive {
    _client: WinInitClient,
    _workspace: PathBuf,
}

impl Drop for SessionKeepalive {
    fn drop(&mut self) {
        // Best-effort: ask init to shut down. The reader thread will see
        // EOF when the service tears down the VM; the pipe HANDLE inside
        // `_client.inner.write` is then closed when this struct drops.
        let _ = self._client.shutdown();
    }
}

struct WinJobOutput {
    client: WinInitClient,
    child_id: String,
}

impl JobOutput for WinJobOutput {
    fn wait_with_timeout(&self, timeout: Duration) -> Result<crate::session::ExecOutput> {
        use std::time::Instant;
        let deadline = Instant::now() + timeout;
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let mut code: Option<i32> = None;
        let mut timed_out = false;

        loop {
            for c in self.client.drain_stdout(&self.child_id) {
                stdout.extend_from_slice(&c);
            }
            for c in self.client.drain_stderr(&self.child_id) {
                stderr.extend_from_slice(&c);
            }
            if let Some((c, _)) = self.client.take_exit(&self.child_id) {
                code = Some(c);
                break;
            }
            if self.client.is_dead() {
                code = Some(-1);
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                timed_out = true;
                let _ = self.client.signal(&self.child_id, 9, true);
                let drain_deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < drain_deadline {
                    self.client.wait_for_event(&self.child_id, drain_deadline);
                    for c in self.client.drain_stdout(&self.child_id) {
                        stdout.extend_from_slice(&c);
                    }
                    for c in self.client.drain_stderr(&self.child_id) {
                        stderr.extend_from_slice(&c);
                    }
                    if let Some((c, _)) = self.client.take_exit(&self.child_id) {
                        code = Some(c);
                        break;
                    }
                }
                break;
            }
            self.client.wait_for_event(&self.child_id, deadline);
        }
        let _ = self.client.close_child(&self.child_id);
        Ok(crate::session::ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: if timed_out { 124 } else { code.unwrap_or(-1) },
        })
    }
}
