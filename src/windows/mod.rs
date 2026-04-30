//! Windows sandbox: SYSTEM service via named pipe.
//!
//! All VM operations are delegated to `tokimo-sandbox-svc.exe`, a Windows
//! service running as `localSystem`. The recommended way to install it is
//! the MSIX in `packaging/windows/`, which registers the service via
//! `desktop6:Service` (no UAC). For local development the legacy
//! `--install` / `--console` flags still work.
//!
//! ## Network policy
//!
//! Windows currently only supports two policies:
//!   * `NetworkPolicy::Blocked` — no NIC is attached to the VM.
//!   * `NetworkPolicy::AllowAll` — default Hyper-V NAT NIC.
//!
//! `Observed` and `Gated` policies are Linux/macOS only; on Windows they
//! are rejected at config validation time so callers don't get silent
//! downgrades.

mod client;
mod init_client;
pub(crate) mod ov_pipe;
pub mod protocol;
pub(crate) mod safe_path;
mod session;

use crate::{Error, ExecutionResult, NetworkPolicy, Result};

use std::path::PathBuf;

const DEFAULT_MEMORY_MB: u64 = 2048;
const DEFAULT_CPUS: usize = 2;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) fn run<S: AsRef<str>>(cmd: &[S], cfg: &crate::config::SandboxConfig) -> Result<ExecutionResult> {
    if cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }

    let network = translate_network(&cfg.network)?;

    let kernel = find_kernel()?;
    let initrd = find_initrd()?;
    let rootfs_dir = find_rootfs_vhdx()?;
    let workspace = ensure_workspace(cfg)?;

    // Write stdin buffer to the workspace so the guest can read it.
    // The init script (in the rootfs initrd) picks up `.vz_stdin` and pipes
    // it into the chrooted command.
    if let Some(ref stdin_data) = cfg.stdin {
        let stdin_path = workspace.join(".vz_stdin");
        std::fs::write(&stdin_path, stdin_data).map_err(|e| Error::exec(format!("write stdin file: {e}")))?;
    }

    // Build a self-contained shell one-liner that handles cwd, env, and the
    // actual command. Stdin redirection is handled by init.sh outside the
    // chroot so we don't have to worry about path mapping here.
    let mut shell_cmd = String::new();

    if let Some(ref cwd) = cfg.cwd {
        shell_cmd.push_str(&format!("cd {} && ", shell_escape(&cwd.to_string_lossy())));
    }
    for (k, v) in &cfg.env {
        shell_cmd.push_str(&format!(
            "export {}={} && ",
            k.to_string_lossy(),
            shell_escape(&v.to_string_lossy())
        ));
    }
    shell_cmd.push_str(
        &cmd.iter()
            .map(|s| shell_escape(s.as_ref()))
            .collect::<Vec<_>>()
            .join(" "),
    );

    use base64::Engine;
    let cmd_b64 = base64::engine::general_purpose::STANDARD.encode(shell_cmd.as_bytes());

    let memory_mb: u64 = std::env::var("TOKIMO_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MB);
    let cpu_count: usize = std::env::var("TOKIMO_CPUS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CPUS);

    client::exec_vm(
        &kernel,
        &initrd,
        &rootfs_dir,
        &workspace,
        &cmd_b64,
        memory_mb,
        cpu_count,
        network,
    )
}

pub(crate) fn spawn_session_shell(cfg: &crate::config::SandboxConfig) -> Result<crate::session::ShellHandle> {
    session::spawn_session_shell(cfg)
}

pub(crate) fn run_without_sandbox<S: AsRef<str>>(
    cmd: &[S],
    cfg: &crate::config::SandboxConfig,
) -> Result<ExecutionResult> {
    use std::process::{Command, Stdio};

    if cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }

    let mut c = Command::new(cmd[0].as_ref());
    for a in &cmd[1..] {
        c.arg(a.as_ref());
    }

    c.stdin(Stdio::piped());
    c.stdout(Stdio::piped());
    c.stderr(if cfg.stream_stderr {
        Stdio::inherit()
    } else {
        Stdio::piped()
    });

    for (k, v) in &cfg.env {
        c.env(k, v);
    }

    if let Some(cwd) = &cfg.cwd {
        c.current_dir(cwd);
    } else {
        c.current_dir(&cfg.work_dir);
    }

    let mut child = c.spawn().map_err(|e| Error::exec(format!("spawn failed: {e}")))?;

    // Write stdin on a separate thread so we can read stdout/stderr concurrently.
    if let Some(ref stdin_data) = cfg.stdin {
        let mut stdin = child.stdin.take().unwrap();
        let data = stdin_data.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(&data);
        });
    } else {
        drop(child.stdin.take());
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::exec(format!("wait failed: {e}")))?;

    Ok(ExecutionResult {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
        timed_out: false,
        oom_killed: false,
    })
}

// ---------------------------------------------------------------------------
// NetworkPolicy translation
// ---------------------------------------------------------------------------

fn translate_network(p: &NetworkPolicy) -> Result<protocol::SvcNetwork> {
    match p {
        NetworkPolicy::Blocked => Ok(protocol::SvcNetwork::Blocked),
        NetworkPolicy::AllowAll => Ok(protocol::SvcNetwork::AllowAll),
        NetworkPolicy::Observed { .. } | NetworkPolicy::Gated { .. } => Err(Error::validation(
            "NetworkPolicy::Observed / Gated are not implemented on Windows. \
             Use Blocked or AllowAll. \
             See docs/network-observability.md for the roadmap.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Shell escaping
// ---------------------------------------------------------------------------

fn shell_escape(s: &str) -> String {
    if s.contains('\'') || s.contains('\\') || s.contains('"') || s.contains('$') || s.contains(' ') {
        let escaped = s.replace('\'', "'\\''");
        format!("'{}'", escaped)
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------
//
// VM artifacts live under `<repo>/vm/`:
//   * `vm/vmlinuz`    — Linux kernel
//   * `vm/initrd.img` — initramfs (busybox + Hyper-V modules + tokimo-sandbox-init)
//   * `vm/rootfs.vhdx` — ext4 VHDX rootfs
//
// Both are produced by the tokimo-package-rootfs CI:
//   https://github.com/tokimo-lab/tokimo-package-rootfs/releases
//
// Use `scripts/fetch-vm.ps1` to download them into `vm/`.
//
// Resolution order — find first directory containing all three files:
//   1. `<exe>/vm/`
//   2. walking up from `<exe>` looking for `vm/`
//   3. walking up from `cwd` looking for `vm/`
// All three must exist together; we reject partial directories so a stray
// `vm/` folder elsewhere in the tree won't be picked up by mistake.

const VM_DIR_NAME: &str = "vm";
const KERNEL_FILE: &str = "vmlinuz";
const INITRD_FILE: &str = "initrd.img";
const ROOTFS_FILE: &str = "rootfs.vhdx";

fn vm_dir_complete(d: &std::path::Path) -> bool {
    d.join(KERNEL_FILE).is_file() && d.join(INITRD_FILE).is_file() && d.join(ROOTFS_FILE).is_file()
}

fn find_vm_dir() -> Result<PathBuf> {
    let mut tried: Vec<PathBuf> = Vec::new();

    let mut probe = |p: PathBuf| -> Option<PathBuf> {
        if vm_dir_complete(&p) {
            Some(p)
        } else {
            tried.push(p);
            None
        }
    };

    // Highest priority: explicit override. Lets CI/dev environments
    // point at a pre-fetched VM artifact directory without polluting
    // the cwd or the service exe parent.
    if let Ok(env_dir) = std::env::var("TOKIMO_VM_DIR")
        && !env_dir.is_empty()
        && let Some(hit) = probe(PathBuf::from(&env_dir))
    {
        return Ok(hit);
    }

    // Next: a project-local `<cwd>/.data/vm/` directory. Convention used
    // by `scripts/fetch-vm.ps1` so caller code can stash artifacts under
    // a single hidden folder per repo without configuration.
    if let Ok(cwd) = std::env::current_dir()
        && let Some(hit) = probe(cwd.join(".data").join(VM_DIR_NAME))
    {
        return Ok(hit);
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        if let Some(hit) = probe(dir.join(VM_DIR_NAME)) {
            return Ok(hit);
        }
        let mut cur = Some(dir);
        while let Some(d) = cur {
            if let Some(hit) = probe(d.join(VM_DIR_NAME)) {
                return Ok(hit);
            }
            cur = d.parent();
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let mut cur: Option<&std::path::Path> = Some(&cwd);
        while let Some(d) = cur {
            if let Some(hit) = probe(d.join(VM_DIR_NAME)) {
                return Ok(hit);
            }
            cur = d.parent();
        }
    }

    let probed = tried
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join("\n  ");
    Err(Error::validation(format!(
        "VM artifacts not found. Expected `{KERNEL_FILE}`, `{INITRD_FILE}`, `{ROOTFS_FILE}` \
         in a `{VM_DIR_NAME}/` directory. Run `scripts/fetch-vm.ps1` to download them. \
         Set $TOKIMO_VM_DIR to override.\n\
         Tried:\n  {probed}"
    )))
}

pub(crate) fn find_kernel() -> Result<PathBuf> {
    Ok(find_vm_dir()?.join(KERNEL_FILE))
}

pub(crate) fn find_initrd() -> Result<PathBuf> {
    Ok(find_vm_dir()?.join(INITRD_FILE))
}

pub(crate) fn find_rootfs_vhdx() -> Result<PathBuf> {
    Ok(find_vm_dir()?.join(ROOTFS_FILE))
}

pub(crate) fn ensure_workspace(cfg: &crate::config::SandboxConfig) -> Result<PathBuf> {
    let work = cfg.work_dir.clone();
    if !work.exists() {
        std::fs::create_dir_all(&work).map_err(|e| Error::exec(format!("create work dir: {e}")))?;
    }
    Ok(work)
}
