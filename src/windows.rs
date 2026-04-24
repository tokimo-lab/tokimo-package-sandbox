//! Windows sandbox: re-executes the command inside WSL2 under bubblewrap.
//!
//! Strategy:
//!   1. If `wsl` is available and `bwrap` is installed inside WSL, run the
//!      command inside WSL under a bwrap sandbox that mirrors the Linux driver.
//!   2. Otherwise fail by default. The caller may opt in to "WSL only, no
//!      bwrap" via `SandboxConfig::network(AllowAll)` + `SAFEBOX_WSL_NO_BWRAP=1`
//!      env var — this still isolates from the Windows host but offers no FS
//!      sandbox within WSL.
//!   3. If WSL itself is unavailable, we refuse execution.

#![cfg(target_os = "windows")]

use crate::config::{NetworkPolicy, SandboxConfig};
use crate::{Error, ExecutionResult, Result};

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn hide(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

pub(crate) fn run(user_cmd: &[impl AsRef<str>], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    if user_cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }
    let inner = build_inner_script(cfg, Some(user_cmd))?;
    let mut wsl = Command::new("wsl");
    hide(&mut wsl);
    wsl.args(["-e", "bash", "-lc", &inner])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = wsl
        .spawn()
        .map_err(|e| Error::exec(format!("spawn wsl failed: {}", e)))?;

    if let Some(bytes) = cfg.stdin.as_deref() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(bytes);
        }
    }

    // Simple timeout on Windows (no pre_exec available).
    let timeout = Duration::from_secs(cfg.limits.timeout_secs);
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(Error::exec(format!("wait failed: {}", e))),
        }
    }

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(ref mut o) = child.stdout {
        let _ = o.read_to_string(&mut stdout);
    }
    if let Some(ref mut e) = child.stderr {
        let _ = e.read_to_string(&mut stderr);
    }
    let exit_code = child
        .wait()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(-1);

    Ok(ExecutionResult {
        stdout,
        stderr: if timed_out {
            format!("sandbox: timeout after {}s\n{}", cfg.limits.timeout_secs, stderr)
        } else {
            stderr
        },
        exit_code: if timed_out { -1 } else { exit_code },
        timed_out,
        oom_killed: false,
    })
}

fn wsl_available() -> bool {
    let mut c = Command::new("wsl");
    hide(&mut c);
    c.arg("--status")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn wsl_has_bwrap() -> bool {
    let mut c = Command::new("wsl");
    hide(&mut c);
    c.args(["-e", "which", "bwrap"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn windows_to_wsl_path(p: &Path) -> Option<String> {
    let s = p.to_string_lossy().to_string();
    if s.starts_with("\\\\") {
        return None;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() >= 2 && chars[1] == ':' {
        let drive = chars[0].to_ascii_lowercase();
        let rest = s[2..].replace('\\', "/");
        return Some(format!("/mnt/{}{}", drive, rest));
    }
    Some(s.replace('\\', "/"))
}

fn shell_quote(s: &str) -> String {
    // POSIX single-quote. To embed a literal ' we close quote, escape, reopen.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Build the bash -lc script that re-execs the user command (or, if `user_cmd`
/// is None, an interactive bash) inside WSL under bwrap.
fn build_inner_script(
    cfg: &SandboxConfig,
    user_cmd: Option<&[impl AsRef<str>]>,
) -> Result<String> {
    if !wsl_available() {
        return Err(Error::ToolNotFound(
            "WSL is not available. Install WSL2 (`wsl --install`). tokimo-package-sandbox on Windows requires WSL2 for real isolation.".into(),
        ));
    }
    let bwrap_inside = wsl_has_bwrap();
    if !bwrap_inside && std::env::var("SAFEBOX_WSL_NO_BWRAP").ok().as_deref() != Some("1") {
        return Err(Error::ToolNotFound(
            "bubblewrap is not installed inside WSL. Run `wsl -e sudo apt install -y bubblewrap`, or set SAFEBOX_WSL_NO_BWRAP=1 to use WSL-only isolation.".into(),
        ));
    }

    let work_dir_wsl = windows_to_wsl_path(&cfg.work_dir)
        .ok_or_else(|| Error::validation("bad work_dir path"))?;

    let mut inner = String::new();
    if bwrap_inside {
        inner.push_str("exec bwrap --unshare-all --die-with-parent");
        for p in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
            inner.push_str(&format!(" --ro-bind {} {}", p, p));
        }
        for p in [
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/ssl/certs",
        ] {
            inner.push_str(&format!(" --ro-bind-try {} {}", p, p));
        }
        inner.push_str(" --dir /home --dir /root");
        inner.push_str(&format!(" --bind {} /tmp", shell_quote(&work_dir_wsl)));
        inner.push_str(" --dev /dev --proc /proc");
        for m in &cfg.extra_mounts {
            let src = windows_to_wsl_path(&m.host)
                .ok_or_else(|| Error::validation(format!("bad mount {}", m.host.display())))?;
            let dst = m
                .guest
                .as_ref()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|| src.clone());
            let flag = if m.read_only { "--ro-bind" } else { "--bind" };
            inner.push_str(&format!(" {} {} {}", flag, shell_quote(&src), shell_quote(&dst)));
        }
        match cfg.network {
            NetworkPolicy::Blocked => inner.push_str(" --unshare-net"),
            NetworkPolicy::AllowAll => inner.push_str(" --share-net"),
        }
        inner.push_str(" --clearenv");
        inner.push_str(" --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        inner.push_str(" --setenv HOME /tmp --setenv TMPDIR /tmp --setenv SAFEBOX 1");
        for (k, v) in &cfg.env {
            inner.push_str(&format!(
                " --setenv {} {}",
                shell_quote(&k.to_string_lossy()),
                shell_quote(&v.to_string_lossy())
            ));
        }
        let cwd = cfg
            .cwd
            .as_ref()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| "/tmp".to_string());
        inner.push_str(&format!(" --chdir {}", shell_quote(&cwd)));
        inner.push_str(" --");
    } else {
        inner.push_str(&format!("cd {} && ", shell_quote(&work_dir_wsl)));
        inner.push_str("exec");
    }

    match user_cmd {
        Some(argv) => {
            for a in argv {
                inner.push(' ');
                inner.push_str(&shell_quote(a.as_ref()));
            }
        }
        None => {
            inner.push_str(" /bin/bash --noprofile --norc");
        }
    }
    Ok(inner)
}

pub(crate) fn spawn_session_shell(
    cfg: &SandboxConfig,
) -> Result<(std::process::Child, Box<dyn std::any::Any + Send>)> {
    let inner = build_inner_script::<&str>(cfg, None)?;
    let mut wsl = Command::new("wsl");
    hide(&mut wsl);
    wsl.args(["-e", "bash", "-lc", &inner])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = wsl
        .spawn()
        .map_err(|e| Error::exec(format!("spawn wsl session shell failed: {}", e)))?;
    Ok((child, Box::new(()) as Box<dyn std::any::Any + Send>))
}
