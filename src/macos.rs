//! macOS sandbox: generates a Seatbelt profile and invokes `sandbox-exec`.

#![cfg(target_os = "macos")]

use crate::common::{pipe_stdio, spawn_run};
use crate::config::{NetworkPolicy, SandboxConfig};
use crate::{Error, ExecutionResult, Result};

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn run(user_cmd: &[impl AsRef<str>], cfg: &SandboxConfig) -> Result<ExecutionResult> {
    if user_cmd.is_empty() {
        return Err(Error::validation("empty command"));
    }
    let work_dir = cfg
        .work_dir
        .canonicalize()
        .map_err(|e| Error::validation(format!("work_dir canonicalize: {}", e)))?;

    let profile_tmp = tempfile::tempdir()?;
    let profile_path = profile_tmp.path().join("tokimo-sandbox.sb");
    let profile = build_profile(&work_dir, cfg)?;
    fs::write(&profile_path, &profile)?;

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f").arg(&profile_path);
    for a in user_cmd {
        cmd.arg(a.as_ref());
    }

    // env: clear then apply user-provided
    cmd.env_clear();
    let mut saw_path = false;
    for (k, v) in &cfg.env {
        let lk = k.to_string_lossy().to_ascii_uppercase();
        if lk == "PATH" {
            saw_path = true;
        }
        cmd.env(k, v);
    }
    if !saw_path {
        cmd.env(
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        );
    }
    cmd.env("HOME", &work_dir);
    cmd.env("TMPDIR", &work_dir);
    cmd.env("SAFEBOX", "1");

    if let Some(c) = &cfg.cwd {
        cmd.current_dir(c);
    } else {
        cmd.current_dir(&work_dir);
    }
    pipe_stdio(&mut cmd);

    let limits = cfg.limits;
    unsafe {
        cmd.pre_exec(move || {
            crate::common::apply_rlimits(&limits);
            Ok(())
        });
    }

    let stdin_bytes = cfg.stdin.as_deref();
    let result = spawn_run(&mut cmd, stdin_bytes, &cfg.limits, cfg.stream_stderr)?;
    drop(profile_tmp);
    Ok(result)
}

fn build_profile(work_dir: &Path, cfg: &SandboxConfig) -> Result<String> {
    let work_s = work_dir.to_string_lossy();
    let mut p = String::new();
    p.push_str("(version 1)\n");
    p.push_str("; safebox macOS Seatbelt profile\n\n");

    // Default allow, then deny the dangerous stuff explicitly.
    p.push_str("(allow default)\n\n");

    // Block dangerous IPC / kernel ops.
    p.push_str("(deny mach-register)\n");
    p.push_str("(deny mach-priv-task-port)\n");
    p.push_str("(deny iokit-open)\n");
    p.push_str("(deny process-exec (regex #\"^/bin/su$\"))\n");
    p.push_str("(deny process-exec (regex #\"^/usr/bin/sudo$\"))\n\n");

    // File write: deny all, allow work_dir + macOS ephemerals.
    p.push_str("(deny file-write*)\n");
    p.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n",
        escape_sb(&work_s)
    ));
    p.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
    p.push_str("(allow file-write* (subpath \"/var/folders\"))\n");

    // User-requested rw mounts.
    for m in &cfg.extra_mounts {
        if !m.read_only {
            let s = m.host.to_string_lossy();
            p.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                escape_sb(&s)
            ));
        }
    }

    // Block reads of sensitive dotfiles regardless.
    p.push_str("\n(deny file-read* (subpath \"/etc\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.ssh\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.aws\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.gnupg\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.config\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.netrc\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/Library/Keychains\"))\n");

    // Network policy.
    match cfg.network {
        NetworkPolicy::Blocked => {
            p.push_str("\n(deny network*)\n");
        }
        NetworkPolicy::AllowAll => {}
    }

    Ok(p)
}

fn escape_sb(s: &str) -> String {
    // Seatbelt literal strings: escape backslashes and quotes.
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
