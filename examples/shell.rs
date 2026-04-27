//! Interactive shell inside the sandbox — equivalent of `docker run -it ... bash`.
//!
//! Usage:   cargo run --example shell
//!
//! Type commands, explore the sandboxed filesystem. Exit with `exit` or Ctrl-D.
//! Anything you do (rm -rf /, curl, whatever) cannot affect the host.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use tokimo_package_sandbox::{NetworkPolicy, ResourceLimits, SandboxConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Persist the work dir across restarts by using a fixed path.
    let work = std::env::var("SAFEBOX_WORK")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tps-shell"));
    std::fs::create_dir_all(&work)?;

    let cfg = SandboxConfig::new(&work)
        .network(NetworkPolicy::Blocked)
        .limits(ResourceLimits {
            max_memory_mb: 2048,
            timeout_secs: 86_400,
            max_file_size_mb: 512,
            max_processes: 4096,
        });

    println!("safebox shell");
    println!("  work dir (host): {}", work.display());
    println!("  inside sandbox this is /tmp, HOME=/tmp");
    println!("  type `exit` or Ctrl-D to leave\n");

    // For a true TTY we bypass `tokimo_package_sandbox::run` (which captures stdout/stderr)
    // and invoke bwrap directly inheriting our stdio.
    exec_interactive_bwrap(&work, &cfg)
}

fn exec_interactive_bwrap(work: &Path, cfg: &SandboxConfig) -> Result<(), Box<dyn std::error::Error>> {
    let work = work.canonicalize()?;
    let mut cmd = Command::new("bwrap");
    cmd.args(["--unshare-all", "--die-with-parent"]);
    for p in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
        if Path::new(p).exists() {
            cmd.args(["--ro-bind", p, p]);
        }
    }
    for etc in [
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/ssl/certs",
        "/etc/ca-certificates.conf",
        "/etc/alternatives",
        "/etc/terminfo",
    ] {
        if Path::new(etc).exists() {
            cmd.args(["--ro-bind", etc, etc]);
        }
    }
    cmd.args(["--dir", "/home", "--dir", "/root"]);
    cmd.args(["--bind", &work.to_string_lossy(), "/tmp"]);
    cmd.args(["--dev", "/dev"]);
    let in_container = Path::new("/.dockerenv").exists();
    if in_container {
        cmd.args(["--dir", "/proc"]);
    } else {
        cmd.args(["--proc", "/proc"]);
    }
    match cfg.network {
        NetworkPolicy::Blocked => {
            cmd.args(["--unshare-net"]);
        }
        NetworkPolicy::AllowAll => {
            cmd.args(["--share-net"]);
        }
        _ => {
            cmd.args(["--share-net"]);
        }
    }
    cmd.args(["--clearenv"]);
    cmd.args([
        "--setenv",
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ]);
    cmd.args(["--setenv", "HOME", "/tmp"]);
    cmd.args(["--setenv", "TMPDIR", "/tmp"]);
    cmd.args(["--setenv", "SAFEBOX", "1"]);
    cmd.args(["--setenv", "PS1", "(tps) \\w $ "]);
    if let Ok(term) = std::env::var("TERM") {
        cmd.args(["--setenv", "TERM", &term]);
    }
    cmd.args(["--chdir", "/tmp"]);
    cmd.args(["--", "/bin/bash", "--norc", "-i"]);

    // Inherit stdio so the shell is really interactive.
    let err = cmd.exec();
    Err(Box::new(err))
}
