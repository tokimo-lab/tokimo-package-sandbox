//! Interactive shell inside the sandbox — equivalent of `docker run -it ... bash`.
//!
//! Usage:   cargo run --example shell
//!
//! Linux   → bubblewrap (bwrap) container with PID/user namespace
//! macOS   → Virtualization.framework (interactive shell pending)
//!
//! Type commands, explore the sandboxed filesystem. Exit with `exit` or Ctrl-D.

// ---------------------------------------------------------------------------
// Linux: bubblewrap
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn work_dir() -> PathBuf {
        std::env::var("SAFEBOX_WORK")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("tps-shell"))
    }

    let work = work_dir();
    std::fs::create_dir_all(&work)?;
    let work = work.canonicalize()?;

    println!("safebox shell  (Linux / bwrap)");
    println!("  work dir (host): {}", work.display());
    println!("  inside sandbox: /tmp, HOME=/tmp");
    println!("  type `exit` or Ctrl-D to leave\n");

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

    cmd.args(["--unshare-net"]); // blocked by default
    cmd.args(["--clearenv"]);
    cmd.args([
        "--setenv", "PATH",
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
    cmd.args(["--", "/bin/bash", "--noprofile", "--norc", "-i"]);

    let err = cmd.exec();
    Err(Box::new(err))
}

// ---------------------------------------------------------------------------
// macOS: Virtualization.framework (interactive shell not yet supported)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn main() {
    eprintln!("safebox shell: interactive shell is not yet supported on macOS.");
    eprintln!("The macOS backend uses Virtualization.framework — interactive sessions");
    eprintln!("require tokimo-sandbox-init with VSOCK support (pending).");
    eprintln!();
    eprintln!("For one-shot commands, use `cargo run --example vz_smoke`.");
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("safebox shell: unsupported platform");
    std::process::exit(1);
}
