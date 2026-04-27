//! Interactive shell inside the sandbox — equivalent of `docker run -it ... bash`.
//!
//! Usage:   cargo run --example shell
//!
//! Linux   → bubblewrap (bwrap) container with PID/user namespace
//! macOS   → sandbox-exec + Seatbelt profile
//!
//! Type commands, explore the sandboxed filesystem. Exit with `exit` or Ctrl-D.

#[cfg(unix)]
use std::path::{Path, PathBuf};

/// Pick a persistent work dir so files survive across restarts.
#[cfg(unix)]
fn work_dir() -> PathBuf {
    std::env::var("SAFEBOX_WORK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tps-shell"))
}

// ---------------------------------------------------------------------------
// Linux: bubblewrap
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

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
    cmd.args(["--", "/bin/bash", "--noprofile", "--norc", "-i"]);

    let err = cmd.exec();
    Err(Box::new(err))
}

// ---------------------------------------------------------------------------
// macOS: sandbox-exec + Seatbelt
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let work = work_dir();
    fs::create_dir_all(&work)?;
    let work = work.canonicalize()?;

    println!("safebox shell  (macOS / Seatbelt)");
    println!("  work dir (host): {}", work.display());
    println!("  HOME={}", work.display());
    println!("  type `exit` or Ctrl-D to leave\n");

    // Build Seatbelt profile for interactive use.
    let profile = build_interactive_profile(&work);

    // Write profile to a temp file. We'll exec() so the file is left behind;
    // /tmp cleans itself on reboot.
    let profile_path = std::env::temp_dir().join("tps-shell-profile.sb");
    let mut f = fs::File::create(&profile_path)?;
    f.write_all(profile.as_bytes())?;
    f.flush()?;

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f").arg(&profile_path);
    cmd.arg("/bin/bash");
    cmd.arg("--noprofile");
    cmd.arg("--norc");
    cmd.arg("-i");

    cmd.env_clear();
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin");
    cmd.env("HOME", work.to_str().unwrap_or("/tmp"));
    cmd.env("TMPDIR", work.to_str().unwrap_or("/tmp"));
    cmd.env("SAFEBOX", "1");
    cmd.env("PS1", "(tps) \\w $ ");
    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", &term);
    }
    if let Ok(lang) = std::env::var("LANG") {
        cmd.env("LANG", &lang);
    }

    let err = cmd.exec();
    Err(Box::new(err))
}

#[cfg(target_os = "macos")]
fn build_interactive_profile(work_dir: &Path) -> String {
    let work_s = work_dir.to_string_lossy();
    let mut p = String::new();

    p.push_str("(version 1)\n");
    p.push_str("; safebox interactive shell — Seatbelt profile\n\n");

    // Default allow, then deny dangerous stuff.
    p.push_str("(allow default)\n\n");

    // Block dangerous IPC / kernel ops.
    p.push_str("(deny mach-register)\n");
    p.push_str("(deny mach-priv-task-port)\n");
    p.push_str("(deny iokit-open)\n");
    p.push_str("(deny process-exec (regex #\"^/bin/su$\"))\n");
    p.push_str("(deny process-exec (regex #\"^/usr/bin/sudo$\"))\n\n");

    // File write: deny all, allow work_dir + macOS ephemerals.
    p.push_str("(deny file-write*)\n");
    p.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", escape_sb(&work_s)));
    p.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
    p.push_str("(allow file-write* (subpath \"/var/folders\"))\n");
    // Allow writing to /dev/pts/* for terminal interaction.
    p.push_str("(allow file-write* (subpath \"/dev\"))\n\n");

    // Block reads of sensitive dotfiles.
    p.push_str("(deny file-read* (subpath \"/etc\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.ssh\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.aws\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.gnupg\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.config\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/\\.netrc\"))\n");
    p.push_str("(deny file-read* (regex #\"^/Users/[^/]+/Library/Keychains\"))\n\n");

    // Block network.
    p.push_str("(deny network*)\n");

    p
}

#[cfg(target_os = "macos")]
fn escape_sb(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("safebox shell: unsupported platform");
    std::process::exit(1);
}
