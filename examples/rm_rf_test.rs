//! Proves the sandbox protects the host: creates a canary file in $HOME and in
//! /tmp, then runs `rm -rf` targeting both host paths from inside the sandbox.
//! The canaries on the host should survive.

use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let canary_home = PathBuf::from(&home).join("tps-canary-DO-NOT-DELETE.txt");
    let canary_tmp_host = PathBuf::from("/tmp").join("tps-canary-host.txt");

    fs::write(&canary_home, b"host canary - should survive\n")?;
    fs::write(&canary_tmp_host, b"host /tmp canary - should survive\n")?;

    let work = tempfile::tempdir()?;
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);

    // Inside the sandbox, /tmp is the sandbox's work_dir, NOT the host's /tmp.
    // And $HOME inside is also /tmp, which is sandboxed. So these rm calls
    // should either affect only the ephemeral sandbox or hit tmpfs-hidden dirs.
    let script = format!(
        "set -x; echo HELLO > /tmp/inside.txt; ls -la /tmp; rm -rf / 2>/dev/null; rm -rf $HOME 2>/dev/null; \
         echo DONE"
    );
    let out = tokimo_package_sandbox::run(&["/bin/sh", "-c", &script], &cfg)?;

    println!("exit: {} timed_out: {} oom: {}", out.exit_code, out.timed_out, out.oom_killed);
    println!("--- stdout ---\n{}", out.stdout);
    println!("--- stderr ---\n{}", out.stderr);

    // Verify canaries.
    let a = canary_home.exists();
    let b = canary_tmp_host.exists();
    println!("\nHost canary in $HOME still present? {}", a);
    println!("Host canary in /tmp still present?   {}", b);
    fs::remove_file(&canary_home).ok();
    fs::remove_file(&canary_tmp_host).ok();

    if a && b {
        println!("\n✅ SANDBOX HELD: host files were not affected.");
        Ok(())
    } else {
        Err("❌ SANDBOX FAILED: a host canary was deleted".into())
    }
}
