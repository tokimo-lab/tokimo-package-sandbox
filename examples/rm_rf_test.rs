//! Proves the sandbox protects the host: creates a canary file in a host temp
//! directory, then runs `rm -rf` from inside the sandbox. The canary on the
//! host should survive.

use std::fs;
use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let canary_dir = std::env::temp_dir().join("tps-rmrf-canary");
    fs::create_dir_all(&canary_dir)?;
    let canary = canary_dir.join("tps-canary-DO-NOT-DELETE.txt");

    fs::write(&canary, b"host canary - should survive\n")?;

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

    println!(
        "exit: {} timed_out: {} oom: {}",
        out.exit_code, out.timed_out, out.oom_killed
    );
    println!("--- stdout ---\n{}", out.stdout);
    println!("--- stderr ---\n{}", out.stderr);

    // Verify canary survived.
    let survived = canary.exists();
    println!("\nHost canary still present? {}", survived);
    fs::remove_file(&canary).ok();
    let _ = fs::remove_dir(&canary_dir);

    if survived {
        println!("\n✅ SANDBOX HELD: host file was not affected.");
        Ok(())
    } else {
        Err("❌ SANDBOX FAILED: the host canary was deleted".into())
    }
}
