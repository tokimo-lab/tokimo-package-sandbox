//! Basic usage: run `ls -la /` inside the sandbox and show the output.

use tokimo_package_sandbox::{NetworkPolicy, ResourceLimits, SandboxConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work = tempfile::tempdir()?;
    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .limits(ResourceLimits {
            max_memory_mb: 256,
            timeout_secs: 10,
            max_file_size_mb: 16,
            max_processes: 64,
        });

    let out = tokimo_package_sandbox::run(&["/bin/sh", "-c", "ls -la / ; echo ---; id ; echo ---; hostname"], &cfg)?;
    println!("exit: {}", out.exit_code);
    println!("timed_out: {}", out.timed_out);
    println!("oom_killed: {}", out.oom_killed);
    println!("--- stdout ---\n{}", out.stdout);
    println!("--- stderr ---\n{}", out.stderr);
    Ok(())
}
