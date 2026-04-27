//! Smoke test for `Session::kill_job`.
//!
//! Verifies that:
//!  1. A long-running spawned job can be killed mid-flight.
//!  2. The session bash stays alive — subsequent `exec` works.
//!  3. Session env / cwd survive the kill.

use std::time::{Duration, Instant};

use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig, Session};

fn main() {
    let work = tempfile::tempdir().expect("tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("open");

    // Set some session state we expect to survive the kill.
    let _ = sess.exec("export SENTINEL=alive ; cd /tmp").expect("setup");

    // Spawn a long-running job.
    let t0 = Instant::now();
    let slow = sess.spawn("sleep 30 ; echo SHOULD-NEVER-PRINT").expect("spawn");
    println!("[{:>4}ms] spawned slow job id={}", t0.elapsed().as_millis(), slow.id());

    // Give bash a beat to actually fork the job (write the pidfile).
    std::thread::sleep(Duration::from_millis(200));

    // Kill it.
    sess.kill_job(slow.id()).expect("kill_job dispatch");
    println!("[{:>4}ms] kill_job dispatched", t0.elapsed().as_millis());

    // Wait should now resolve quickly with a non-zero exit (signal).
    let r = slow.wait_with_timeout(Duration::from_secs(3));
    println!(
        "[{:>4}ms] wait_with_timeout returned: {:?}",
        t0.elapsed().as_millis(),
        r.as_ref().map(|o| o.exit_code).map_err(|e| e.to_string())
    );
    let out = r.expect("wait should succeed (job killed)");
    assert!(out.exit_code != 0, "killed job must have non-zero exit, got 0");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "kill should finish well under 30s, took {:?}",
        elapsed
    );

    // Session still alive — env and cwd preserved.
    let r = sess.exec("echo $SENTINEL ; pwd").expect("post-kill exec");
    let stdout = r.stdout.trim();
    println!("[{:>4}ms] post-kill exec: {:?}", t0.elapsed().as_millis(), stdout);
    assert!(
        stdout.starts_with("alive"),
        "session env LOST after kill_job: stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/tmp"),
        "session cwd LOST after kill_job: stdout={stdout:?}"
    );

    // Killing an already-dead job is a no-op (pidfile already cleaned up).
    sess.kill_job(slow.id()).expect("idempotent kill");

    println!("ok");
}
