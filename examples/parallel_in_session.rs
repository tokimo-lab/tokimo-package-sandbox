//! Demonstrate intra-session parallelism: a slow background job runs while
//! fast foreground exec()s return immediately, all sharing one bash.

use std::time::{Duration, Instant};
use tokimo_package_sandbox::{NetworkPolicy, ResourceLimits, SandboxConfig, Session};

fn main() {
    let work = std::env::temp_dir().join("tps-parallel-demo");
    let _ = std::fs::create_dir_all(&work);
    let cfg = SandboxConfig::new(&work)
        .network(NetworkPolicy::Blocked)
        .limits(ResourceLimits {
            max_memory_mb: 256,
            timeout_secs: 30,
            ..Default::default()
        });

    let mut sess = Session::open(&cfg).expect("open");

    // Kick off a slow background job (sleeps ~2s then writes "SLOW DONE").
    let t0 = Instant::now();
    let slow = sess
        .spawn("for i in 1 2 3 4; do echo \"step $i\"; sleep 0.5; done; echo SLOW DONE")
        .expect("spawn");
    println!("[{:>5}ms] spawned slow job id={}", t0.elapsed().as_millis(), slow.id());

    // Fast foreground exec — should NOT wait for the slow one.
    let r = sess.exec("echo FAST && echo also-fast").expect("exec");
    println!(
        "[{:>5}ms] fast exec done: {:?}",
        t0.elapsed().as_millis(),
        r.stdout.trim()
    );
    assert!(r.stdout.contains("FAST"));
    assert!(t0.elapsed() < Duration::from_millis(500), "fast exec was blocked!");

    // Another fast one — also unblocked.
    let r = sess.exec("date +%s").expect("exec");
    println!("[{:>5}ms] date: {}", t0.elapsed().as_millis(), r.stdout.trim());

    // Spawn a second background job concurrently.
    let other = sess
        .spawn("sleep 1 && echo OTHER DONE && echo bye >&2")
        .expect("spawn");
    println!("[{:>5}ms] spawned other id={}", t0.elapsed().as_millis(), other.id());

    // Yet another fast exec while two bg jobs run.
    let r = sess.exec("echo still-fast").expect("exec");
    println!("[{:>5}ms] still-fast: {}", t0.elapsed().as_millis(), r.stdout.trim());

    // Now wait for both bg jobs (in arbitrary order).
    let r = other.wait().expect("wait other");
    println!(
        "[{:>5}ms] other finished: stdout={:?} stderr={:?} rc={}",
        t0.elapsed().as_millis(),
        r.stdout.trim(),
        r.stderr.trim(),
        r.exit_code
    );
    assert_eq!(r.stdout.trim(), "OTHER DONE");
    assert_eq!(r.stderr.trim(), "bye");
    assert_eq!(r.exit_code, 0);

    let r = slow.wait().expect("wait slow");
    println!(
        "[{:>5}ms] slow finished: rc={} stdout last line: {:?}",
        t0.elapsed().as_millis(),
        r.exit_code,
        r.stdout.lines().last().unwrap_or("")
    );
    assert!(r.stdout.contains("SLOW DONE"));
    assert!(r.stdout.contains("step 4"));
    assert_eq!(r.exit_code, 0);

    sess.close().expect("close");
    println!("ok");
}
