//! Edge-case tests: concurrent multi-thread wait(), session killed mid-flight,
//! background job exceeds its wait timeout.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tokimo_package_sandbox::{NetworkPolicy, ResourceLimits, SandboxConfig, Session};

fn mk_cfg(name: &str) -> SandboxConfig {
    let work = std::env::temp_dir().join(format!("tps-edge-{}", name));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    SandboxConfig::new(&work)
        .network(NetworkPolicy::Blocked)
        .limits(ResourceLimits {
            max_memory_mb: 256,
            timeout_secs: 30,
            ..Default::default()
        })
}

fn case_concurrent_waits() {
    println!("== case 1: concurrent multi-thread wait() ==");
    let mut sess = Session::open(&mk_cfg("concurrent")).unwrap();

    // Spawn 8 bg jobs with varying sleep durations.
    let mut handles = Vec::new();
    let t0 = Instant::now();
    for i in 0..8u32 {
        // Each job sleeps a bit, prints "job-N", and exits with rc=N.
        let cmd = format!(
            "sleep 0.{}; echo job-{}; exit {}",
            (i + 2) * 100 / 1000 + (i + 2) % 10,
            i,
            i
        );
        handles.push((i, sess.spawn(&cmd).unwrap()));
    }
    println!("  spawned 8 jobs in {:?}", t0.elapsed());

    // Hand each handle to its own thread; they all wait() concurrently.
    let done = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for (i, h) in handles {
        let done = done.clone();
        threads.push(thread::spawn(move || {
            let r = h.wait().expect("wait");
            assert_eq!(r.stdout.trim(), format!("job-{}", i), "job {} stdout", i);
            assert_eq!(r.exit_code, i as i32, "job {} rc", i);
            done.fetch_add(1, Ordering::SeqCst);
            (i, r.exit_code)
        }));
    }

    // Meanwhile, the main thread keeps doing exec() — must not be blocked
    // by waiting threads (they only touch shared Mutex briefly).
    for k in 0..5 {
        let r = sess.exec(&format!("echo main-{}", k)).unwrap();
        assert_eq!(r.stdout.trim(), format!("main-{}", k));
        thread::sleep(Duration::from_millis(50));
    }

    // Collect.
    let mut results: Vec<(u32, i32)> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    results.sort();
    println!("  wait results: {:?}", results);
    assert_eq!(done.load(Ordering::SeqCst), 8);
    assert_eq!(results, (0..8u32).map(|i| (i, i as i32)).collect::<Vec<_>>());
    println!("  ✓ all 8 concurrent waits resolved correctly\n");

    sess.close().unwrap();
}

fn case_session_killed_midflight() {
    println!("== case 2: session killed mid-flight ==");
    let mut sess = Session::open(&mk_cfg("killed")).unwrap();
    sess.set_exec_timeout(Duration::from_secs(5));

    // Spawn a slow bg job that we'll never get to wait for.
    let bg = sess.spawn("sleep 10; echo unreachable").unwrap();

    // Run a fast exec to confirm session is alive.
    let r = sess.exec("echo alive").unwrap();
    assert_eq!(r.stdout.trim(), "alive");

    // Bash kills ITSELF. The exec script writes `kill -9 $$` which kills
    // bash before it can emit any sentinel. Our reader sees EOF, marks
    // early_eof, and the blocked exec returns an error.
    let r = sess.exec("kill -9 $$");
    println!(
        "  exec(kill -9 $$) returned: {:?}",
        r.as_ref().err().map(|e| e.to_string())
    );
    assert!(r.is_err(), "exec should fail when bash dies before sentinel");

    // Subsequent exec must also fail (session is dead).
    let r2 = sess.exec("echo nope");
    println!(
        "  follow-up exec returned: {:?}",
        r2.as_ref().err().map(|e| e.to_string())
    );
    assert!(r2.is_err(), "follow-up exec on dead session must error");

    // Pending JobHandle::wait() must return error too (early_eof set).
    let r3 = bg.wait();
    println!(
        "  pending wait() returned: {:?}",
        r3.as_ref().err().map(|e| e.to_string())
    );
    assert!(r3.is_err(), "pending wait() must error after session dies");

    println!("  ✓ all post-mortem ops returned errors cleanly\n");
    // Drop sess — close_inner is idempotent.
}

fn case_bg_job_timeout() {
    println!("== case 3: background job exceeds wait timeout ==");
    let mut sess = Session::open(&mk_cfg("bgtimeout")).unwrap();

    // Slow bg job sleeps 5s.
    let slow = sess.spawn("sleep 5; echo too-late").unwrap();

    // Other execs continue to work.
    let r = sess.exec("echo quick").unwrap();
    assert_eq!(r.stdout.trim(), "quick");

    // wait_with_timeout(500ms) must time out (job needs 5s).
    let t0 = Instant::now();
    let r = slow.wait_with_timeout(Duration::from_millis(500));
    let elapsed = t0.elapsed();
    println!(
        "  wait_with_timeout(500ms) returned in {:?}: {:?}",
        elapsed,
        r.as_ref().err().map(|e| e.to_string())
    );
    assert!(r.is_err(), "must time out");
    assert!(
        elapsed >= Duration::from_millis(450),
        "timeout was too eager: {:?}",
        elapsed
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "timeout was too late: {:?}",
        elapsed
    );

    // Session is still healthy — more execs work fine.
    let r = sess.exec("echo still-alive").unwrap();
    assert_eq!(r.stdout.trim(), "still-alive");

    // Wait again with larger timeout — should now succeed (bg job finishes).
    let r = slow.wait_with_timeout(Duration::from_secs(8)).unwrap();
    assert_eq!(r.stdout.trim(), "too-late");
    assert_eq!(r.exit_code, 0);
    println!("  ✓ retry with longer timeout succeeded\n");

    sess.close().unwrap();
}

fn main() {
    case_concurrent_waits();
    case_session_killed_midflight();
    case_bg_job_timeout();
    println!("🎉 ALL EDGE CASES PASSED");
}
