//! Verify that `Session::run_oneshot` is truly concurrent: launch N
//! `sleep 1` calls in parallel and assert wall-clock ≈ 1s, not N seconds.
//!
//! Run with:
//!     cargo run --example concurrent_oneshot

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig, Session};

fn main() {
    let tmp = std::env::temp_dir().join(format!("tk-oneshot-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = SandboxConfig::new(&tmp).network(NetworkPolicy::Blocked);
    let sess = Session::open(&cfg).expect("Session::open");
    let factory = sess
        .run_oneshot_factory()
        .expect("run_oneshot_factory available on Linux");
    // Keep the session alive on the main thread; threads only need the
    // factory (which is Arc<dyn Fn..> and Send + Sync).
    let _keep_alive = sess;

    const N: usize = 10;
    let started = Instant::now();
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let f = Arc::clone(&factory);
            std::thread::spawn(move || {
                let t = Instant::now();
                let r = f("sleep 1; echo done", Duration::from_secs(5)).expect("run_oneshot");
                println!(
                    "[{:>4}ms] worker {} exit={} stdout={:?}",
                    t.elapsed().as_millis(),
                    i,
                    r.exit_code,
                    r.stdout.trim()
                );
                r.exit_code
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), 0);
    }
    let elapsed = started.elapsed();
    println!(
        "{} workers finished in {}ms (serial would be ~{}ms)",
        N,
        elapsed.as_millis(),
        N * 1000
    );
    assert!(
        elapsed < Duration::from_millis(2500),
        "run_oneshot is not concurrent: took {}ms for {} parallel sleeps",
        elapsed.as_millis(),
        N
    );
    println!("ok");
}
