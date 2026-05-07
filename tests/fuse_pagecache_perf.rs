//! Demonstrates the FOPEN_KEEP_CACHE win: repeated reads of the same
//! file should hit the kernel page cache without round-tripping to the
//! VFS host. Measures cold vs warm read latency for a 16MB file inside
//! a real bwrap+FUSE sandbox.
//!
//! Not an `assert!`-style test: numbers are printed for human inspection
//! when run with `--nocapture`. CI just verifies it doesn't crash.

mod common;

use std::time::{Duration, Instant};

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::Sandbox;

#[test]
fn fopen_keep_cache_warm_reads_are_faster() {
    const LABEL: &str = "pagecache-perf";
    const FNAME: &str = "warm.bin";
    const SIZE_MB: usize = 16;

    let ws = workspace_dir(LABEL);
    let path = ws.join(FNAME);
    let data = vec![0xCDu8; SIZE_MB * 1024 * 1024];
    std::fs::write(&path, &data).expect("seed file");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(LABEL)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Helper: run `dd` with a unique marker, return wall time of the
    // exec round-trip (host-observed; includes shell + dd overhead, but
    // the *delta* between cold and warm runs is dominated by FUSE I/O).
    let timed_read = |round: u32| -> Duration {
        let marker = format!("__done_{round}__");
        let cmd = format!("dd if=/work/{FNAME} of=/dev/null bs=1M 2>/dev/null; echo {marker}\n");
        let t0 = Instant::now();
        sb.write_stdin(&shell, cmd.as_bytes()).expect("write_stdin");
        let _ = drain_until(&rx, &shell, &marker, Duration::from_secs(30));
        t0.elapsed()
    };

    // Drop guest page cache before the cold run so the first read
    // really exercises the FUSE wire path.
    let drop_marker = "__dropped__";
    sb.write_stdin(
        &shell,
        format!("sync; echo 3 >/proc/sys/vm/drop_caches 2>/dev/null; echo {drop_marker}\n").as_bytes(),
    )
    .expect("drop caches");
    let _ = drain_until(&rx, &shell, drop_marker, Duration::from_secs(5));

    let cold = timed_read(0);
    let warm1 = timed_read(1);
    let warm2 = timed_read(2);
    let warm3 = timed_read(3);

    eprintln!("=== FUSE page-cache perf ({SIZE_MB} MB file) ===");
    eprintln!("  cold  read: {:?}", cold);
    eprintln!("  warm1 read: {:?}", warm1);
    eprintln!("  warm2 read: {:?}", warm2);
    eprintln!("  warm3 read: {:?}", warm3);
    if let Some(ratio) = cold.as_nanos().checked_div(warm2.as_nanos().max(1)) {
        eprintln!("  cold/warm2 speedup: {ratio}×");
    }

    sb.stop_vm().ok();
}
