mod common;

use std::time::{Duration, Instant};

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

#[test]
fn status_rpcs_during_blocking_shell() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("async")).expect("configure");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // bash is now blocked in `sleep 3`. write_stdin returns as soon as the
    // bytes are queued in the host→guest pipe — it does NOT wait for bash
    // to finish processing the line.
    sb.write_stdin(&shell, b"sleep 3\n").unwrap();

    // Issue several status RPCs while sleep is running. They should all
    // return almost instantly because the dispatcher is independent of
    // the per-shell event pump.
    let t0 = Instant::now();
    for _ in 0..5 {
        assert!(sb.is_running().expect("is_running"));
        assert!(sb.is_guest_connected().expect("is_guest_connected"));
    }
    let elapsed = t0.elapsed();
    sb.stop_vm().ok();

    assert!(
        elapsed < Duration::from_secs(2),
        "status RPCs were serialized with shell stdin: {elapsed:?}"
    );
}

#[test]
fn concurrent_commands_in_single_shell() {
    let cfg = config("concurrent");
    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Two background jobs: A sleeps 2s, B sleeps 5s. With wall clock between
    // ~5s and ~7s (sequential would be ≥7s, parallel ≥5s).
    let started = Instant::now();
    sb.write_stdin(
        &shell,
        b"(sleep 2; echo JOB_A_DONE) & (sleep 5; echo JOB_B_DONE) & wait; echo ALL_CONCURRENT_DONE\n",
    )
    .unwrap();
    let captured = drain_until(&rx, &shell, "ALL_CONCURRENT_DONE", Duration::from_secs(15));
    let elapsed = started.elapsed();
    sb.stop_vm().ok();

    assert!(captured.contains("JOB_A_DONE"), "missing JOB_A_DONE: {captured:?}");
    assert!(captured.contains("JOB_B_DONE"), "missing JOB_B_DONE: {captured:?}");
    // Sequential would be ≥7s. Parallel should land in [5s, 7s).
    // Allow generous upper bound (network/startup variance).
    assert!(elapsed < Duration::from_secs(7), "jobs ran sequentially ({elapsed:?})");
    assert!(
        elapsed >= Duration::from_secs(5),
        "completed too fast — sleeps not honoured? ({elapsed:?})"
    );
}
