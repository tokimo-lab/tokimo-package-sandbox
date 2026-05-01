//! Integration tests for the public `Sandbox` API.
//!
//! Requires the SYSTEM service to be running. See
//! `scripts/test-integration.ps1` for the elevated runner.
//!
//! Tests are serialized via `--test-threads=1` because Hyper-V is rate
//! limited and tests share the host-side service.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{ConfigureParams, Event, JobId, NetworkPolicy, Plan9Share, Sandbox};

// Counter to make per-test session_id unique within a single test process.
static N: AtomicU32 = AtomicU32::new(0);

fn workspace_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tokimo-test-{label}"));
    std::fs::create_dir_all(&dir).ok();
    dir
}

fn config(label: &str) -> ConfigureParams {
    ConfigureParams {
        user_data_name: "test".into(),
        memory_mb: 1024,
        cpu_count: 2,
        plan9_shares: vec![Plan9Share {
            name: "ws".into(),
            host_path: workspace_dir(label),
            guest_path: "/work".into(),
            read_only: false,
        }],
        network: NetworkPolicy::Blocked,
        session_id: format!("{}-{}-{}", std::process::id(), label, N.fetch_add(1, Ordering::Relaxed)),
        ..Default::default()
    }
}

/// Drain `rx` for stdout chunks belonging to `shell` until either `needle`
/// is seen or the timeout elapses. Returns the captured text either way.
fn drain_until(rx: &Receiver<Event>, shell: &JobId, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::<u8>::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Stdout { id, data }) if id == *shell => {
                buf.extend_from_slice(&data);
                if std::str::from_utf8(&buf).map(|s| s.contains(needle)).unwrap_or(false) {
                    break;
                }
            }
            Ok(Event::Exit { id, .. }) if id == *shell => break,
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

// ---------------------------------------------------------------------------
// 1. Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_start_and_stop() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("basic")).expect("configure");
    sb.start_vm().expect("start_vm");

    let shell = sb.shell_id().expect("shell_id");
    assert!(!shell.as_str().is_empty(), "shell id must not be empty");
    assert!(sb.is_running().expect("is_running"));

    sb.stop_vm().expect("stop_vm");
}

#[test]
fn shell_id_before_start() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("nostart")).expect("configure");
    assert!(sb.shell_id().is_err(), "shell_id should fail before start_vm");
}

#[test]
fn shell_id_after_stop_is_error() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("after_stop")).expect("configure");
    sb.start_vm().expect("start_vm");
    sb.shell_id().expect("shell_id during run");
    sb.stop_vm().expect("stop_vm");
    assert!(sb.shell_id().is_err(), "shell_id after stop must fail");
}

// ---------------------------------------------------------------------------
// 2. Stdout
// ---------------------------------------------------------------------------

#[test]
fn shell_stdout_echo() {
    const MARKER: &str = "TOKIMO_MARKER_8F2E";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("echo")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, format!("echo {MARKER}\n").as_bytes())
        .expect("write_stdin");

    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(
        captured.contains(MARKER),
        "marker never seen on stdout. captured: {captured:?}"
    );
}

#[test]
fn shell_runs_multiple_commands() {
    const END: &str = "END_MULTI_5A1F";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("multicmd")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, b"pwd\n").unwrap();
    sb.write_stdin(&shell, b"uname -s\n").unwrap();
    sb.write_stdin(&shell, b"id -u\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(captured.contains("Linux"), "missing uname output: {captured:?}");
    assert!(captured.contains(END), "missing terminator: {captured:?}");
}

// ---------------------------------------------------------------------------
// 3. Plan9 mount visibility
// ---------------------------------------------------------------------------

#[test]
fn plan9_host_file_visible_in_guest() {
    const FNAME: &str = "tokimo_sentinel.txt";
    const BODY: &str = "SENTINEL_FROM_HOST_5C9D";

    // We need to write the file on the host *before* configure picks up
    // the workspace path. config(label) creates a per-label tmp dir and
    // shares it as /work — write the sentinel into that exact dir.
    let label = "p9visible";
    let host_path = workspace_dir(label).join(FNAME);
    std::fs::write(&host_path, BODY).expect("write sentinel on host");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, format!("cat /work/{FNAME}\n").as_bytes())
        .unwrap();

    let captured = drain_until(&rx, &shell, BODY, Duration::from_secs(30));
    sb.stop_vm().ok();
    let _ = std::fs::remove_file(&host_path);

    assert!(
        captured.contains(BODY),
        "host sentinel not visible in guest. captured: {captured:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Async / parallel: status RPCs must not block on shell stdin
// ---------------------------------------------------------------------------

#[test]
fn status_rpcs_during_blocking_shell() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("async")).expect("configure");
    sb.start_vm().expect("start_vm");
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

// ---------------------------------------------------------------------------
// 5. Multi-session: two parallel Sandbox handles, distinct VMs.
// ---------------------------------------------------------------------------

#[test]
fn multi_session_concurrent() {
    use std::thread;

    let h1 = thread::spawn(|| run_marker_session("session-A", "MARKER_A_4F2"));
    let h2 = thread::spawn(|| run_marker_session("session-B", "MARKER_B_8E1"));
    h1.join().expect("session-A panicked");
    h2.join().expect("session-B panicked");
}

fn run_marker_session(label: &str, marker: &str) {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, format!("echo {marker}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, marker, Duration::from_secs(45));
    sb.stop_vm().ok();

    assert!(
        captured.contains(marker),
        "[{label}] marker not seen. captured: {captured:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. Plan9 dynamic add / remove
// ---------------------------------------------------------------------------

#[test]
fn plan9_dynamic_add_remove() {
    const FNAME: &str = "extra_sentinel.txt";
    const BODY: &str = "DYNAMIC_5E7C_HOST";

    let label = "p9dyn";
    let extra = workspace_dir(&format!("{label}-extra"));
    std::fs::write(extra.join(FNAME), BODY).expect("write sentinel");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    // 1. Before add: /extra is empty / nonexistent.
    sb.write_stdin(&shell, b"ls /extra 2>&1 | head -1; echo PRE_DONE_1AB\n")
        .unwrap();
    let pre = drain_until(&rx, &shell, "PRE_DONE_1AB", Duration::from_secs(20));
    assert!(
        !pre.contains(BODY),
        "extra share already mounted before add. captured: {pre:?}"
    );

    // 2. Add share, then read sentinel from inside the guest.
    sb.add_plan9_share(Plan9Share {
        name: "extra".into(),
        host_path: extra.clone(),
        guest_path: "/extra".into(),
        read_only: false,
    })
    .expect("add_plan9_share");
    sb.write_stdin(&shell, format!("cat /extra/{FNAME}; echo POST_ADD_2CD\n").as_bytes())
        .unwrap();
    let post = drain_until(&rx, &shell, "POST_ADD_2CD", Duration::from_secs(30));
    assert!(
        post.contains(BODY),
        "after add, sentinel not visible. captured: {post:?}"
    );

    // 3. Remove share. After this, /extra may be empty or fail to read.
    sb.remove_plan9_share("extra").expect("remove_plan9_share");
    sb.write_stdin(
        &shell,
        format!("cat /extra/{FNAME} 2>&1; echo POST_REM_3EF\n").as_bytes(),
    )
    .unwrap();
    let removed = drain_until(&rx, &shell, "POST_REM_3EF", Duration::from_secs(20));
    assert!(
        !removed.contains(BODY),
        "after remove, sentinel still readable. captured: {removed:?}"
    );

    sb.stop_vm().ok();
}

// ---------------------------------------------------------------------------
// 7. SIGINT delivery via signal_shell
// ---------------------------------------------------------------------------
//
// Note: the boot-time shell runs in pipe mode without a controlling TTY,
// so bash itself takes the default SIGINT disposition (terminate). This
// test therefore verifies the *wire path* — host → service → init →
// `killpg(SIGINT)` → kernel — by asserting an Exit event surfaces with
// `signal == Some(2)`. A higher-level "interrupt the foreground command
// without killing the shell" mode requires PTY-mode shells, which is
// tracked separately.

#[test]
fn signal_shell_delivers_sigint() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("sigint")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    // Park bash inside a long sleep so SIGINT has something to interrupt.
    sb.write_stdin(&shell, b"sleep 60\n").unwrap();
    std::thread::sleep(Duration::from_millis(750));

    sb.interrupt_shell().expect("interrupt_shell");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_exit = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Exit { id, exit_code, signal }) if id == shell => {
                got_exit = Some((exit_code, signal));
                break;
            }
            Ok(_) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    sb.stop_vm().ok();

    let (exit_code, signal) = got_exit.expect("shell never reported Exit after SIGINT");
    assert_eq!(
        signal,
        Some(2),
        "expected SIGINT (2). exit_code={exit_code} signal={signal:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. NetworkPolicy enforcement
// ---------------------------------------------------------------------------
//
// Blocked  → no NetworkAdapter device on the VM → guest has only `lo`.
// AllowAll → HCN NAT endpoint attached → guest gets at least one extra NIC.

fn link_count(rx: &Receiver<Event>, sb: &Sandbox, shell: &JobId) -> usize {
    sb.write_stdin(shell, b"ls -1 /sys/class/net/ 2>&1 | wc -l; echo LC_DONE_X9F2\n")
        .unwrap();
    let captured = drain_until(rx, shell, "LC_DONE_X9F2", Duration::from_secs(20));
    // Find the first line that is purely a number — that's `wc -l`.
    captured
        .lines()
        .find_map(|l| l.trim().parse::<usize>().ok())
        .unwrap_or_else(|| panic!("no numeric link count line in: {captured:?}"))
}

#[test]
fn network_blocked_only_loopback() {
    let mut cfg = config("net-blocked");
    cfg.network = NetworkPolicy::Blocked;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    let n = link_count(&rx, &sb, &shell);
    assert_eq!(n, 1, "Blocked policy must yield exactly 1 link (lo), got {n}");

    // Egress probe MUST fail under Blocked.
    sb.write_stdin(
        &shell,
        b"timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo NET_LEAK_BLK || echo NET_DENIED_BLK'; echo NET_PROBE_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "NET_PROBE_DONE", Duration::from_secs(10));

    sb.stop_vm().ok();
    assert!(
        probe.contains("NET_DENIED_BLK"),
        "Blocked: egress should fail. probe={probe:?}"
    );
    assert!(
        !probe.contains("NET_LEAK_BLK"),
        "Blocked: TCP unexpectedly opened. probe={probe:?}"
    );
}

// Verifies that AllowAll attaches an HCN endpoint and the guest enumerates
// it as eth0 (synthetic Hyper-V NIC via `hv_netvsc`).
#[test]
fn network_allow_all_has_nic() {
    let mut cfg = config("net-allow");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    let n = link_count(&rx, &sb, &shell);
    assert!(n >= 2, "AllowAll policy must yield ≥2 links (lo + NIC), got {n}");

    // Real egress probe via bash /dev/tcp (avoids depending on curl/wget).
    // The HCN NAT gateway is at 192.168.127.1 and routes to the host network.
    sb.write_stdin(
        &shell,
        b"timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo NET_OK_8F2E || echo NET_FAIL_8F2E'; echo NET_PROBE_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "NET_PROBE_DONE", Duration::from_secs(15));

    sb.stop_vm().ok();
    assert!(
        probe.contains("NET_OK_8F2E"),
        "AllowAll: TCP egress to 1.1.1.1:53 failed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// 9. Concurrent commands inside a single VM (single shell, bash background)
// ---------------------------------------------------------------------------
//
// The architecture deliberately exposes ONE shell per session. Concurrency
// inside that shell is achieved by the user sending normal bash backgrounded
// pipelines (`cmd1 & cmd2 & wait`). This test asserts that two sleeps
// running in parallel finish in ~max(durations), not in sum(durations) —
// proving the init pipeline does not serialise children, and stdout from
// both jobs is interleaved correctly.

#[test]
fn concurrent_commands_in_single_shell() {
    let cfg = config("concurrent");
    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
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
