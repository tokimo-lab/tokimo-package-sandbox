//! Integration tests for the public `Sandbox` API.
//!
//! Requires the SYSTEM service to be running. See
//! `scripts/windows/test-integration.ps1` for the elevated runner.
//!
//! Tests are serialized via `--test-threads=1` because Hyper-V is rate
//! limited and tests share the host-side service.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{AddUserOpts, ConfigureParams, Event, JobId, Mount, NetworkPolicy, Sandbox, ShellOpts};

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
        mounts: vec![Mount {
            name: "ws".into(),
            host_path: workspace_dir(label),
            guest_path: "/work".into(),
            read_only: false,
            create_host_dir: false,
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
fn shell_env_does_not_leak_init_control_vars() {
    // Regression test: init's private control env vars
    // (TOKIMO_SANDBOX_CONTROL_FD, TOKIMO_SANDBOX_BRINGUP_LO,
    // TOKIMO_SANDBOX_MOUNT_SYSFS, TOKIMO_SANDBOX_SECCOMP_B64, ...) must
    // never be visible inside the sandbox. They were previously snapshotted
    // verbatim by `snapshot_base_env` and inherited by every shell child.
    const END: &str = "END_ENV_LEAK_9C7B";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("envleak")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, b"env | grep -c '^TOKIMO_SANDBOX_' || true\n")
        .unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    // `grep -c` prints "0" when nothing matches. Anything else means leakage.
    let count_line = captured
        .lines()
        .rfind(|l| l.trim().chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("");
    assert_eq!(
        count_line.trim(),
        "0",
        "TOKIMO_SANDBOX_* env vars leaked into shell. captured: {captured:?}"
    );
}

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
// 3. FUSE mount visibility
// ---------------------------------------------------------------------------

#[test]
fn fuse_host_file_visible_in_guest() {
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
// 6. FUSE dynamic add / remove
// ---------------------------------------------------------------------------

#[test]
fn fuse_dynamic_add_remove() {
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
    sb.add_mount(Mount {
        name: "extra".into(),
        host_path: extra.clone(),
        guest_path: "/extra".into(),
        read_only: false,
        create_host_dir: false,
    })
    .expect("add_mount");
    sb.write_stdin(&shell, format!("cat /extra/{FNAME}; echo POST_ADD_2CD\n").as_bytes())
        .unwrap();
    let post = drain_until(&rx, &shell, "POST_ADD_2CD", Duration::from_secs(30));
    assert!(
        post.contains(BODY),
        "after add, sentinel not visible. captured: {post:?}"
    );

    // 3. Remove share. After this, /extra may be empty or fail to read.
    sb.remove_mount("extra").expect("remove_mount");
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

    sb.interrupt_shell(&shell).expect("interrupt_shell");

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
    // Under the always-on netstack design (since macOS-NFS-mount), the
    // guest always has tk0 in its netns regardless of policy — Blocked
    // just gates egress at the smoltcp gateway. The only egress that
    // survives Blocked is registered LocalServices (e.g. NFS). So we
    // expect 2 links here: lo + tk0. The egress probe below proves
    // external traffic is still blocked.
    assert_eq!(n, 2, "Blocked policy must yield 2 links (lo + tk0), got {n}");

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

    // Egress probe — AllowAll should let the guest open an outbound TCP
    // connection. We use 1.1.1.1:53 (Cloudflare DNS) as a stable target
    // that is reachable from virtually any internet-connected host.
    // The exact NIC IP / subnet depends on the backend (Windows: HCN NAT
    // 192.168.127.0/24; Linux bwrap: shared host netns; macOS VZ: bridged
    // NAT) — what we assert is the *capability*, not the implementation.
    sb.write_stdin(
        &shell,
        b"timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo NET_OK_ALLOW || echo NET_FAIL_ALLOW'; echo NET_PROBE_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "NET_PROBE_DONE", Duration::from_secs(15));

    sb.stop_vm().ok();
    assert!(
        probe.contains("NET_OK_ALLOW"),
        "AllowAll: egress to 1.1.1.1:53 should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// 8.b ICMPv4 PING — verify the userspace netstack proxies ping echo replies.
// Ignored by default: ICMP through smoltcp TAP is environment-sensitive
// (GitHub Actions runners may block raw ICMP). Run manually:
//   cargo test --test sandbox_integration network_allow_all_icmpv4_ping -- --ignored
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn network_allow_all_icmpv4_ping() {
    let mut cfg = config("net-ping4");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(
        &shell,
        b"timeout 8 ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1 && echo PING4_OK || echo PING4_FAIL; echo PING4_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "PING4_DONE", Duration::from_secs(15));
    sb.stop_vm().ok();
    assert!(
        probe.contains("PING4_OK"),
        "AllowAll: ICMPv4 ping to 1.1.1.1 should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// 8.c IPv6 TCP — verify the netstack carries v6 SYN/ACK to a real endpoint.
// ---------------------------------------------------------------------------
#[test]
fn network_allow_all_ipv6_tcp() {
    let mut cfg = config("net-tcp6");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    // Cloudflare v6 DNS over TCP.
    sb.write_stdin(
        &shell,
        b"timeout 8 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/53 && echo TCP6_OK || echo TCP6_FAIL'; echo TCP6_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "TCP6_DONE", Duration::from_secs(20));
    sb.stop_vm().ok();
    // Host must have IPv6 connectivity for this to pass; tolerate skip if
    // the host machine lacks v6 by allowing the host probe to confirm first.
    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping assertion (probe={probe:?})");
        return;
    }
    assert!(
        probe.contains("TCP6_OK"),
        "AllowAll: IPv6 TCP egress should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// 8.d ICMPv6 PING — verify the netstack proxies v6 echo replies.
// ---------------------------------------------------------------------------
#[test]
fn network_allow_all_icmpv6_ping() {
    let mut cfg = config("net-ping6");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(
        &shell,
        b"timeout 8 ping -6 -c 1 -W 5 2606:4700:4700::1111 >/dev/null 2>&1 && echo PING6_OK || echo PING6_FAIL; echo PING6_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "PING6_DONE", Duration::from_secs(15));
    sb.stop_vm().ok();
    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping assertion (probe={probe:?})");
        return;
    }
    assert!(
        probe.contains("PING6_OK"),
        "AllowAll: ICMPv6 ping should succeed. probe={probe:?}"
    );
}

/// Check whether the host has working IPv6 connectivity by attempting to
/// open a short-lived TCP connection to a known dual-stack endpoint.
fn host_has_ipv6() -> bool {
    use std::net::{SocketAddr, TcpStream};
    let addr: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}

// ---------------------------------------------------------------------------
// 8.e IPv6 DIAGNOSTIC — `cargo test ... network_allow_all_ipv6_diag -- --ignored --nocapture`
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn network_allow_all_ipv6_diag() {
    let mut cfg = config("net-v6-diag");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    let cmds = b"echo === V6-ADDR ===\n\
ip -6 addr\n\
echo === V6-ROUTE ===\n\
ip -6 route\n\
echo === V6-NEIGH-BEFORE ===\n\
ip -6 neigh\n\
echo === DISABLE-IPV6 ===\n\
cat /proc/sys/net/ipv6/conf/tk0/disable_ipv6 2>&1 || echo MISSING\n\
echo === PING-V6-GW ===\n\
timeout 3 ping -6 -c 2 -W 1 fd00:7f::1 2>&1 || echo PING_GW6_FAIL\n\
echo === PING-V6-EXT ===\n\
timeout 3 ping -6 -c 2 -W 1 2606:4700:4700::1111 2>&1 || echo PING_EXT6_FAIL\n\
echo === V6-NEIGH-AFTER ===\n\
ip -6 neigh\n\
echo === TCP6 ===\n\
timeout 5 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/53 && echo TCP6_OK || echo TCP6_FAIL'\n\
echo V6_DIAG_DONE\n";
    sb.write_stdin(&shell, cmds).unwrap();
    let out = drain_until(&rx, &shell, "V6_DIAG_DONE", Duration::from_secs(30));
    sb.stop_vm().ok();
    eprintln!("=== V6 DIAG ===\n{out}\n=== END ===");
}

// ---------------------------------------------------------------------------
// 8.x DIAGNOSTIC — run with: cargo test --test sandbox_integration network_allow_all_diag -- --ignored --test-threads=1 --nocapture
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn network_allow_all_diag() {
    let mut cfg = config("net-diag");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let shell = sb.shell_id().expect("shell_id");

    let cmds = b"echo === LINKS ===\n\
ip -s link\n\
echo === ADDR ===\n\
ip -4 addr\n\
echo === ROUTE ===\n\
ip -4 route\n\
echo === NEIGH-BEFORE ===\n\
ip neigh\n\
echo === ARPING-GW ===\n\
timeout 3 arping -c 2 -I eth0 192.168.127.1 2>&1 || echo arping_failed_or_missing\n\
echo === PING-GW ===\n\
timeout 3 ping -c 2 -W 1 192.168.127.1 2>&1 || echo ping_gw_failed\n\
echo === PING-1.1.1.1 ===\n\
timeout 3 ping -c 2 -W 1 1.1.1.1 2>&1 || echo ping_1111_failed\n\
echo === NEIGH-AFTER ===\n\
ip neigh\n\
echo === TCP-SYN-PROBE ===\n\
(timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo TCP_OK || echo TCP_FAIL') &\n\
sleep 6\n\
echo === LINKS-AFTER ===\n\
ip -s link\n\
echo DIAG_DONE\n";
    sb.write_stdin(&shell, cmds).unwrap();
    let out = drain_until(&rx, &shell, "DIAG_DONE", Duration::from_secs(30));
    sb.stop_vm().ok();
    eprintln!("=== GUEST DIAG OUTPUT ===\n{out}\n=== END ===");
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

// ---------------------------------------------------------------------------
// 10. Multi-shell API: spawn_shell / close_shell / signal_shell-by-id
// ---------------------------------------------------------------------------
//
// Each shell has independent stdin/stdout streams (events are tagged with
// the JobId returned from spawn_shell). This exercises true API-level
// concurrency: two shells running in parallel, each individually
// addressable for write/signal/close.

fn drain_until_for_id(rx: &Receiver<Event>, target: &JobId, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut buf = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Event::Stdout { id, data }) if &id == target => {
                buf.push_str(&String::from_utf8_lossy(&data));
                if buf.contains(needle) {
                    return buf;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    buf
}

#[test]
fn multi_shell_isolated_streams() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("multi-shell")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell_a = sb.shell_id().expect("shell_id (boot shell = A)");
    let shell_b = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell B");
    assert_ne!(shell_a, shell_b, "spawn_shell must yield a fresh JobId");

    // Send distinct markers to each shell. Stdout streams MUST be tagged
    // with the right JobId — A's marker only on A's stream, B's only on B.
    sb.write_stdin(&shell_a, b"echo MARK_FROM_A_F00D\n").unwrap();
    sb.write_stdin(&shell_b, b"echo MARK_FROM_B_BEEF\n").unwrap();

    // Single drain loop — events for A and B arrive interleaved on one
    // channel. Bucket by JobId so neither marker gets discarded.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut from_a = String::new();
    let mut from_b = String::new();
    while Instant::now() < deadline {
        if from_a.contains("MARK_FROM_A_F00D") && from_b.contains("MARK_FROM_B_BEEF") {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Event::Stdout { id, data }) if id == shell_a => {
                from_a.push_str(&String::from_utf8_lossy(&data));
            }
            Ok(Event::Stdout { id, data }) if id == shell_b => {
                from_b.push_str(&String::from_utf8_lossy(&data));
            }
            _ => {}
        }
    }

    sb.close_shell(&shell_b).expect("close_shell B");
    sb.stop_vm().ok();

    assert!(
        from_a.contains("MARK_FROM_A_F00D"),
        "A stream missing A marker: {from_a:?}"
    );
    assert!(
        !from_a.contains("MARK_FROM_B_BEEF"),
        "A stream leaked B marker: {from_a:?}"
    );
    assert!(
        from_b.contains("MARK_FROM_B_BEEF"),
        "B stream missing B marker: {from_b:?}"
    );
    assert!(
        !from_b.contains("MARK_FROM_A_F00D"),
        "B stream leaked A marker: {from_b:?}"
    );
}

#[test]
fn multi_shell_independent_signals() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("multi-sig")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell_a = sb.shell_id().expect("shell_id");
    let shell_b = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell");

    // Park A in a long sleep; B will stay idle.
    sb.write_stdin(&shell_a, b"sleep 60\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));

    // SIGINT only A.
    sb.signal_shell(&shell_a, 2).expect("signal A");

    // Watch for A's exit but NOT B's.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut a_exited = false;
    let mut b_exited = false;
    while Instant::now() < deadline && !a_exited {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(500)) {
            #[allow(clippy::collapsible_match)]
            if let Event::Exit { id, signal, .. } = &ev {
                if id == &shell_a {
                    assert_eq!(*signal, Some(2), "A should die from SIGINT, got {signal:?}");
                    a_exited = true;
                } else if id == &shell_b {
                    b_exited = true;
                }
            }
        }
    }

    // Probe B is still alive by sending a marker and reading it back.
    sb.write_stdin(&shell_b, b"echo B_STILL_ALIVE_77\n").unwrap();
    let probe = drain_until_for_id(&rx, &shell_b, "B_STILL_ALIVE_77", Duration::from_secs(5));

    sb.close_shell(&shell_b).ok();
    sb.stop_vm().ok();

    assert!(a_exited, "A should have exited from SIGINT");
    assert!(!b_exited, "B should NOT have exited (signal was scoped to A)");
    assert!(
        probe.contains("B_STILL_ALIVE_77"),
        "B unresponsive after A's SIGINT: {probe:?}"
    );
}

#[test]
fn list_shells_tracks_lifecycle() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("list-shells")).expect("configure");
    sb.start_vm().expect("start_vm");

    let boot = sb.shell_id().expect("shell_id");
    let initial = sb.list_shells().expect("list_shells (initial)");
    assert_eq!(initial.len(), 1, "expected only the boot shell, got {initial:?}");
    assert!(
        initial.contains(&boot),
        "boot shell missing from initial list: {initial:?}"
    );

    let extra1 = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell #1");
    let extra2 = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell #2");

    let after_spawn = sb.list_shells().expect("list_shells (after spawn)");
    assert_eq!(after_spawn.len(), 3, "expected 3 shells, got {after_spawn:?}");
    for id in [&boot, &extra1, &extra2] {
        assert!(after_spawn.contains(id), "{id:?} missing from {after_spawn:?}");
    }

    sb.close_shell(&extra1).expect("close_shell #1");
    // close_shell removes the bookkeeping synchronously; list_shells must
    // reflect the change immediately, even if Event::Exit hasn't propagated.
    let after_close = sb.list_shells().expect("list_shells (after close)");
    assert_eq!(
        after_close.len(),
        2,
        "expected 2 shells after close, got {after_close:?}"
    );
    assert!(
        !after_close.contains(&extra1),
        "closed shell still listed: {after_close:?}"
    );
    assert!(after_close.contains(&boot), "boot shell vanished: {after_close:?}");
    assert!(after_close.contains(&extra2), "extra2 vanished: {after_close:?}");

    sb.close_shell(&extra2).ok();
    sb.stop_vm().ok();
}

// ---------------------------------------------------------------------------
// add_user — real-login path (VM modes) / env-fallback (Linux bwrap)
// ---------------------------------------------------------------------------
//
// Asserts the shell returned by `add_user` reports the requested user_id
// and HOME. On macOS VZ / Windows HCS the script in init runs `useradd`
// + `runuser -l`, so `whoami` returns the real account. On Linux bwrap
// the user-namespace fake-root cannot write /etc/passwd, so the script
// falls back to root + injected env; in that case `whoami` may say
// `root` but `$USER` / `$HOME` still match.

#[test]
fn add_user_sets_user_and_home_env() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("adduser")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let alice = sb
        .add_user(
            "alice",
            AddUserOpts {
                home: "/home/alice".into(),
                ..Default::default()
            },
        )
        .expect("add_user(alice)");

    sb.write_stdin(
        &alice,
        b"echo USER=$USER; echo HOME=$HOME; echo PWD=$(pwd); echo DONE_AU_71\n",
    )
    .unwrap();
    let out = drain_until(&rx, &alice, "DONE_AU_71", Duration::from_secs(30));

    assert!(out.contains("USER=alice"), "USER not set to alice: {out:?}");
    assert!(out.contains("HOME=/home/alice"), "HOME not set: {out:?}");
    assert!(out.contains("PWD=/home/alice"), "cwd not HOME: {out:?}");

    sb.remove_user("alice").ok();
    sb.stop_vm().ok();
}

// ---------------------------------------------------------------------------
// add_user + reverse-mount: guest writes inside HOME → host sees the file.
// ---------------------------------------------------------------------------
//
// This is the canonical "give a user an isolated home backed by a host
// directory" use case from the API rustdoc. The host pre-creates a
// directory, mounts it at /home/bob, then add_user("bob") with
// home=/home/bob. The shell writes to $HOME/note.txt inside the guest;
// the host reads the same bytes back from its local path.

#[test]
fn add_user_with_reverse_mount_writes_to_host() {
    const SENTINEL: &str = "BOB_WROTE_THIS_F3A2";

    let label = "adduser-rev";
    let bob_host = workspace_dir(&format!("{label}-bobhome"));
    // Make sure we start clean — file from a prior run would defeat the
    // assertion.
    let _ = std::fs::remove_file(bob_host.join("note.txt"));

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    sb.add_mount(Mount {
        name: "bob-home".into(),
        host_path: bob_host.clone(),
        guest_path: "/home/bob".into(),
        read_only: false,
        create_host_dir: true,
    })
    .expect("add_mount");

    let bob = sb
        .add_user(
            "bob",
            AddUserOpts {
                home: "/home/bob".into(),
                ..Default::default()
            },
        )
        .expect("add_user(bob)");

    sb.write_stdin(
        &bob,
        format!("echo {SENTINEL} > $HOME/note.txt; echo DONE_REV_88\n").as_bytes(),
    )
    .unwrap();
    let _ = drain_until(&rx, &bob, "DONE_REV_88", Duration::from_secs(30));

    // Host-side readback: the bytes written from inside the guest must
    // be visible on the host without any explicit sync — virtio-fs /
    // fuse / bwrap-bind all give us coherent shared storage.
    let host_path = bob_host.join("note.txt");
    let read = std::fs::read_to_string(&host_path).unwrap_or_default();
    assert!(
        read.contains(SENTINEL),
        "host did not see guest write at {host_path:?}, got {read:?}"
    );

    sb.remove_user("bob").ok();
    sb.stop_vm().ok();
}

// =========================================================================
// PTY tests (PROTOCOL_VERSION 4)
// =========================================================================

/// Byte-exact drain. Collects raw stdout bytes for `target` until either
/// `needle` (as bytes) appears or the timeout elapses.
fn drain_bytes_until(rx: &Receiver<Event>, target: &JobId, needle: &[u8], timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Event::Stdout { id, data }) if &id == target => {
                buf.extend_from_slice(&data);
                if buf.windows(needle.len()).any(|w| w == needle) {
                    return buf;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    buf
}

#[test]
fn pty_shell_reports_correct_size() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-size")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((40, 132)),
            ..Default::default()
        })
        .expect("spawn pty shell");
    sb.write_stdin(&shell, b"stty size\n").expect("write_stdin");

    let captured = drain_until_for_id(&rx, &shell, "40 132", Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(captured.contains("40 132"), "stty size missing '40 132': {captured:?}");
}

#[test]
fn pty_shell_resize_propagates() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-resize")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((24, 80)),
            ..Default::default()
        })
        .expect("spawn pty shell");
    sb.write_stdin(&shell, b"stty size\n").unwrap();
    let first = drain_until_for_id(&rx, &shell, "24 80", Duration::from_secs(15));
    assert!(first.contains("24 80"), "initial stty size missing '24 80': {first:?}");

    sb.resize_shell(&shell, 50, 120).expect("resize_shell");
    sb.write_stdin(&shell, b"stty size\n").unwrap();
    let second = drain_until_for_id(&rx, &shell, "50 120", Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(
        second.contains("50 120"),
        "post-resize stty size missing '50 120': {second:?}"
    );
}

#[test]
fn pty_shell_ctrl_c_does_not_kill_shell() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-ctrlc")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((24, 80)),
            ..Default::default()
        })
        .expect("spawn pty shell");

    // Park the shell in a long sleep, then deliver Ctrl-C as a slave-side
    // byte. In a PTY the line discipline turns this into SIGINT delivered
    // ONLY to the foreground process group (sleep), not the shell itself.
    sb.write_stdin(&shell, b"sleep 60\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    sb.write_stdin(&shell, b"\x03").unwrap();

    sb.write_stdin(&shell, b"echo ALIVE\n").unwrap();
    let captured = drain_until_for_id(&rx, &shell, "ALIVE", Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(
        captured.contains("ALIVE"),
        "shell unresponsive after Ctrl-C — slave-side ^C must NOT kill the shell. captured: {captured:?}"
    );
}

#[test]
fn pty_shell_color_escape_codes_pass_through() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-color")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((24, 80)),
            ..Default::default()
        })
        .expect("spawn pty shell");
    sb.write_stdin(&shell, b"printf '\\e[31mRED\\e[0m\\n'\n").unwrap();

    let needle: &[u8] = b"\x1b[31mRED\x1b[0m";
    let captured = drain_bytes_until(&rx, &shell, needle, Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(
        captured.windows(needle.len()).any(|w| w == needle),
        "color escape sequence missing — captured bytes: {:?}",
        String::from_utf8_lossy(&captured)
    );
}

// ---------------------------------------------------------------------------
// Session sharing — `SharedBackend` registry semantics
// ---------------------------------------------------------------------------
//
// These tests verify that two `Sandbox::connect()` handles that supply
// the same `session_id` end up driving the **same** VM, mirroring the
// Windows service's behaviour on Linux/macOS via the in-process
// registry.  See `src/shared_backend.rs`.

#[test]
fn shared_session_two_handles_see_same_shell() {
    let cfg = config("share_same");

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg.clone()).expect("configure 1");
    sb1.start_vm().expect("start_vm");
    let shell_a = sb1.shell_id().expect("shell_id 1");

    // Second connect with the same session_id MUST observe the running
    // VM and return the same boot-shell JobId.
    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg.clone()).expect("configure 2 idempotent");
    assert!(sb2.is_running().expect("is_running 2"));
    let shell_b = sb2.shell_id().expect("shell_id 2");
    assert_eq!(shell_a, shell_b, "same session_id must share the boot shell");

    // start_vm on the second handle must also be idempotent.
    sb2.start_vm().expect("start_vm 2 idempotent");

    sb1.stop_vm().expect("stop_vm");
    // After teardown, the second handle observes the VM as not running.
    assert!(!sb2.is_running().unwrap_or(true));
}

#[test]
fn shared_session_writes_visible_via_other_handle() {
    let cfg = config("share_io");

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg.clone()).expect("configure 1");
    let rx = sb1.subscribe().expect("subscribe");
    sb1.start_vm().expect("start_vm");
    let shell = sb1.shell_id().expect("shell_id");

    // Drive stdin from the *second* handle, observe events on the first.
    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg.clone()).expect("configure 2");

    const TOKEN: &str = "SHARED_OK_8E1A";
    sb2.write_stdin(&shell, format!("echo {TOKEN}\n").as_bytes())
        .expect("write_stdin via sb2");

    let captured = drain_until(&rx, &shell, TOKEN, Duration::from_secs(20));
    assert!(
        captured.contains(TOKEN),
        "stdout from shared session not seen, got: {captured:?}"
    );

    sb1.stop_vm().expect("stop_vm");
}

#[test]
fn distinct_session_ids_get_distinct_vms() {
    // Two configs with **different** session_ids → two separate VMs.
    // Proof: writes into VM A only show up on A's event stream; B's
    // stream sees only B's writes.  (JobId values are not a proxy
    // for distinctness — each VM numbers shells locally.)
    let cfg_a = config("distinct_a");
    let cfg_b = config("distinct_b");

    let sb_a = Sandbox::connect().expect("connect a");
    sb_a.configure(cfg_a).expect("configure a");
    let rx_a = sb_a.subscribe().expect("subscribe a");
    sb_a.start_vm().expect("start_vm a");
    let shell_a = sb_a.shell_id().expect("shell_id a");

    let sb_b = Sandbox::connect().expect("connect b");
    sb_b.configure(cfg_b).expect("configure b");
    let rx_b = sb_b.subscribe().expect("subscribe b");
    sb_b.start_vm().expect("start_vm b");
    let shell_b = sb_b.shell_id().expect("shell_id b");

    const TOK_A: &str = "DISTINCT_A_4F1C";
    const TOK_B: &str = "DISTINCT_B_4F1C";
    sb_a.write_stdin(&shell_a, format!("echo {TOK_A}\n").as_bytes())
        .expect("write a");
    sb_b.write_stdin(&shell_b, format!("echo {TOK_B}\n").as_bytes())
        .expect("write b");

    let out_a = drain_until(&rx_a, &shell_a, TOK_A, Duration::from_secs(20));
    let out_b = drain_until(&rx_b, &shell_b, TOK_B, Duration::from_secs(20));
    assert!(out_a.contains(TOK_A) && !out_a.contains(TOK_B), "A leaked B's output");
    assert!(out_b.contains(TOK_B) && !out_b.contains(TOK_A), "B leaked A's output");

    // Stopping A must not affect B.
    sb_a.stop_vm().expect("stop_vm a");
    assert!(
        sb_b.is_running().expect("is_running b after stop a"),
        "stopping VM A must not affect VM B"
    );
    sb_b.stop_vm().expect("stop_vm b");
}

#[test]
fn stop_from_one_handle_tears_down_for_others() {
    let cfg = config("share_stop");

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg.clone()).expect("configure 1");
    sb1.start_vm().expect("start_vm");

    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg.clone()).expect("configure 2");
    assert!(sb2.is_running().expect("is_running 2"));

    // Stop from sb2.
    sb2.stop_vm().expect("stop_vm via sb2");

    // sb1's view is now also "not running".
    assert!(!sb1.is_running().unwrap_or(true), "stop must affect all handles");
    // shell_id on sb1 should now error (VmNotRunning).
    assert!(sb1.shell_id().is_err(), "shell_id after shared stop must error");
}

#[test]
fn empty_session_id_is_not_shared() {
    // Empty session_id → untracked, fresh backend per handle. Two
    // such handles must NOT share a VM.  Proof: writes are isolated
    // to each handle's event stream.
    let mut cfg_a = config("empty_a");
    cfg_a.session_id = String::new();
    let mut cfg_b = config("empty_b");
    cfg_b.session_id = String::new();

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg_a).expect("configure 1");
    let rx1 = sb1.subscribe().expect("subscribe 1");
    sb1.start_vm().expect("start_vm 1");
    let shell_1 = sb1.shell_id().expect("shell_id 1");

    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg_b).expect("configure 2");
    let rx2 = sb2.subscribe().expect("subscribe 2");
    sb2.start_vm().expect("start_vm 2");
    let shell_2 = sb2.shell_id().expect("shell_id 2");

    const TOK1: &str = "EMPTY_ONE_DA32";
    const TOK2: &str = "EMPTY_TWO_DA32";
    sb1.write_stdin(&shell_1, format!("echo {TOK1}\n").as_bytes()).unwrap();
    sb2.write_stdin(&shell_2, format!("echo {TOK2}\n").as_bytes()).unwrap();

    let o1 = drain_until(&rx1, &shell_1, TOK1, Duration::from_secs(20));
    let o2 = drain_until(&rx2, &shell_2, TOK2, Duration::from_secs(20));
    assert!(o1.contains(TOK1) && !o1.contains(TOK2), "VM1 saw VM2 output");
    assert!(o2.contains(TOK2) && !o2.contains(TOK1), "VM2 saw VM1 output");

    sb1.stop_vm().ok();
    sb2.stop_vm().ok();
}

// ---------------------------------------------------------------------------
// macOS: dynamic NFS-backed mount → guest writes visible on the host.
// ---------------------------------------------------------------------------
//
// On macOS, `add_mount` registers the host directory with the in-process
// NFSv3 server (see src/macos/nfs.rs) and asks the guest to mount it via
// the smoltcp gateway. This is the bidirectional replacement for the old
// virtio-fs APFS-clone hack.

#[test]
#[cfg(target_os = "macos")]
fn nfs_dynamic_mount_writes_to_host() {
    const SENTINEL: &str = "NFS_DYN_WROTE_F19C";

    let label = "nfs-dyn";
    let host = workspace_dir(&format!("{label}-share"));
    let _ = std::fs::remove_file(host.join("hello.txt"));

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");

    sb.add_mount(Mount {
        name: "share1".into(),
        host_path: host.clone(),
        guest_path: "/mnt/share1".into(),
        read_only: false,
        create_host_dir: true,
    })
    .expect("add_mount");

    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(
        &shell,
        format!("echo {SENTINEL} > /mnt/share1/hello.txt; echo NFS_DONE_4F8\n").as_bytes(),
    )
    .unwrap();
    let _ = drain_until(&rx, &shell, "NFS_DONE_4F8", Duration::from_secs(30));

    let read = std::fs::read_to_string(host.join("hello.txt")).unwrap_or_default();
    assert!(
        read.contains(SENTINEL),
        "host did not see guest write through NFS mount: got {read:?}"
    );

    sb.remove_mount("share1").ok();
    sb.stop_vm().ok();
}
