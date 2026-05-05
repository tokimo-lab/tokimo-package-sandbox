mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, drain_until_for_id, host_has_ipv6};
use tokimo_package_sandbox::{NetworkPolicy, Sandbox, ShellOpts};

// User-reported repro: `curl -6 www.baidu.com` 10 times with 1-2 s
// between, observed to truncate output mid-stream and hang the shell
// after a handful of iterations. This test reproduces the exact human
// invocation rather than going via /dev/tcp, in case the bug is in
// how curl interacts with the netstack or pty.
#[test]
fn network_allow_all_curl_v6_baidu_loop() {
    let mut cfg = config("net-curl-v6-baidu");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping");
        return;
    }

    // Confirm curl exists in the rootfs first; otherwise the test is a
    // no-op (we'd be measuring `command not found` not the real path).
    sb.write_stdin(
        &shell,
        b"command -v curl >/dev/null && echo CURL_OK || echo CURL_MISSING\necho CURL_PROBE_END\n",
    )
    .unwrap();
    let curl_check = drain_until(&rx, &shell, "CURL_PROBE_END", Duration::from_secs(15));
    if !curl_check.contains("CURL_OK") {
        eprintln!("curl not in rootfs (got: {curl_check:?}), skipping");
        return;
    }

    // Loop: 10 sequential `curl -6 www.baidu.com -s -o /dev/null -w
    // "ITER=$i HTTP=%{http_code} BYTES=%{size_download}\n"`. We pause
    // 1.5 s between to mimic the human cadence.
    let probe = b"for i in 1 2 3 4 5 6 7 8 9 10; do \
	timeout 20 curl -6 -s -o /dev/null \
	-w \"ITER=$i HTTP=%{http_code} BYTES=%{size_download}\\n\" \
	http://www.baidu.com/ || echo \"ITER=$i CURL_FAIL=$?\"; \
	sleep 1; \
	done; echo CURL_LOOP_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    let out = drain_until(&rx, &shell, "CURL_LOOP_END", Duration::from_secs(240));
    sb.stop_vm().ok();
    eprintln!("=== CURL v6 BAIDU LOOP OUTPUT ===\n{out}\n=== END ===");
    assert!(
        out.contains("CURL_LOOP_END"),
        "shell hung before reaching loop end marker: {out:?}"
    );
    let success = out
        .lines()
        .filter(|l| l.contains("HTTP=") && !l.contains("HTTP=000"))
        .count();
    assert!(
        success >= 8,
        "expected >=8 successful curl iterations, got {success}: {out:?}"
    );
}

// User-reported repro #2: same as curl_v6_baidu_loop but uses a PTY shell
// AND lets curl print the FULL ~640KB Baidu home page to stdout (no
// `-s -o /dev/null`). 30 iterations with 2s sleep. This stresses the
// init→host stdout streaming path under sustained large bursts, which
// is what the human repro actually does (curl in a Terminal app PTY,
// no output redirection). The user reports the sandbox occasionally
// "freezes" after one of these curls, after which `spawn_shell` on a
// new shell returns "init connection closed before reply".
#[test]
fn network_allow_all_curl_v6_baidu_pty_full_output() {
    let mut cfg = config("net-curl-v6-baidu-pty");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping");
        return;
    }

    // Spawn a real PTY shell (mirroring the human-facing terminal),
    // not the default pipes shell.
    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((40, 132)),
            ..Default::default()
        })
        .expect("spawn pty shell");

    // Confirm curl is present.
    sb.write_stdin(
        &shell,
        b"command -v curl >/dev/null && echo CURL_OK || echo CURL_MISSING\necho CURL_PROBE_END\n",
    )
    .unwrap();
    let curl_check = drain_until_for_id(&rx, &shell, "CURL_PROBE_END", Duration::from_secs(15));
    if !curl_check.contains("CURL_OK") {
        eprintln!("curl not in rootfs (got: {curl_check:?}), skipping");
        sb.close_shell(&shell).ok();
        return;
    }

    // Disable PTY echo — we drain output by needle, and an echoed command
    // line containing the needle would falsely complete drain_until early.
    // Two writes so stty -echo has actually applied before we write the
    // marker (otherwise the input echo of "ECHO_OFF" matches the needle
    // before stty takes effect).
    sb.write_stdin(&shell, b"stty -echo\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    sb.write_stdin(&shell, b"echo ECHO_OFF_NOW\n").unwrap();
    drain_until_for_id(&rx, &shell, "ECHO_OFF_NOW", Duration::from_secs(5));

    // 30 iterations, FULL OUTPUT (no -s -o /dev/null), 2s pause between.
    // Add an inline echo of size after each curl so we can count
    // successes (curl exits 0 on a complete fetch).
    let probe = b"for i in $(seq 1 30); do \
	timeout 30 curl -6 http://www.baidu.com/ > /tmp/out_$i 2>/dev/null && \
	printf \"ITER=%s OK BYTES=%s\\n\" \"$i\" \"$(wc -c < /tmp/out_$i)\" || \
	printf \"ITER=%s FAIL=%s\\n\" \"$i\" \"$?\"; \
	cat /tmp/out_$i; rm -f /tmp/out_$i; \
	sleep 2; \
	done; echo CURL_PTY_LOOP_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    // Generous timeout: 30 * (curl ~2s + sleep 2s) ≈ 120s + slack.
    let out = drain_until_for_id(&rx, &shell, "CURL_PTY_LOOP_END", Duration::from_secs(360));

    // Surface diagnostics regardless of pass/fail.
    let success = out
        .lines()
        .filter(|l| l.contains("OK BYTES=") && !l.contains("BYTES=0"))
        .count();
    let fail = out.lines().filter(|l| l.contains("FAIL=")).count();
    eprintln!(
        "=== CURL v6 BAIDU PTY FULL-OUTPUT LOOP === successes={success} failures={fail} reached_end={}",
        out.contains("CURL_PTY_LOOP_END")
    );

    // Try a control command on the SAME pty after the loop, to
    // detect mid-test sandbox hang. If init has died, this echo will
    // never come back (test will already have failed at drain_until).
    sb.write_stdin(&shell, b"echo POST_LOOP_PROBE\n").unwrap();
    let post = drain_until_for_id(&rx, &shell, "POST_LOOP_PROBE", Duration::from_secs(10));

    // Also probe whether spawning a NEW shell still works — this is the
    // exact failure mode the user reports ("init connection closed
    // before reply" on a brand-new spawn_shell call after a heavy v6
    // curl session).
    let new_shell_result = sb.spawn_shell(ShellOpts::default());

    sb.close_shell(&shell).ok();
    if let Ok(ns) = &new_shell_result {
        sb.close_shell(ns).ok();
    }
    sb.stop_vm().ok();

    assert!(
        out.contains("CURL_PTY_LOOP_END"),
        "shell hung mid-loop (no end marker): successes={success}, last 2KB of output:\n{}",
        &out[out.len().saturating_sub(2048)..]
    );
    assert!(
        post.contains("POST_LOOP_PROBE"),
        "post-loop probe never echoed — pty stuck: {post:?}"
    );
    assert!(
        new_shell_result.is_ok(),
        "spawn_shell on a fresh shell after heavy v6 curl loop failed (this IS the user-reported regression): {:?}",
        new_shell_result.err()
    );
    assert!(
        success >= 25,
        "expected >=25 successful curl iterations out of 30, got {success} (failures={fail})\nfull output tail:\n{}",
        &out[out.len().saturating_sub(4096)..]
    );
}

// ---------------------------------------------------------------------------
// HTTPS throughput — verify the smoltcp netstack can carry a real HTTPS
// download end-to-end, 10 times in series.
//
// Uses `curl` inside the sandbox to download a small, stable HTTPS resource
// and checks:
//   - HTTP status 200
//   - total time < 5 seconds per run
//   - at least 1 KiB transferred (body is not empty)
//
// Marked #[ignore] because it requires outbound internet access from the CI
// runner. Run manually:
//   PATH="$PWD/target/debug:$PATH" cargo test --test sandbox_integration \
//     netstack_https_throughput -- --ignored --test-threads=1 --nocapture
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn netstack_https_throughput() {
    const RUNS: usize = 10;
    const END: &str = "HTTPS_THRU_DONE_7E3C";
    // Baidu: domestic CDN, low-latency from CN networks; if this is slow,
    // it indicates a real netstack throughput bug rather than upstream RTT.
    const URL: &str = "https://www.baidu.com/";

    let mut cfg = config("net-https-thru");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    for run in 1..=RUNS {
        let sentinel = format!("{END}_{run}");
        // curl -s: silent, -L: follow redirects, -w: write status + time + size
        // to stdout after the body, -o /dev/null: discard body.
        let cmd = format!(
            "curl -4 -s -L -w '\\nHTTPS_CODE=%{{http_code}} HTTPS_TIME=%{{time_total}} HTTPS_SIZE=%{{size_download}} HTTPS_DNS=%{{time_namelookup}} HTTPS_CONN=%{{time_connect}} HTTPS_TLS=%{{time_appconnect}} HTTPS_TTFB=%{{time_starttransfer}}\\n' \
             -o /dev/null '{URL}'; echo {sentinel}\n"
        );
        sb.write_stdin(&shell, cmd.as_bytes()).expect("write_stdin");
        let out = drain_until(&rx, &shell, &sentinel, Duration::from_secs(30));

        // Parse the curl write-out line.
        let stat_line = out
            .lines()
            .find(|l| l.contains("HTTPS_CODE="))
            .unwrap_or_else(|| panic!("run {run}: no HTTPS_CODE line in output:\n{out}"));

        let http_code: u32 = stat_line
            .split("HTTPS_CODE=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let time_secs: f64 = stat_line
            .split("HTTPS_TIME=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(f64::MAX);

        let size_bytes: u64 = stat_line
            .split("HTTPS_SIZE=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let parse_field = |key: &str| -> f64 {
            stat_line
                .split(key)
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(f64::NAN)
        };
        let dns = parse_field("HTTPS_DNS=");
        let conn = parse_field("HTTPS_CONN=");
        let tls = parse_field("HTTPS_TLS=");
        let ttfb = parse_field("HTTPS_TTFB=");
        eprintln!(
            "[https-thru] run {run}: code={http_code} total={time_secs:.3}s size={size_bytes} dns={dns:.3} conn={conn:.3} tls={tls:.3} ttfb={ttfb:.3}"
        );

        assert_eq!(
            http_code, 200,
            "run {run}: expected HTTP 200, got {http_code}. curl output:\n{out}"
        );
        assert!(
            time_secs < 5.0,
            "run {run}: request took {time_secs:.3}s, expected < 5s. curl output:\n{out}"
        );
        assert!(
            size_bytes >= 128,
            "run {run}: only {size_bytes} bytes received, expected ≥ 128. curl output:\n{out}"
        );
    }

    sb.stop_vm().ok();
}
