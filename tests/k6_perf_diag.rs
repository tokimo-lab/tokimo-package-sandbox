//! Diagnostic test for the "k6 inside sandbox is slow" report.
//!
//! User scenario (reproduced from their k6 script):
//!   - 5 VUs, 5s duration, https://www.baidu.com per iter, sleep(1) between.
//!   - Observed: http_req_duration avg = 16ms (fast network!)
//!     but iteration_duration avg = 6.06s.
//!   - i.e. ~5s of unexplained per-iter overhead that is NOT network.
//!
//! The existing `netstack_https_throughput` test already proved that an
//! in-sandbox `curl` to baidu costs ~80ms total (DNS+TCP+TLS+req combined),
//! so the bottleneck is NOT the network.
//!
//! This test characterises the *non-network* per-iter cost in the sandbox:
//!   1. nproc / cpuinfo            — vCPU count actually seen by guest
//!   2. `time sleep 1` × 5         — VM clock fidelity (does sleep(1) really
//!      take ~1s, or is it being throttled?)
//!   3. Serial curl loop (5×)      — pure sequential curl wall time
//!   4. Concurrent curl burst (5×) — 5 parallel curl, mimicking 5 VUs
//!   5. CPU micro-bench            — md5sum of 100MB /dev/zero (CPU only)
//!
//! Runs with the SAME VM resource config the user's prod sandbox uses
//! (cpu_count=8, memory=1024MB sufficient) so the diagnosis matches reality.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::{NetworkPolicy, Sandbox};

const PROBE_END: &str = "K6DIAG_PROBE_END_8F2A";

#[test]
#[ignore]
fn k6_slow_iteration_diag() {
    // Match prod-ish resources so the diagnosis is representative.
    let mut cfg = config("k6-perf-diag");
    cfg.cpu_count = 8;
    cfg.memory_mb = 2048;
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // ---- 1. vCPU and kernel info ----
    let cmd = format!(
        "echo '--- CPU INFO ---'; nproc; grep -c ^processor /proc/cpuinfo; uname -r; cat /proc/cpuinfo | grep -m1 'model name'; echo '--- BOGOMIPS ---'; grep -m1 bogomips /proc/cpuinfo; echo {PROBE_END}_CPU\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let cpu_out = drain_until(&rx, &shell, &format!("{PROBE_END}_CPU"), Duration::from_secs(15));
    eprintln!("=== [1] CPU / KERNEL ===\n{cpu_out}\n");

    // ---- 2. Clock fidelity: time sleep 1 × 5 ----
    let cmd = format!(
        "echo '--- SLEEP FIDELITY ---'; for i in 1 2 3 4 5; do /usr/bin/time -f 'sleep1_real=%e' sleep 1 2>&1; done; echo {PROBE_END}_SLEEP\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let sleep_out = drain_until(&rx, &shell, &format!("{PROBE_END}_SLEEP"), Duration::from_secs(20));
    eprintln!("=== [2] SLEEP FIDELITY (each should be ~1.00s) ===\n{sleep_out}\n");

    // ---- 3. Serial curl × 5 (matches k6 sequential pattern per VU) ----
    let cmd = format!(
        "echo '--- SERIAL CURL ---'; for i in 1 2 3 4 5; do \
         curl -4 -s -o /dev/null -w 'iter=%{{iter_placeholder}} total=%{{time_total}}s dns=%{{time_namelookup}}s conn=%{{time_connect}}s tls=%{{time_appconnect}}s ttfb=%{{time_starttransfer}}s code=%{{http_code}}\\n' \
         https://www.baidu.com/ | sed \"s/iter_placeholder/$i/\"; \
         done; echo {PROBE_END}_SERIAL\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let serial_out = drain_until(&rx, &shell, &format!("{PROBE_END}_SERIAL"), Duration::from_secs(60));
    eprintln!("=== [3] SERIAL CURL × 5 ===\n{serial_out}\n");

    // ---- 4. Concurrent curl × 5 (matches k6 VUs=5 pattern) ----
    //
    // Wall-clock the whole burst. If 5 parallel curls take ~80ms, no
    // contention. If they take 5s, sandbox/network has a concurrency cap.
    let cmd = format!(
        "echo '--- CONCURRENT CURL ---'; t0=$(date +%s.%N); \
         for i in 1 2 3 4 5; do \
           ( curl -4 -s -o /dev/null -w \"par$i total=%{{time_total}}s tls=%{{time_appconnect}}s code=%{{http_code}}\\n\" https://www.baidu.com/ ) & \
         done; wait; t1=$(date +%s.%N); \
         echo \"WALL_CONCURRENT=$(echo \\\"$t1 - $t0\\\" | bc)s\"; \
         echo {PROBE_END}_PARALLEL\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let par_out = drain_until(&rx, &shell, &format!("{PROBE_END}_PARALLEL"), Duration::from_secs(60));
    eprintln!("=== [4] CONCURRENT CURL × 5 ===\n{par_out}\n");

    // ---- 5. CPU micro-bench: md5sum 100MB of /dev/zero ----
    let cmd = format!(
        "echo '--- CPU BENCH ---'; /usr/bin/time -f 'cpu_bench_real=%e cpu_user=%U cpu_sys=%S' bash -c 'dd if=/dev/zero bs=1M count=100 2>/dev/null | md5sum' 2>&1; echo {PROBE_END}_CPU2\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let cpu2_out = drain_until(&rx, &shell, &format!("{PROBE_END}_CPU2"), Duration::from_secs(30));
    eprintln!("=== [5] CPU BENCH (md5 of 100MB) ===\n{cpu2_out}\n");

    // ---- 6. fork/exec overhead: 100x `true` ----
    let cmd = format!(
        "echo '--- FORK/EXEC ---'; /usr/bin/time -f 'fork100_real=%e' bash -c 'for i in $(seq 1 100); do /bin/true; done' 2>&1; echo {PROBE_END}_FORK\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let fork_out = drain_until(&rx, &shell, &format!("{PROBE_END}_FORK"), Duration::from_secs(30));
    eprintln!("=== [6] FORK/EXEC × 100 ===\n{fork_out}\n");

    // Test always passes — we only care about the eprintln! diagnostics.
    sb.stop_vm().ok();
}

/// Regression test for the "concurrent DNS lookups starve each other"
/// bug fixed in `netstack/mod.rs`.
///
/// Before the fix, each `(src_ip, src_port, dst_ip, dst_port)` got its
/// own smoltcp UDP socket — but smoltcp dispatch routes every inbound
/// UDP packet to the *first* socket matching by dst_port only. As a
/// result, 5 parallel guest DNS queries to gateway:53 funnelled into the
/// same smoltcp socket, replies got addressed to whichever guest src last
/// touched `flow.remote`, and 3-4 of the 5 curls timed out at glibc's
/// resolver retry budget (~5s / ~9.78s) reporting `code=000`.
///
/// After the fix: one smoltcp listener per (dst_ip, dst_port), demuxed
/// to per-guest-src sub-flows. All 5 curls succeed in well under 2s.
#[test]
fn concurrent_curl_burst_regression() {
    let mut cfg = config("concurrent-curl-burst");
    cfg.cpu_count = 4;
    cfg.memory_mb = 1024;
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let cmd = format!(
        "for i in 1 2 3 4 5; do \
           ( curl -4 -s -o /dev/null -w \"par$i total=%{{time_total}}s code=%{{http_code}}\\n\" \
             --max-time 4 https://www.baidu.com/ ) & \
         done; wait; echo {PROBE_END}_BURST\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let out = drain_until(&rx, &shell, &format!("{PROBE_END}_BURST"), Duration::from_secs(15));
    eprintln!("=== concurrent_curl_burst output ===\n{out}\n");

    let mut ok = 0usize;
    let mut max_total: f64 = 0.0;
    let mut failures: Vec<String> = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if !line.starts_with("par") {
            continue;
        }
        // Format: "par1 total=0.087s code=200"
        let code = line
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("code="))
            .unwrap_or("");
        let total_str = line
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("total=").and_then(|s| s.strip_suffix('s')))
            .unwrap_or("0");
        let total: f64 = total_str.parse().unwrap_or(0.0);
        if total > max_total {
            max_total = total;
        }
        if code == "200" {
            ok += 1;
        } else {
            failures.push(line.to_string());
        }
    }

    sb.stop_vm().ok();

    assert_eq!(
        ok, 5,
        "expected 5 successful concurrent curls, got {ok}. failures: {failures:?}\nfull output:\n{out}"
    );
    assert!(
        max_total < 2.0,
        "concurrent curls should all finish < 2s; slowest = {max_total:.3}s.\nfull output:\n{out}"
    );
}
