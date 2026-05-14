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

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::{NetworkPolicy, Sandbox};

const PROBE_END: &str = "K6DIAG_PROBE_END_8F2A";

const K6_VERSION: &str = "v0.55.0";
const K6_URL: &str = "https://github.com/grafana/k6/releases/download/v0.55.0/k6-v0.55.0-linux-amd64.tar.gz";
const K6_DIR_IN_TARBALL: &str = "k6-v0.55.0-linux-amd64";

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

/// End-to-end regression test for the real k6 workload that originally
/// surfaced the smoltcp UDP-by-dst_port collapse bug.
///
/// User script: 5 VUs / 5s / GET https://www.baidu.com / sleep(1).
/// Before the fix: http_req_duration avg ~16ms but iteration_duration
/// avg ~6.06s, because 4 of 5 concurrent DNS lookups timed out at
/// glibc's resolver retry budget. After the fix: iterations should
/// complete in roughly sleep(1) + network overhead.
///
/// k6 itself is not in the rootfs; this test downloads the official
/// linux-amd64 release tarball once into `target/integration/k6-cache/`
/// and reuses it on subsequent runs. The cached binary is copied into
/// the host-side workspace (mounted at `/tmp/tokimo-share` inside the
/// VM) so the guest can execute it.
#[test]
fn k6_real_regression() {
    let ws = workspace_dir("k6-real");
    let k6_host = ensure_k6_binary().expect("provision k6 binary");

    // Stage k6 + script in the shared workspace so the guest can see them.
    std::fs::copy(&k6_host, ws.join("k6")).expect("copy k6 into workspace");
    let script = r#"import http from 'k6/http';
import { sleep, check } from 'k6';
export const options = {
  vus: 5,
  duration: '5s',
  thresholds: {
    http_req_duration: ['p(95)<5000'],
    http_req_failed: ['rate<0.05'],
  },
};
export default function () {
  const res = http.get('https://www.baidu.com');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'duration < 3s': (r) => r.timings.duration < 3000,
  });
  sleep(1);
}
"#;
    std::fs::write(ws.join("k6-test.js"), script).expect("write k6 script");
    // Wipe any stale summary so we don't accidentally validate the previous run.
    let _ = std::fs::remove_file(ws.join("k6-summary.json"));

    let mut cfg = config("k6-real");
    cfg.cpu_count = 8;
    cfg.memory_mb = 2048;
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Run k6. --quiet keeps stdout small; the summary JSON is the
    // authoritative source of truth for assertions.
    let cmd = format!(
        "chmod +x /tmp/tokimo-share/k6 && \
         /tmp/tokimo-share/k6 run --quiet \
           --summary-export=/tmp/tokimo-share/k6-summary.json \
           /tmp/tokimo-share/k6-test.js; \
         echo K6_EXIT=$?; echo {PROBE_END}_K6\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    // Generous timeout: k6 runs for 5s + setup/teardown. Allow 60s.
    let out = drain_until(&rx, &shell, &format!("{PROBE_END}_K6"), Duration::from_secs(60));
    eprintln!("=== k6 stdout/stderr ===\n{out}\n");

    let exit_line = out
        .lines()
        .find_map(|l| l.trim().strip_prefix("K6_EXIT="))
        .unwrap_or("");
    let summary_path = ws.join("k6-summary.json");
    let summary_raw = std::fs::read_to_string(&summary_path).unwrap_or_else(|e| {
        sb.stop_vm().ok();
        panic!(
            "failed to read k6 summary {}: {e}.\nk6 exit code line: {exit_line:?}\nk6 stdout:\n{out}",
            summary_path.display()
        );
    });
    let summary: serde_json::Value = serde_json::from_str(&summary_raw)
        .unwrap_or_else(|e| panic!("parse k6 summary JSON: {e}\nraw:\n{summary_raw}"));

    let metrics = &summary["metrics"];
    // Note: `--summary-export` uses a flatter legacy schema than the
    // newer `summary.json`. Metric fields live directly on the metric
    // object (not nested under a `values` map). For rate metrics like
    // `http_req_failed`, the rate is exposed as `value` (with `passes`
    // counting the "true" cases — i.e. failed requests — and `fails`
    // counting the "false" cases). Durations are reported in ms.
    let http_req_failed_rate = metrics["http_req_failed"]["value"].as_f64().unwrap_or(f64::NAN);
    let http_req_duration_p95 = metrics["http_req_duration"]["p(95)"].as_f64().unwrap_or(f64::NAN);
    let iteration_duration_avg = metrics["iteration_duration"]["avg"].as_f64().unwrap_or(f64::NAN);
    let iterations_count = metrics["iterations"]["count"].as_f64().unwrap_or(f64::NAN);

    eprintln!(
        "=== k6 key metrics ===\n  http_req_failed.rate       = {http_req_failed_rate:.4}\n  http_req_duration.p(95)    = {http_req_duration_p95:.1} ms\n  iteration_duration.avg     = {iteration_duration_avg:.1} ms\n  iterations.count           = {iterations_count}\n"
    );

    sb.stop_vm().ok();

    assert_eq!(exit_line, "0", "k6 exited non-zero: {exit_line:?}\nstdout:\n{out}");
    assert!(
        http_req_failed_rate < 0.05,
        "http_req_failed.rate = {http_req_failed_rate:.4}, expected < 0.05. Indicates request failures (regression of DNS demux fix?)."
    );
    assert!(
        iteration_duration_avg < 1500.0,
        "iteration_duration.avg = {iteration_duration_avg:.1}ms, expected < 1500ms. \
         Bug signature: iterations stretched to ~6000ms because concurrent DNS lookups starved each other. \
         http_req_duration.p95 = {http_req_duration_p95:.1}ms, http_req_failed.rate = {http_req_failed_rate:.4}, iterations = {iterations_count}."
    );
    assert!(
        http_req_duration_p95 < 5000.0,
        "http_req_duration.p(95) = {http_req_duration_p95:.1}ms, expected < 5000ms (k6 threshold)."
    );
    assert!(
        iterations_count > 10.0,
        "iterations.count = {iterations_count}, expected > 10. \
         5 VUs × 5s with sleep(1) should yield ~20 iterations; the bug capped it at 5 because each VU hung for ~5s on DNS."
    );
}

/// Throughput benchmark with NO `sleep()` between iterations.
///
/// Same shape as `k6_real_regression` (5 VUs, 5s, GET baidu) but the
/// k6 script omits `sleep(1)`, so each VU loops as fast as the network
/// allows. The goal is to *measure* raw end-to-end RPS the sandbox
/// netstack can sustain — NOT to assert a floor (baidu rate-limits
/// aggressively, and the failure rate is itself part of the reported
/// number).
///
/// `#[ignore]` because:
///  - depends on external internet (baidu)
///  - baidu rate-limiting means absolute numbers vary run-to-run
///  - it's a one-shot diagnostic, not a regression guard
#[test]
#[ignore]
fn k6_no_sleep_throughput() {
    let ws = workspace_dir("k6-nosleep");
    let k6_host = ensure_k6_binary().expect("provision k6 binary");

    std::fs::copy(&k6_host, ws.join("k6")).expect("copy k6 into workspace");
    let script = r#"import http from 'k6/http';
import { check } from 'k6';
export const options = {
  vus: 5,
  duration: '5s',
};
export default function () {
  const res = http.get('https://www.baidu.com');
  check(res, { 'status 200': (r) => r.status === 200 });
  // NO sleep
}
"#;
    std::fs::write(ws.join("k6-test.js"), script).expect("write k6 script");
    let _ = std::fs::remove_file(ws.join("k6-summary.json"));

    let mut cfg = config("k6-nosleep");
    cfg.cpu_count = 8;
    cfg.memory_mb = 2048;
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let cmd = format!(
        "chmod +x /tmp/tokimo-share/k6 && \
         /tmp/tokimo-share/k6 run --quiet \
           --summary-export=/tmp/tokimo-share/k6-summary.json \
           /tmp/tokimo-share/k6-test.js; \
         echo K6_EXIT=$?; echo {PROBE_END}_K6NS\n"
    );
    sb.write_stdin(&shell, cmd.as_bytes()).unwrap();
    let out = drain_until(&rx, &shell, &format!("{PROBE_END}_K6NS"), Duration::from_secs(60));
    eprintln!("=== k6 stdout/stderr ===\n{out}\n");

    let summary_path = ws.join("k6-summary.json");
    let summary_raw = std::fs::read_to_string(&summary_path).unwrap_or_else(|e| {
        sb.stop_vm().ok();
        panic!(
            "failed to read k6 summary {}: {e}.\nk6 stdout:\n{out}",
            summary_path.display()
        );
    });
    let summary: serde_json::Value = serde_json::from_str(&summary_raw)
        .unwrap_or_else(|e| panic!("parse k6 summary JSON: {e}\nraw:\n{summary_raw}"));

    let m = &summary["metrics"];
    // `--summary-export` legacy flat schema: metric fields live on the
    // metric object directly (not under `.values`). Durations are in ms,
    // rates are per-second.
    let iterations_count = m["iterations"]["count"].as_f64().unwrap_or(f64::NAN);
    let iterations_rate = m["iterations"]["rate"].as_f64().unwrap_or(f64::NAN);
    let http_reqs_count = m["http_reqs"]["count"].as_f64().unwrap_or(f64::NAN);
    let http_reqs_rate = m["http_reqs"]["rate"].as_f64().unwrap_or(f64::NAN);
    let http_req_failed_rate = m["http_req_failed"]["value"].as_f64().unwrap_or(f64::NAN);
    let http_req_failed_passes = m["http_req_failed"]["passes"].as_f64().unwrap_or(f64::NAN);
    let http_req_failed_fails = m["http_req_failed"]["fails"].as_f64().unwrap_or(f64::NAN);
    let dur_avg = m["http_req_duration"]["avg"].as_f64().unwrap_or(f64::NAN);
    let dur_p95 = m["http_req_duration"]["p(95)"].as_f64().unwrap_or(f64::NAN);
    let dur_max = m["http_req_duration"]["max"].as_f64().unwrap_or(f64::NAN);
    let iter_dur_avg = m["iteration_duration"]["avg"].as_f64().unwrap_or(f64::NAN);
    let connecting_avg = m["http_req_connecting"]["avg"].as_f64().unwrap_or(f64::NAN);
    let tls_avg = m["http_req_tls_handshaking"]["avg"].as_f64().unwrap_or(f64::NAN);

    eprintln!(
        "=== k6 no-sleep throughput ===\n\
         iterations.count            = {iterations_count}\n\
         iterations.rate             = {iterations_rate:.3} /s\n\
         http_reqs.count             = {http_reqs_count}\n\
         http_reqs.rate              = {http_reqs_rate:.3} /s   (avg RPS)\n\
         http_req_failed.rate        = {http_req_failed_rate:.4}   (passes={http_req_failed_passes}, fails={http_req_failed_fails})\n\
         http_req_duration.avg       = {dur_avg:.2} ms\n\
         http_req_duration.p(95)     = {dur_p95:.2} ms\n\
         http_req_duration.max       = {dur_max:.2} ms\n\
         iteration_duration.avg      = {iter_dur_avg:.2} ms   (≈ http_req_duration when no sleep)\n\
         http_req_connecting.avg     = {connecting_avg:.2} ms   (TCP)\n\
         http_req_tls_handshaking.avg= {tls_avg:.2} ms   (TLS)\n"
    );

    sb.stop_vm().ok();

    // Only assert we actually ran. No throughput floor — baidu's rate
    // limiter makes absolute numbers unreliable. No http_req_failed
    // assertion for the same reason.
    assert!(
        iterations_count > 0.0,
        "iterations.count = {iterations_count}, expected > 0 (test didn't run)"
    );
}

/// Ensures the k6 amd64 binary exists under `target/integration/k6-cache/`
/// and returns its host path. Downloads + extracts on first run, no-ops
/// on subsequent runs.
fn ensure_k6_binary() -> anyhow::Result<PathBuf> {
    let cache_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("integration")
        .join("k6-cache");
    std::fs::create_dir_all(&cache_root)?;
    let k6_path = cache_root.join("k6");
    if k6_path.exists()
        && std::fs::metadata(&k6_path)
            .map(|m| m.len() > 1_000_000)
            .unwrap_or(false)
    {
        eprintln!("[k6] using cached binary: {}", k6_path.display());
        return Ok(k6_path);
    }

    eprintln!("[k6] downloading {K6_VERSION} from {K6_URL}");
    let body = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?
        .get(K6_URL)
        .send()?
        .error_for_status()?
        .bytes()?;
    eprintln!("[k6] downloaded {} bytes, extracting", body.len());

    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(body));
    let mut archive = tar::Archive::new(gz);
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let want = Path::new(K6_DIR_IN_TARBALL).join("k6");
        if path == want {
            entry.unpack(&k6_path)?;
            found = true;
            break;
        }
    }
    if !found {
        anyhow::bail!("k6 binary not found in tarball entry {K6_DIR_IN_TARBALL}/k6");
    }
    eprintln!("[k6] extracted to {}", k6_path.display());
    Ok(k6_path)
}
