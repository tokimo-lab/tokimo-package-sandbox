//! Linux-only integration tests that replicate the real
//! `tokimo-server::AgentSandbox` configuration shape (peer-aware shared
//! mounts, per-agent RW leaves, skill mounts, observed network policy,
//! `run_oneshot_factory`, and the `wait_with_timeout` + `kill_job` safety
//! path).
//!
//! These tests use `SystemLayout::CallerProvided` and require a real Debian
//! rootfs available via the `TOKIMO_TEST_ROOTFS` environment variable.
//! Without it, every test prints a SKIP line and returns `Ok(())` so local
//! runs do not fail.
//!
//! ```bash
//! TOKIMO_TEST_ROOTFS=/path/to/rootfs cargo test --test agent_sandbox_replica
//! ```

#![cfg(target_os = "linux")]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{
    Mount, NetEvent, NetEventSink, NetworkPolicy, SandboxConfig, Session, SystemLayout, Verdict,
};

mod common;

type TestResult = Result<(), Box<dyn Error>>;

// ---------------------------------------------------------------------------
// Rootfs lookup + skip plumbing
// ---------------------------------------------------------------------------

/// Returns the rootfs path if `TOKIMO_TEST_ROOTFS` is set and points to a
/// directory containing at least `usr/bin/bash` (or `bin/bash`).
fn find_test_rootfs() -> Option<PathBuf> {
    let raw = std::env::var("TOKIMO_TEST_ROOTFS").ok()?;
    let p = PathBuf::from(raw);
    if !p.is_dir() {
        return None;
    }
    let bash_a = p.join("bin").join("bash");
    let bash_b = p.join("usr").join("bin").join("bash");
    if !bash_a.exists() && !bash_b.exists() {
        return None;
    }
    Some(p)
}

/// Standard set of read-only system mounts derived from a rootfs. Only paths
/// that exist on the host (rootfs side) are emitted, so missing top-level
/// symlinks (Debian-style `/bin` → `/usr/bin`) do not cause validation
/// failure.
fn rootfs_system_mounts(rootfs: &Path) -> Vec<Mount> {
    ["bin", "sbin", "lib", "lib64", "usr", "etc", "var"]
        .iter()
        .filter_map(|seg| {
            let host = rootfs.join(seg);
            if host.exists() {
                Some(Mount::ro(host).guest(format!("/{seg}")))
            } else {
                None
            }
        })
        .collect()
}

/// Gate every test with a uniform skip path. Returns `None` if the test
/// should silently skip; `Some(rootfs)` otherwise.
fn gate(test_name: &str) -> Option<PathBuf> {
    if !common::is_linux() {
        println!("SKIP {test_name}: not Linux");
        return None;
    }
    if !common::has_bwrap() {
        println!("SKIP {test_name}: bwrap not installed");
        return None;
    }
    match find_test_rootfs() {
        Some(r) => Some(r),
        None => {
            println!("SKIP {test_name}: TOKIMO_TEST_ROOTFS not set (or rootfs invalid; missing bash)");
            None
        }
    }
}

/// Holder for paths that must outlive the Session.
struct RootHost {
    _root: tempfile::TempDir,
    base: PathBuf,
}

impl RootHost {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let base = root.path().to_path_buf();
        Self { _root: root, base }
    }

    fn make_dir(&self, rel: &str) -> PathBuf {
        let p = self.base.join(rel);
        std::fs::create_dir_all(&p).expect("create_dir_all");
        p
    }
}

// ---------------------------------------------------------------------------
// Test 1: peer mounts visibility + isolation (≥ 33 mounts)
// ---------------------------------------------------------------------------

#[test]
fn peer_mounts_visibility_and_isolation() -> TestResult {
    let Some(rootfs) = gate("peer_mounts_visibility_and_isolation") else {
        return Ok(());
    };
    let host = RootHost::new();

    // Self leaves.
    let self_workspace = host.make_dir("self/workspace");
    let self_tmp = host.make_dir("self/tmp");
    let self_upload = host.make_dir("self/upload");
    let self_output = host.make_dir("self/output");

    // Shared markers.
    let shared_root_marker = host.make_dir("shared_root");
    let shared_ro_marker = host.make_dir("shared_ro");
    for sub in ["home/workspace", "tmp", "upload", "output"] {
        std::fs::create_dir_all(shared_ro_marker.join(sub))?;
    }

    // Skills.
    let user_skills = host.make_dir("user_skills");
    let builtin_skills = host.make_dir("builtin_skills");

    // Pre-seed a marker file in the builtin skills dir so the RO assertion is
    // meaningful (we read it from inside the sandbox).
    std::fs::write(builtin_skills.join("BUILTIN.md"), b"hello-builtin")?;

    let self_name = "self";
    std::fs::create_dir_all(shared_root_marker.join(self_name))?;

    let mut mounts: Vec<Mount> = Vec::new();
    // Rootfs RO base.
    mounts.extend(rootfs_system_mounts(&rootfs));

    // Self RW leaves.
    mounts.push(Mount::rw(self_workspace.clone()).guest("/home/workspace"));
    mounts.push(Mount::rw(self_tmp.clone()).guest("/tmp"));
    mounts.push(Mount::rw(self_upload.clone()).guest("/upload"));
    mounts.push(Mount::rw(self_output.clone()).guest("/output"));

    // /mnt/shared RO root.
    mounts.push(Mount::ro(shared_root_marker.clone()).guest("/mnt/shared"));
    mounts.push(Mount::ro(shared_ro_marker.clone()).guest(format!("/mnt/shared/{self_name}")));
    mounts.push(Mount::rw(self_workspace.clone()).guest(format!("/mnt/shared/{self_name}/home/workspace")));
    mounts.push(Mount::rw(self_tmp.clone()).guest(format!("/mnt/shared/{self_name}/tmp")));
    mounts.push(Mount::rw(self_upload.clone()).guest(format!("/mnt/shared/{self_name}/upload")));
    mounts.push(Mount::rw(self_output.clone()).guest(format!("/mnt/shared/{self_name}/output")));

    // Five peers. We keep handles to peer_a's workspace for the cross-visibility
    // check below.
    let peers = ["a", "b", "c", "d", "e"];
    let mut peer_a_workspace = PathBuf::new();
    for peer in &peers {
        std::fs::create_dir_all(shared_root_marker.join(peer))?;
        let pw = host.make_dir(&format!("peers/{peer}/workspace"));
        let pt = host.make_dir(&format!("peers/{peer}/tmp"));
        let pu = host.make_dir(&format!("peers/{peer}/upload"));
        let po = host.make_dir(&format!("peers/{peer}/output"));
        if *peer == "a" {
            peer_a_workspace = pw.clone();
        }
        mounts.push(Mount::ro(shared_ro_marker.clone()).guest(format!("/mnt/shared/{peer}")));
        mounts.push(Mount::rw(pw).guest(format!("/mnt/shared/{peer}/home/workspace")));
        mounts.push(Mount::rw(pt).guest(format!("/mnt/shared/{peer}/tmp")));
        mounts.push(Mount::rw(pu).guest(format!("/mnt/shared/{peer}/upload")));
        mounts.push(Mount::rw(po).guest(format!("/mnt/shared/{peer}/output")));
    }

    mounts.push(Mount::rw(user_skills).guest("/skills"));
    mounts.push(Mount::ro(builtin_skills).guest("/home/tokimo/.tokimo/skills"));

    // Sanity: at least 33 caller-provided mounts (excluding rootfs RO base).
    let caller_count = mounts.len() - rootfs_system_mounts(&rootfs).len();
    assert!(caller_count >= 33, "expected ≥ 33 caller mounts, got {caller_count}");

    // Drop a marker on host side under peer_a's workspace; we should see it
    // inside the sandbox under /mnt/shared/a/home/workspace.
    std::fs::write(peer_a_workspace.join("from_host.txt"), b"peer_a_marker_xyz")?;

    let cfg = SandboxConfig::new(&self_workspace)
        .name("agent-replica")
        .system_layout(SystemLayout::CallerProvided)
        .network(NetworkPolicy::Blocked)
        .cwd(PathBuf::from("/home/workspace"))
        .mounts(mounts);

    let mut sess = Session::open(&cfg).map_err(|e| format!("Session::open: {e}"))?;

    // Cross-peer visibility.
    let out = sess.exec("cat /mnt/shared/a/home/workspace/from_host.txt")?;
    assert_eq!(out.exit_code, 0, "stderr={}", out.stderr);
    assert!(
        out.stdout.contains("peer_a_marker_xyz"),
        "expected peer marker, got: {}",
        out.stdout
    );

    // Writing to RO `/mnt/shared` (its root) must fail.
    let out = sess.exec("touch /mnt/shared/forbidden 2>&1; echo EXIT:$?")?;
    let combined = out.stdout.clone();
    assert!(
        !combined.contains("EXIT:0"),
        "expected failure writing /mnt/shared, got: {combined}"
    );

    // Writing to a peer's RO marker (its `/mnt/shared/<peer>` segment, not
    // a leaf) must also fail.
    let out = sess.exec("touch /mnt/shared/b/sneaky 2>&1; echo EXIT:$?")?;
    assert!(
        !out.stdout.contains("EXIT:0"),
        "expected failure writing /mnt/shared/b root, got: {}",
        out.stdout
    );

    // /skills RW succeeds.
    let out = sess.exec("touch /skills/probe && echo OK")?;
    assert!(out.stdout.contains("OK"), "skills RW failed: {}", out.stderr);

    // /home/tokimo/.tokimo/skills RO fails.
    let out = sess.exec("touch /home/tokimo/.tokimo/skills/forbidden 2>&1; echo EXIT:$?")?;
    assert!(
        !out.stdout.contains("EXIT:0"),
        "expected RO failure on builtin skills, got: {}",
        out.stdout
    );
    // ...but we can read the seeded marker.
    let out = sess.exec("cat /home/tokimo/.tokimo/skills/BUILTIN.md")?;
    assert!(out.stdout.contains("hello-builtin"), "builtin read: {}", out.stdout);

    sess.close().map_err(|e| format!("close: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: concurrent run_oneshot + long-running main session
// ---------------------------------------------------------------------------

fn build_minimal_session(rootfs: &Path, host: &RootHost) -> Session {
    let workspace = host.make_dir("ws");
    let mut mounts = rootfs_system_mounts(rootfs);
    mounts.push(Mount::rw(workspace.clone()).guest("/home/workspace"));
    mounts.push(Mount::rw(host.make_dir("tmp")).guest("/tmp"));
    let cfg = SandboxConfig::new(&workspace)
        .system_layout(SystemLayout::CallerProvided)
        .network(NetworkPolicy::Blocked)
        .cwd(PathBuf::from("/home/workspace"))
        .mounts(mounts);
    Session::open(&cfg).expect("Session::open minimal")
}

#[test]
fn concurrent_oneshot_with_main_session() -> TestResult {
    let Some(rootfs) = gate("concurrent_oneshot_with_main_session") else {
        return Ok(());
    };
    let host = RootHost::new();
    let mut sess = build_minimal_session(&rootfs, &host);

    // Long-running main job — must remain alive while oneshots run.
    let main_job = sess.spawn("sleep 5").map_err(|e| format!("spawn main: {e}"))?;

    // Lock-free factory for parallel oneshots (does not contend with the
    // session mutex).
    let factory = sess
        .run_oneshot_factory()
        .ok_or("run_oneshot_factory returned None on Linux — should always be Some")?;

    // Calibrate sequential cost (rough lower bound — 2 invocations).
    let calib_start = Instant::now();
    for _ in 0..2 {
        let r = factory("echo CALIB && sleep 0.05", Duration::from_secs(10)).map_err(|e| format!("calib: {e}"))?;
        assert_eq!(r.exit_code, 0);
    }
    let per_call = calib_start.elapsed() / 2;
    let sequential_lower_bound = per_call * 8;

    // Fire 8 oneshots in parallel.
    const N: usize = 8;
    let parallel_start = Instant::now();
    let mut threads = Vec::with_capacity(N);
    for i in 0..N {
        let f = factory.clone();
        threads.push(thread::spawn(move || -> Result<(i32, String), String> {
            let cmd = format!("echo PID=$$ TAG={i} && date +%N");
            let out = f(&cmd, Duration::from_secs(15)).map_err(|e| format!("oneshot {i}: {e}"))?;
            Ok((out.exit_code, out.stdout))
        }));
    }
    let mut pids = std::collections::HashSet::new();
    for (i, t) in threads.into_iter().enumerate() {
        let (rc, stdout) = t.join().map_err(|_| format!("thread {i} panic"))??;
        assert_eq!(rc, 0, "oneshot {i} rc: {stdout}");
        let pid = stdout
            .lines()
            .find(|l| l.starts_with("PID="))
            .and_then(|l| l.split_whitespace().next())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("oneshot {i} missing PID line: {stdout}"))?;
        pids.insert(pid);
    }
    assert_eq!(pids.len(), N, "expected {N} distinct PIDs, got {pids:?}");
    let parallel = parallel_start.elapsed();
    let bound = sequential_lower_bound.mul_f32(0.6);
    println!("concurrent_oneshot: sequential≈{sequential_lower_bound:?}, parallel={parallel:?}, bound={bound:?}");
    assert!(
        parallel <= bound,
        "parallel oneshots ({parallel:?}) should be ≤ 0.6× sequential ({sequential_lower_bound:?})"
    );

    // Main job is still alive — kill it cleanly and drain.
    let main_id = main_job.id();
    sess.kill_job(main_id).map_err(|e| format!("kill main: {e}"))?;
    let _ = main_job.wait_with_timeout(Duration::from_secs(3));

    // Session is reusable.
    let out = sess.exec("echo POST_OK")?;
    assert!(out.stdout.contains("POST_OK"), "post-kill exec: {}", out.stdout);

    sess.close().map_err(|e| format!("close: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3: timeout → kill_job → session still usable
// ---------------------------------------------------------------------------

#[test]
fn timeout_kill_job_preserves_session() -> TestResult {
    let Some(rootfs) = gate("timeout_kill_job_preserves_session") else {
        return Ok(());
    };
    let host = RootHost::new();
    let mut sess = build_minimal_session(&rootfs, &host);

    // Spawn a long-runner.
    let handle = sess.spawn("sleep 30").map_err(|e| format!("spawn: {e}"))?;

    // First wait should time out (returns Err on timeout).
    let first = handle.wait_with_timeout(Duration::from_millis(500));
    assert!(
        first.is_err(),
        "wait_with_timeout(500ms) should have timed out for sleep 30, got: {first:?}"
    );

    // Now kill_job and drain.
    sess.kill_job(handle.id()).map_err(|e| format!("kill_job: {e}"))?;
    let drain = handle.wait_with_timeout(Duration::from_secs(2));
    // After kill, the drain may succeed (with non-zero rc) or surface an
    // error — the contract is just that the session itself stays alive.
    println!("drain after kill: {drain:?}");

    // Second spawn must succeed and session is fully reusable.
    let h2 = sess.spawn("echo still alive").map_err(|e| format!("spawn 2: {e}"))?;
    let out = h2
        .wait_with_timeout(Duration::from_secs(5))
        .map_err(|e| format!("wait 2: {e}"))?;
    assert_eq!(out.exit_code, 0, "second spawn rc, stderr={}", out.stderr);
    assert!(
        out.stdout.contains("still alive"),
        "expected 'still alive' in stdout, got: {}",
        out.stdout
    );

    sess.close().map_err(|e| format!("close: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 4: high-throughput stdout (≥ 4 MiB)
// ---------------------------------------------------------------------------

#[test]
fn high_throughput_stdout() -> TestResult {
    let Some(rootfs) = gate("high_throughput_stdout") else {
        return Ok(());
    };
    let host = RootHost::new();
    let mut sess = build_minimal_session(&rootfs, &host);

    const RAW_BYTES: usize = 4 * 1024 * 1024; // 4 MiB raw → ~5.6 MiB base64.
    let cmd = format!("head -c {RAW_BYTES} /dev/urandom | base64");

    let started = Instant::now();
    let handle = sess.spawn(&cmd).map_err(|e| format!("spawn: {e}"))?;
    let out = handle
        .wait_with_timeout(Duration::from_secs(30))
        .map_err(|e| format!("wait (potential deadlock): {e}"))?;
    let elapsed = started.elapsed();

    assert_eq!(out.exit_code, 0, "rc, stderr={}", out.stderr);

    // base64 of N random bytes is roughly N * 4/3 + newlines. We assert
    // captured length is at least the raw byte count, with a generous
    // upper bound to catch corruption (±10% around the expected expansion).
    let captured = out.stdout.len();
    assert!(
        captured >= RAW_BYTES,
        "captured {captured} < raw input {RAW_BYTES} — likely truncated"
    );
    let expected = RAW_BYTES * 4 / 3;
    let lower = (expected as f64 * 0.9) as usize;
    let upper = (expected as f64 * 1.10) as usize + RAW_BYTES / 64; // newlines slack
    assert!(
        captured >= lower && captured <= upper,
        "captured {captured} not within ±10% of expected base64 length {expected} (lower={lower}, upper={upper})"
    );
    println!("high_throughput_stdout: {captured} bytes captured in {elapsed:?} (no deadlock)");

    sess.close().map_err(|e| format!("close: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 5: NetworkPolicy::Observed sink records L7 events
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CollectingSink {
    events: Mutex<Vec<NetEvent>>,
}

impl NetEventSink for CollectingSink {
    fn on_event(&self, ev: &NetEvent) -> Verdict {
        self.events.lock().expect("sink lock").push(ev.clone());
        Verdict::Allow
    }
}

#[test]
fn network_observed_sink_records_events() -> TestResult {
    let Some(rootfs) = gate("network_observed_sink_records_events") else {
        return Ok(());
    };
    let host = RootHost::new();
    let workspace = host.make_dir("ws");
    let mut mounts = rootfs_system_mounts(&rootfs);
    mounts.push(Mount::rw(workspace.clone()).guest("/home/workspace"));
    mounts.push(Mount::rw(host.make_dir("tmp")).guest("/tmp"));

    let sink = Arc::new(CollectingSink::default());
    let cfg = SandboxConfig::new(&workspace)
        .system_layout(SystemLayout::CallerProvided)
        .cwd(PathBuf::from("/home/workspace"))
        .mounts(mounts)
        .network(NetworkPolicy::Observed { sink: sink.clone() });

    let mut sess = Session::open(&cfg).map_err(|e| format!("Session::open: {e}"))?;

    // Trigger an HTTP request via the injected HTTP_PROXY env. Try curl
    // first (Debian rootfs) and fall back to python3 stdlib. The upstream
    // host is invalid — we don't care about success, only that the proxy
    // observed the request.
    let probe = r#"
if command -v curl >/dev/null 2>&1; then
  curl --max-time 3 -s -o /dev/null http://example.invalid/probe || true
else
  python3 - <<'PY' || true
import urllib.request
try:
    urllib.request.urlopen('http://example.invalid/probe', timeout=3)
except Exception:
    pass
PY
fi
echo PROBE_DONE
"#;
    let out = sess.exec(probe).map_err(|e| format!("probe exec: {e}"))?;
    assert!(out.stdout.contains("PROBE_DONE"), "probe stdout: {}", out.stdout);

    // Wait up to ~3 s for the sink to receive the event.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !sink.events.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let events = sink.events.lock().unwrap().clone();
    assert!(
        !events.is_empty(),
        "expected ≥ 1 NetEvent on the Observed sink, got 0 (probe stdout={}, stderr={})",
        out.stdout,
        out.stderr
    );

    // At least one event should reference the probed host.
    let saw_host = events.iter().any(|e| {
        e.host
            .as_deref()
            .map(|h| h.contains("example.invalid"))
            .unwrap_or(false)
    });
    assert!(saw_host, "no event referenced example.invalid; events={events:?}");

    sess.close().map_err(|e| format!("close: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 6: profile-style env + mounts combined
// ---------------------------------------------------------------------------

#[test]
fn profile_env_and_mounts_combined() -> TestResult {
    let Some(rootfs) = gate("profile_env_and_mounts_combined") else {
        return Ok(());
    };
    let host = RootHost::new();

    let workspace = host.make_dir("ws");
    let conf_a = host.make_dir("conf_a");
    let conf_b = host.make_dir("conf_b");
    std::fs::write(conf_a.join("a.conf"), b"a=1")?;
    std::fs::write(conf_b.join("b.conf"), b"b=2")?;

    let mut mounts = rootfs_system_mounts(&rootfs);
    mounts.push(Mount::rw(workspace.clone()).guest("/home/workspace"));
    mounts.push(Mount::rw(host.make_dir("tmp")).guest("/tmp"));
    // The 3 caller mounts: 1 RW workspace + 2 RO config dirs (workspace
    // already counted above, plus two RO).
    mounts.push(Mount::ro(conf_a).guest("/etc/conf_a"));
    mounts.push(Mount::ro(conf_b).guest("/etc/conf_b"));

    // 5 profile-style env vars.
    let envs: [(&str, &str); 5] = [
        ("USER", "tokimo"),
        ("HOME", "/home/tokimo"),
        ("LANG", "C.UTF-8"),
        ("TZ", "UTC"),
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ];

    let mut cfg = SandboxConfig::new(&workspace)
        .system_layout(SystemLayout::CallerProvided)
        .network(NetworkPolicy::Blocked)
        .cwd(PathBuf::from("/home/workspace"))
        .mounts(mounts);
    for (k, v) in envs {
        cfg = cfg.env(k, v);
    }

    let mut sess = Session::open(&cfg).map_err(|e| format!("Session::open: {e}"))?;

    let h = sess.spawn("env | sort").map_err(|e| format!("spawn env: {e}"))?;
    let out = h
        .wait_with_timeout(Duration::from_secs(5))
        .map_err(|e| format!("wait env: {e}"))?;
    assert_eq!(out.exit_code, 0, "rc, stderr={}", out.stderr);
    for (k, v) in envs {
        let needle = format!("{k}={v}");
        assert!(
            out.stdout.contains(&needle),
            "expected `{needle}` in env output:\n{}",
            out.stdout
        );
    }

    let h2 = sess.spawn("pwd").map_err(|e| format!("spawn pwd: {e}"))?;
    let out = h2
        .wait_with_timeout(Duration::from_secs(5))
        .map_err(|e| format!("wait pwd: {e}"))?;
    assert!(
        out.stdout.trim() == "/home/workspace",
        "pwd should be /home/workspace, got: {}",
        out.stdout
    );

    // Mounts are visible too.
    let out = sess.exec("cat /etc/conf_a/a.conf && cat /etc/conf_b/b.conf")?;
    assert!(
        out.stdout.contains("a=1") && out.stdout.contains("b=2"),
        "conf: {}",
        out.stdout
    );

    sess.close().map_err(|e| format!("close: {e}"))?;
    Ok(())
}
