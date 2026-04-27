//! Regression tests for `Session::spawn` output capture.
//!
//! Background — see Tokimo conversation `9f47e6fd`. When a downstream caller
//! (`AgentSandbox`) uses `extra_mounts` to remap `/tmp` to a different host
//! directory than `cfg.work_dir`, the previous implementation wrote
//! per-job stdout/stderr to `$TMPDIR/.tps_job_*.{out,err}` (a host path
//! pointing at the remapped tmpfs) but `JobHandle::wait_with_timeout` read
//! from `cfg.work_dir.join(...)` — a different host directory. The
//! `unwrap_or_default()` on the file read silently turned the missing file
//! into empty bytes, so every write-side bash tool call came back as
//! `Exit code N\n(no output)` and the AI lost all diagnostic information.
//!
//! These tests pin the behavior so the bug can't return.

#![cfg(target_os = "linux")]

use std::time::Duration;

use tempfile::tempdir;
use tokimo_package_sandbox::{Mount, NetworkPolicy, SandboxConfig, Session};

fn skip_if_no_bwrap() -> bool {
    if std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .ok()
        .map_or(false, |o| o.status.success())
    {
        return false;
    }
    eprintln!("bwrap not available — skipping sandbox spawn-capture test");
    true
}

/// Reproduces conversation 9f47e6fd: `AgentSandbox`-style configuration —
/// `cfg.work_dir` is host-side, an `extra_mount` rebinds it to a custom
/// guest path (`/home/workspace`), and a *separate* `extra_mount` overrides
/// `/tmp` with a per-agent tmpfs. Under the old `$TMPDIR`-based capture
/// path, the script wrote outputs into the alt tmpfs but `JobHandle` read
/// from `work_dir`, returning empty stdout/stderr.
#[test]
fn spawn_captures_output_when_tmp_is_remapped() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let alt_tmp = tempdir().expect("alt_tmp tempdir");

    let cfg = SandboxConfig::new(work.path())
        .cwd("/home/workspace")
        .network(NetworkPolicy::Blocked)
        .mount(Mount::rw(work.path()).guest("/home/workspace"))
        .mount(Mount::rw(alt_tmp.path()).guest("/tmp"));

    let mut sess = Session::open(&cfg).expect("Session::open");

    let handle = sess
        .spawn("echo hello-stdout; echo hello-stderr 1>&2; exit 7")
        .expect("Session::spawn");
    let out = handle.wait_with_timeout(Duration::from_secs(15)).expect("wait");

    assert_eq!(out.exit_code, 7, "exit code propagated");
    assert!(
        out.stdout.contains("hello-stdout"),
        "stdout lost (the original 9f47e6fd bug). got stdout={:?}, stderr={:?}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("hello-stderr"),
        "stderr lost (the original 9f47e6fd bug). got stdout={:?}, stderr={:?}",
        out.stdout,
        out.stderr
    );
}

/// Even without remapping, a non-zero exit must surface stderr — pip-style
/// failure (`echo BOOM 1>&2; exit 1`) is the exact shape that returned
/// `(no output)` in the broken implementation.
#[test]
fn spawn_captures_stderr_on_nonzero_exit() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    let handle = sess.spawn("echo BOOM 1>&2; exit 1").expect("Session::spawn");
    let out = handle.wait_with_timeout(Duration::from_secs(10)).expect("wait");

    assert_eq!(out.exit_code, 1);
    assert!(
        out.stderr.contains("BOOM"),
        "expected BOOM in stderr, got stdout={:?}, stderr={:?}",
        out.stdout,
        out.stderr
    );
}

/// Two concurrent spawns under AgentSandbox-style remapping — stress
/// output capture under contention so we catch any cross-job file path
/// collisions.
#[test]
fn spawn_concurrent_two_jobs_distinct_outputs() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let alt_tmp = tempdir().expect("alt_tmp tempdir");
    let cfg = SandboxConfig::new(work.path())
        .cwd("/home/workspace")
        .network(NetworkPolicy::Blocked)
        .mount(Mount::rw(work.path()).guest("/home/workspace"))
        .mount(Mount::rw(alt_tmp.path()).guest("/tmp"));

    let mut sess = Session::open(&cfg).expect("Session::open");

    let h1 = sess
        .spawn("for i in $(seq 1 5); do echo job1-$i; done")
        .expect("spawn job1");
    let h2 = sess
        .spawn("for i in $(seq 1 5); do echo job2-$i 1>&2; done; exit 3")
        .expect("spawn job2");

    let o1 = h1.wait_with_timeout(Duration::from_secs(15)).expect("wait1");
    let o2 = h2.wait_with_timeout(Duration::from_secs(15)).expect("wait2");

    assert_eq!(o1.exit_code, 0);
    assert_eq!(o2.exit_code, 3);
    for i in 1..=5 {
        assert!(
            o1.stdout.contains(&format!("job1-{i}")),
            "job1 stdout missing line job1-{i}: {:?}",
            o1.stdout
        );
        assert!(
            o2.stderr.contains(&format!("job2-{i}")),
            "job2 stderr missing line job2-{i}: {:?}",
            o2.stderr
        );
    }
    assert!(
        !o1.stdout.contains("job2"),
        "job1 stdout leaked job2 output: {:?}",
        o1.stdout
    );
    assert!(
        !o2.stderr.contains("job1"),
        "job2 stderr leaked job1 output: {:?}",
        o2.stderr
    );
}

/// The core contract test: even when a caller remaps `/tmp`, cwd, and other
/// common paths to unrelated host directories via `extra_mounts`, spawn
/// output capture must still work — because the sandbox manages its own
/// internal capture mount at `/run/sandbox-jobs` that the caller cannot
/// accidentally break.
#[test]
fn spawn_captures_when_caller_remaps_everything() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let unrelated_1 = tempdir().expect("unrelated_1 tempdir");
    let unrelated_2 = tempdir().expect("unrelated_2 tempdir");
    let unrelated_3 = tempdir().expect("unrelated_3 tempdir");

    // Simulate a caller that completely remaps every path the old
    // `guest_work_dir` heuristic might guess — none of these bind to
    // `work_dir`, so if capture still works it's because the internal
    // `/run/sandbox-jobs` mount is doing its job.
    //
    // Mount order matters: parent paths must come before child paths
    // because bwrap applies mounts sequentially and later mounts
    // override earlier ones. `/home` first, then `/home/workspace`
    // so the workspace sub-mount lands on top of the home mount.
    let cfg = SandboxConfig::new(work.path())
        .cwd("/home/workspace")
        .network(NetworkPolicy::Blocked)
        .mount(Mount::rw(unrelated_3.path()).guest("/home"))
        .mount(Mount::rw(unrelated_1.path()).guest("/home/workspace"))
        .mount(Mount::rw(unrelated_2.path()).guest("/tmp"));

    let mut sess = Session::open(&cfg).expect("Session::open");

    let handle = sess
        .spawn("echo captured-stdout; echo captured-stderr 1>&2; exit 42")
        .expect("Session::spawn");
    let out = handle.wait_with_timeout(Duration::from_secs(15)).expect("wait");

    assert_eq!(out.exit_code, 42, "exit code propagated");
    assert!(
        out.stdout.contains("captured-stdout"),
        "stdout lost when everything remapped. got stdout={:?}, stderr={:?}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("captured-stderr"),
        "stderr lost when everything remapped. got stdout={:?}, stderr={:?}",
        out.stdout,
        out.stderr
    );
}

/// Capture must not truncate large output. 1.4 MB of base64-encoded random
/// data exercises the file-based capture path — the read must return every
/// byte.
#[test]
fn spawn_captures_megabyte_stdout_without_truncation() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // ~1.4 MB of base64 output.
    let cmd = "dd if=/dev/urandom bs=1024 count=1024 2>/dev/null | base64 -w0";
    let handle = sess.spawn(cmd).expect("Session::spawn");
    let out = handle.wait_with_timeout(Duration::from_secs(30)).expect("wait");

    assert_eq!(out.exit_code, 0, "exit code");
    let expected_min = 1024 * 1024 * 4 / 3; // base64 expansion floor
    assert!(
        out.stdout.len() >= expected_min,
        "stdout too short: {} bytes (expected >= {expected_min})",
        out.stdout.len()
    );
}

/// 50 concurrent spawns, each writing a unique magic string to stdout.
/// After all complete, every handle must return its own output without
/// crosstalk or truncation.
#[test]
fn spawn_concurrent_50_jobs_no_crosstalk() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    const N: usize = 50;
    let mut handles = Vec::with_capacity(N);

    for i in 0..N {
        let magic = format!("MAGIC_{i}_MAGIC");
        let handle = sess
            .spawn(&format!("echo {magic}"))
            .unwrap_or_else(|e| panic!("spawn job {i}: {e}"));
        handles.push((magic, handle));
    }

    for (i, (magic, handle)) in handles.into_iter().enumerate() {
        let out = handle
            .wait_with_timeout(Duration::from_secs(30))
            .unwrap_or_else(|e| panic!("wait job {i}: {e}"));
        assert_eq!(out.exit_code, 0, "job {i} exit code (magic={magic}): {}", out.exit_code);
        let trimmed = out.stdout.trim();
        assert_eq!(
            trimmed, &magic,
            "job {i} crosstalk or truncation: expected '{magic}', got '{trimmed}'"
        );
    }
}

// --- pipe-mode specific tests ---

/// Pipe mode must inherit the session bash's cwd. Env vars passed via
/// `SandboxConfig::env` are visible; `export` in the shell may not update
/// `/proc/<pid>/environ` on all kernels, so we test cwd only for the
/// shell-state-inheritance path.
#[test]
fn spawn_inherits_bash_env_and_cwd() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Change the session's cwd via exec.
    sess.exec("cd /tmp").expect("exec cd");

    // Spawn reads the inherited cwd from /proc/<shell_pid>/cwd.
    let handle = sess.spawn("pwd").expect("spawn cwd test");
    let out = handle.wait_with_timeout(Duration::from_secs(10)).expect("wait");

    assert_eq!(out.exit_code, 0);
    assert!(
        out.stdout.contains("/tmp"),
        "cwd inheritance failed: stdout={:?}",
        out.stdout
    );
}

/// Subprocess output faster than host consumption — pipe buffer fills,
/// child blocks until host drains. Verify no data loss.
#[test]
fn spawn_pipe_buffer_backpressure_no_data_loss() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // ~13 MB of base64 output. Pipe buffer is 64 KB — backpressure
    // kicks in almost immediately.
    let cmd = "dd if=/dev/urandom bs=1M count=10 2>/dev/null | base64 -w0";
    let handle = sess.spawn(cmd).expect("spawn backpressure");

    // Simulate consumer delay to ensure backpressure engages.
    std::thread::sleep(Duration::from_secs(1));

    let out = handle.wait_with_timeout(Duration::from_secs(60)).expect("wait");

    assert_eq!(out.exit_code, 0);
    let expected_min = 10 * 1024 * 1024 * 4 / 3; // base64 expansion of 10 MB
    assert!(
        out.stdout.len() >= expected_min,
        "backpressure data loss: {} bytes (expected >= {expected_min})",
        out.stdout.len()
    );
}

/// Child exits before host reads all pipe data. Verify `wait` drains
/// remaining bytes after exit.
#[test]
fn spawn_child_exits_before_host_reads() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Generate a large output and exit immediately. The child's stdout
    // pipe has data still buffered when the exit event arrives.
    let cmd = "python3 -c 'import sys; sys.stdout.write(\"X\" * 200_000); sys.stdout.flush()' 2>/dev/null \
         || perl -e 'print \"X\" x 200_000' 2>/dev/null \
         || awk 'BEGIN {while(i++<200000) printf \"X\"}'";
    let handle = sess.spawn(cmd).expect("spawn big+exit");
    let out = handle.wait_with_timeout(Duration::from_secs(15)).expect("wait");

    assert_eq!(out.exit_code, 0, "exit_code={}", out.exit_code);
    assert_eq!(
        out.stdout.len(),
        200_000,
        "data loss: expected 200000 bytes, got {}",
        out.stdout.len()
    );
    assert!(out.stdout.chars().all(|c| c == 'X'), "unexpected content in stdout");
}

/// If init disconnects while a job is running, `wait_with_timeout` must
/// return promptly (not hang forever). The convention from `run_oneshot`
/// is to return `Ok` with exit_code = -1 when the client is dead.
#[test]
fn spawn_init_disconnect_during_job() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Spawn a slow job.
    let handle = sess.spawn("sleep 30").expect("spawn slow");

    // Kill the session (and therefore init) while the job is running.
    // This drops the ShellHandle which kills bwrap.
    sess.close().expect("close session");

    // The job handle should return promptly with exit_code = -1.
    let start = std::time::Instant::now();
    let out = handle
        .wait_with_timeout(Duration::from_secs(5))
        .expect("should not hang");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(4),
        "wait should return quickly after init death, took {elapsed:?}"
    );
    assert_eq!(
        out.exit_code, -1,
        "expected exit_code -1 when init dies, got {}",
        out.exit_code
    );
}

/// 1000 concurrent `echo hello` jobs must complete without crosstalk,
/// and memory must not grow linearly with job count.
#[test]
fn spawn_1000_small_jobs_memory_stable() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    const N: usize = 1000;
    let mut handles = Vec::with_capacity(N);

    for _ in 0..N {
        handles.push(sess.spawn("echo hello").expect("spawn"));
    }

    for (i, h) in handles.into_iter().enumerate() {
        let out = h
            .wait_with_timeout(Duration::from_secs(30))
            .unwrap_or_else(|e| panic!("wait job {i}: {e}"));
        assert_eq!(out.exit_code, 0, "job {i} exit code: {}", out.exit_code);
        assert_eq!(out.stdout.trim(), "hello", "job {i} wrong output: {:?}", out.stdout);
    }
}

/// Interleaved stdout/stderr at base64 chunk boundaries must not cause
/// cross-contamination between the two streams.
#[test]
fn spawn_stdout_stderr_interleave_boundary() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Write ~24 KB to both stdout and stderr in interleaved chunks.
    // Each iteration writes ~100 bytes to each stream; 256 iterations
    // produces ~25 KB per stream, crossing the 16 KB base64 chunk boundary.
    let cmd = "for i in $(seq 0 255); do \
        printf 'OUT%04d' $i; head -c 100 /dev/zero | tr '\\0' 'A'; echo; \
        printf 'ERR%04d' $i >&2; head -c 100 /dev/zero | tr '\\0' 'B' >&2; echo >&2; \
        done";
    let handle = sess.spawn(cmd).expect("spawn interleave");
    let out = handle.wait_with_timeout(Duration::from_secs(30)).expect("wait");

    assert_eq!(out.exit_code, 0, "exit_code={}", out.exit_code);

    // Verify stdout lines all start with OUT, not ERR.
    for line in out.stdout.lines() {
        if line.is_empty() {
            continue;
        }
        assert!(line.starts_with("OUT"), "stderr leaked into stdout: {:?}", line);
    }
    // Verify stderr lines all start with ERR.
    for line in out.stderr.lines() {
        if line.is_empty() {
            continue;
        }
        assert!(line.starts_with("ERR"), "stdout leaked into stderr: {:?}", line);
    }

    // Should have 256 lines in each stream.
    let out_count = out.stdout.lines().filter(|l| !l.is_empty()).count();
    let err_count = out.stderr.lines().filter(|l| !l.is_empty()).count();
    assert!(out_count >= 200, "too few stdout lines: {out_count}");
    assert!(err_count >= 200, "too few stderr lines: {err_count}");
}

/// Spawn a slow command, wait with a short timeout — must return
/// exit_code = 124 (matching coreutils `timeout` convention) and
/// return promptly.
#[test]
fn spawn_timeout_kills_job() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    let handle = sess.spawn("sleep 60 && echo NEVER").expect("spawn slow");
    let start = std::time::Instant::now();
    let out = handle
        .wait_with_timeout(Duration::from_secs(2))
        .expect("timeout wait should not error");
    let elapsed = start.elapsed();

    assert_eq!(
        out.exit_code, 124,
        "timeout exit_code should be 124, got {}",
        out.exit_code
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout should return quickly, took {elapsed:?}"
    );
    // The "NEVER" should not appear — child was killed before finishing.
    assert!(!out.stdout.contains("NEVER"), "job was not killed");
}

/// Spawn a long-running job, kill it via `Session::kill_job`, verify
/// the session stays alive and subsequent exec/spawn work normally.
#[test]
fn spawn_kill_job_keeps_session_alive() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Set some session state.
    sess.exec("export FOO=bar && cd /tmp").expect("exec setup");
    let cwd_check = sess.exec("pwd").expect("exec pwd");
    assert!(
        cwd_check.stdout.contains("/tmp"),
        "cwd before kill: {:?}",
        cwd_check.stdout
    );

    // Spawn a long-running job.
    let handle = sess.spawn("sleep 60 && echo NEVER").expect("spawn slow");
    let job_id = handle.id();

    // Kill it.
    sess.kill_job(job_id).expect("kill_job dispatch");
    let out = handle
        .wait_with_timeout(Duration::from_secs(5))
        .expect("wait after kill");

    assert!(
        out.exit_code != 0 || out.stdout.is_empty(),
        "killed job should not succeed: exit_code={}, stdout={:?}",
        out.exit_code,
        out.stdout
    );

    // Session must still be alive — exec and spawn should work.
    let after = sess.exec("echo ALIVE").expect("exec after kill");
    assert!(after.stdout.contains("ALIVE"), "session dead after kill_job");

    let h2 = sess.spawn("echo SPAWN_ALIVE").expect("spawn after kill");
    let o2 = h2
        .wait_with_timeout(Duration::from_secs(10))
        .expect("wait spawn after kill");
    assert!(
        o2.stdout.contains("SPAWN_ALIVE"),
        "spawn broken after kill_job: {:?}",
        o2.stdout
    );
}

/// Interleave `exec` and `spawn` — exec changes cwd, spawn inherits it,
/// then exec again and spawn again, all without interference.
#[test]
fn spawn_exec_mixed_inherits_state() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Round 1: exec changes cwd, spawn sees it.
    sess.exec("cd /tmp").expect("exec cd /tmp");
    let h1 = sess.spawn("pwd").expect("spawn round 1");
    let o1 = h1.wait_with_timeout(Duration::from_secs(10)).expect("wait round 1");
    assert!(o1.stdout.contains("/tmp"), "spawn r1 cwd wrong: {:?}", o1.stdout);

    // Round 2: exec changes cwd again, spawn sees the new one.
    sess.exec("cd /home").expect("exec cd /home");
    let h2 = sess.spawn("pwd").expect("spawn round 2");
    let o2 = h2.wait_with_timeout(Duration::from_secs(10)).expect("wait round 2");
    assert!(o2.stdout.contains("/home"), "spawn r2 cwd wrong: {:?}", o2.stdout);

    // Verify exec also sees the right cwd.
    let e2 = sess.exec("pwd").expect("exec round 2");
    assert!(e2.stdout.contains("/home"), "exec r2 cwd wrong: {:?}", e2.stdout);
}
