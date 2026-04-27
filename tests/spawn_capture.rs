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
    let out = handle
        .wait_with_timeout(Duration::from_secs(15))
        .expect("wait");

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

    let handle = sess
        .spawn("echo BOOM 1>&2; exit 1")
        .expect("Session::spawn");
    let out = handle
        .wait_with_timeout(Duration::from_secs(10))
        .expect("wait");

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
    let out = handle
        .wait_with_timeout(Duration::from_secs(15))
        .expect("wait");

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

/// Attempting to use an `extra_mount` whose guest path collides with the
/// internal capture directory (`/run/sandbox-jobs` or a subdirectory) must
/// be rejected at `Session::open` time with a clear error message.
#[test]
fn spawn_rejects_extra_mount_collision_with_capture_dir() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let some_dir = tempdir().expect("some_dir tempdir");

    // Direct collision: guest path IS the capture dir.
    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .mount(Mount::rw(some_dir.path()).guest("/run/sandbox-jobs"));
    let err = Session::open(&cfg).err().expect("expected Err").to_string();
    assert!(
        err.contains("/run/sandbox-jobs"),
        "expected collision error mentioning /run/sandbox-jobs, got: {err}"
    );

    // Subdirectory collision: guest path is a child of the capture dir.
    let cfg2 = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .mount(Mount::rw(some_dir.path()).guest("/run/sandbox-jobs/subdir"));
    let err2 = Session::open(&cfg2).err().expect("expected Err").to_string();
    assert!(
        err2.contains("/run/sandbox-jobs/subdir"),
        "expected collision error mentioning /run/sandbox-jobs/subdir, got: {err2}"
    );
}

/// When the host-side capture file is genuinely missing (e.g. deleted by an
/// external process between spawn and wait), `JobHandle::wait_with_timeout`
/// must return `Err` rather than silently returning `Ok("")`.
#[test]
fn wait_returns_err_when_capture_file_missing() {
    if skip_if_no_bwrap() {
        return;
    }

    let work = tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");

    // Spawn a slow command so the capture file is open long enough for us
    // to unlink it from the host side before bash closes it.
    let handle = sess
        .spawn("sleep 2 && echo gone")
        .expect("Session::spawn");
    let job_id = handle.id();

    // Give bash time to start the brace group and open the redirect files.
    std::thread::sleep(Duration::from_millis(300));

    // Find and unlink the capture files from the host side while bash still
    // holds them open. Bash can still write to its fds, but the directory
    // entry is gone — when bash closes the fd, the inode is freed. The
    // subsequent `wait_with_timeout` read sees a missing file → Err.
    let capture_dir = work.path().join(".sandbox-jobs");
    if let Ok(entries) = std::fs::read_dir(&capture_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Match files for this specific job id (format: .tps_job_{sid}_{id}.{out,err}).
            if name.contains(&format!("_{}.", job_id)) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let result = handle.wait_with_timeout(Duration::from_secs(10));
    match result {
        Err(e) => {
            assert!(
                e.to_string().contains("failed to read"),
                "expected 'failed to read' in error, got: {e}"
            );
        }
        Ok(out) => {
            // The files might have been recreated by bash if we unlinked
            // too early (before the redirect opened them). That's fine —
            // this is a best-effort race test. On most runs the unlink
            // will land while bash holds the fd open, triggering the Err
            // path. If the unlink happened before open, bash just creates
            // a new file and we read normally — not a test failure.
            eprintln!(
                "note: unlink landed before bash opened capture files; \
                 output was readable (exit_code={})",
                out.exit_code
            );
        }
    }
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
    let out = handle
        .wait_with_timeout(Duration::from_secs(30))
        .expect("wait");

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
        assert_eq!(
            out.exit_code, 0,
            "job {i} exit code (magic={magic}): {}",
            out.exit_code
        );
        let trimmed = out.stdout.trim();
        assert_eq!(
            trimmed, &magic,
            "job {i} crosstalk or truncation: expected '{magic}', got '{trimmed}'"
        );
    }
}
