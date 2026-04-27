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
