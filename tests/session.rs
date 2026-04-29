//! Cross-platform Session integration tests.
//!
//! These tests run on both Linux (bwrap) and macOS (Virtualization.framework).
//! They share the same assertions — only the sandbox backend differs.
//!
//! On macOS the tests auto-download rootfs artifacts if missing.
//!
//! ```bash
//! # Run all session tests:
//! cargo test --test session
//!
//! # Run with verbose output:
//! cargo test --test session -- --nocapture
//! ```

mod common;

use std::time::Duration;
use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig, Session};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    _work: tempfile::TempDir,
    sess: Session,
}

impl Fixture {
    fn new() -> Self {
        // Auto-download artifacts on macOS.
        #[cfg(target_os = "macos")]
        common::download_vz_artifacts().expect("download artifacts");

        let work = tempfile::tempdir().expect("work tempdir");
        let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
        let sess = Session::open(&cfg).expect("Session::open");
        Self { _work: work, sess }
    }
}

/// Call at start of each session test. Returns early if prerequisites
/// are missing or sessions aren't supported.
macro_rules! require_session {
    () => {
        if common::skip_unless_platform_ready() || common::skip_unless_session_supported() {
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn session_exec_echo() {
    require_session!();
    let mut f = Fixture::new();
    let out = f.sess.exec("echo hello").expect("exec echo");
    assert_eq!(out.stdout.trim(), "hello");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn session_exec_env_persistence() {
    require_session!();
    let mut f = Fixture::new();
    f.sess.exec("export FOO=bar42").expect("set env");
    let out = f.sess.exec("echo $FOO").expect("read env");
    assert_eq!(out.stdout.trim(), "bar42");
}

#[test]
fn session_exec_cwd_persistence() {
    require_session!();
    let mut f = Fixture::new();
    f.sess
        .exec("mkdir -p /tmp/tps_cwd_test && cd /tmp/tps_cwd_test")
        .expect("cd");
    let out = f.sess.exec("pwd").expect("pwd");
    assert!(out.stdout.contains("tps_cwd_test"), "cwd: {}", out.stdout);
}

#[test]
fn session_exec_stderr_capture() {
    require_session!();
    let mut f = Fixture::new();
    let out = f.sess.exec("echo to-stderr 1>&2").expect("stderr test");
    assert_eq!(out.stderr.trim(), "to-stderr");
    assert!(out.stdout.trim().is_empty());
}

#[test]
fn session_exec_exit_code_nonzero() {
    require_session!();
    let mut f = Fixture::new();
    let out = f.sess.exec("bash -c 'exit 7'").expect("exit 7");
    assert_eq!(out.exit_code, 7);
}

#[test]
fn session_exec_large_output() {
    require_session!();
    let mut f = Fixture::new();
    let out = f.sess.exec("seq 1 500").expect("seq");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 500);
    assert_eq!(lines[0].trim(), "1");
    assert_eq!(lines[499].trim(), "500");
}

#[test]
fn session_exec_timeout_tears_down_session() {
    require_session!();
    let mut f = Fixture::new();
    f.sess.set_exec_timeout(Duration::from_millis(500));
    let err = f.sess.exec("sleep 10").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("timed out") || msg.contains("session is closed"),
        "expected timeout, got: {msg}"
    );
}

#[test]
fn session_spawn_captures_output() {
    require_session!();
    let mut f = Fixture::new();
    let job = f.sess.spawn("echo spawn-hello && echo spawn-err 1>&2").expect("spawn");
    let out = job.wait_with_timeout(Duration::from_secs(10)).expect("wait");
    assert_eq!(out.stdout.trim(), "spawn-hello");
    assert_eq!(out.stderr.trim(), "spawn-err");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn session_spawn_inherits_cwd() {
    require_session!();
    let mut f = Fixture::new();
    f.sess
        .exec("mkdir -p /tmp/spawn_cwd_inherit && cd /tmp/spawn_cwd_inherit")
        .expect("cd");
    let job = f.sess.spawn("pwd").expect("spawn cwd");
    let out = job.wait_with_timeout(Duration::from_secs(10)).expect("wait");
    assert!(out.stdout.contains("spawn_cwd_inherit"), "cwd: {}", out.stdout);
}

#[test]
fn session_spawn_timeout_kills_job() {
    require_session!();
    let mut f = Fixture::new();
    let job = f.sess.spawn("sleep 60").expect("spawn sleep");
    let out = job.wait_with_timeout(Duration::from_secs(2)).expect("wait");
    assert_eq!(
        out.exit_code, 124,
        "timeout exit_code should be 124, got {}",
        out.exit_code
    );
}

#[test]
fn session_kill_job_keeps_session_alive() {
    require_session!();
    let mut f = Fixture::new();
    let job = f.sess.spawn("sleep 60").expect("spawn sleep");
    let jid = job.id();
    f.sess.kill_job(jid).expect("kill_job");
    let _ = job.wait_with_timeout(Duration::from_secs(3));
    let out = f.sess.exec("echo ALIVE").expect("exec after kill");
    assert_eq!(out.stdout.trim(), "ALIVE");
    // Idempotent kill: child may already be reaped, ignore error.
    let _ = f.sess.kill_job(jid);
}

#[test]
fn session_spawn_concurrent_no_crosstalk() {
    require_session!();
    let mut f = Fixture::new();
    let j1 = f.sess.spawn("echo JOB1_MARKER_ABC").expect("spawn j1");
    let j2 = f.sess.spawn("echo JOB2_MARKER_XYZ").expect("spawn j2");
    let o1 = j1.wait_with_timeout(Duration::from_secs(5)).expect("wait j1");
    let o2 = j2.wait_with_timeout(Duration::from_secs(5)).expect("wait j2");
    assert!(o1.stdout.contains("JOB1_MARKER_ABC"), "j1: {}", o1.stdout);
    assert!(o2.stdout.contains("JOB2_MARKER_XYZ"), "j2: {}", o2.stdout);
    assert!(!o1.stdout.contains("JOB2_MARKER"), "crosstalk in j1");
    assert!(!o2.stdout.contains("JOB1_MARKER"), "crosstalk in j2");
}

#[test]
fn session_close_cleans_up() {
    require_session!();
    let f = Fixture::new();
    f.sess.close().expect("close");
}

#[test]
fn session_spawn_exec_mixed() {
    require_session!();
    let mut f = Fixture::new();
    f.sess.exec("export MIX_TEST=one").expect("exec export");
    f.sess
        .exec("mkdir -p /tmp/mix_test_dir && cd /tmp/mix_test_dir")
        .expect("cd mix");

    let j1 = f.sess.spawn("echo MIX=$MIX_TEST && pwd").expect("spawn j1");
    let o1 = j1.wait_with_timeout(Duration::from_secs(5)).expect("wait j1");
    assert!(o1.stdout.contains("mix_test_dir"), "cwd in spawn: {}", o1.stdout);
    assert!(o1.stdout.contains("MIX="), "env in spawn: {}", o1.stdout);

    f.sess.exec("export MIX_TEST=two").expect("exec export2");
    let out = f.sess.exec("echo MIX=$MIX_TEST").expect("exec read");
    assert!(out.stdout.contains("MIX=two"), "exec env: {}", out.stdout);
}
