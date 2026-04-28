//! macOS VZ Session integration tests.
//!
//! These tests exercise the persistent VM session path (VSOCK-based init
//! protocol). They require a VZ-capable Mac with kernel + initrd + rootfs
//! artifacts from tokimo-package-rootfs.

#![cfg(target_os = "macos")]

use std::time::Duration;

use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig, Session};

fn skip_if_no_vz() -> bool {
    let vmlinuz = std::env::var("TOKIMO_VZ_KERNEL").ok().or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.tokimo/kernel/vmlinuz"))
    });
    let Some(kernel) = vmlinuz else {
        eprintln!("SKIP: TOKIMO_VZ_KERNEL not set and ~/.tokimo/kernel/vmlinuz not found");
        return true;
    };
    if !std::path::Path::new(&kernel).exists() {
        eprintln!("SKIP: kernel not found at {kernel}");
        return true;
    }
    // VZ availability check via arcbox_vz.
    if !arcbox_vz::is_supported() {
        eprintln!("SKIP: Virtualization.framework not available");
        return true;
    }
    false
}

#[test]
fn session_exec_echo_returns_stdout() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let out = sess.exec("echo hello").expect("exec echo");
    assert_eq!(out.stdout.trim(), "hello");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn session_exec_preserves_env() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    sess.exec("export FOO=bar42").expect("set env");
    let out = sess.exec("echo $FOO").expect("read env");
    assert_eq!(out.stdout.trim(), "bar42");
}

#[test]
fn session_exec_preserves_cwd() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    sess.exec("cd /tmp && mkdir -p tps_cwd_test && cd tps_cwd_test")
        .expect("cd");
    let out = sess.exec("pwd").expect("pwd");
    assert!(
        out.stdout.contains("tps_cwd_test"),
        "cwd should be tps_cwd_test, got: {}",
        out.stdout
    );
}

#[test]
fn session_exec_exit_code_nonzero() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let out = sess.exec("exit 7").expect("exec exit 7");
    assert_eq!(out.exit_code, 7);
}

#[test]
fn session_exec_captures_stderr() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let out = sess.exec("echo to-stderr 1>&2").expect("exec stderr");
    assert_eq!(out.stderr.trim(), "to-stderr");
    assert!(out.stdout.is_empty() || out.stdout.trim().is_empty());
}

#[test]
fn session_exec_large_output_no_truncation() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let out = sess.exec("seq 1 500").expect("exec seq");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 500);
    assert_eq!(lines[0].trim(), "1");
    assert_eq!(lines[499].trim(), "500");
}

#[test]
fn session_exec_timeout_tears_down_session() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    sess.set_exec_timeout(Duration::from_millis(500));
    let err = sess.exec("sleep 10").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("timed out") || msg.contains("session is closed"),
        "expected timeout or session closed, got: {msg}"
    );
}

#[test]
fn session_spawn_captures_output() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let job = sess.spawn("echo spawn-hello && echo spawn-err 1>&2").expect("spawn");
    let out = job.wait_with_timeout(Duration::from_secs(10)).expect("wait");
    assert_eq!(out.stdout.trim(), "spawn-hello");
    assert_eq!(out.stderr.trim(), "spawn-err");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn session_spawn_inherits_env_and_cwd() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    sess.exec("export MYSPAWNVAR=inherited42").expect("export");
    sess.exec("mkdir -p /tmp/spawn_cwd_test && cd /tmp/spawn_cwd_test")
        .expect("cd");
    let job = sess.spawn("echo MV=$MYSPAWNVAR && pwd").expect("spawn");
    let out = job.wait_with_timeout(Duration::from_secs(10)).expect("wait");
    assert!(
        out.stdout.contains("MV=inherited42"),
        "env should be inherited: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("spawn_cwd_test"),
        "cwd should be inherited: {}",
        out.stdout
    );
}

#[test]
fn session_spawn_timeout_kills_job() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let job = sess.spawn("sleep 60").expect("spawn sleep");
    let out = job.wait_with_timeout(Duration::from_secs(2)).expect("wait");
    assert_eq!(
        out.exit_code, 124,
        "timeout should give exit_code 124, got {}",
        out.exit_code
    );
}

#[test]
fn session_kill_job_keeps_session_alive() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let job = sess.spawn("sleep 60").expect("spawn sleep");
    let jid = job.id();
    sess.kill_job(jid).expect("kill_job");
    // Job should be dead, session should still work.
    let out = sess.exec("echo ALIVE").expect("exec after kill");
    assert_eq!(out.stdout.trim(), "ALIVE");
    // Idempotent kill should not crash.
    sess.kill_job(jid).expect("idempotent kill_job");
}

#[test]
fn session_spawn_concurrent_no_crosstalk() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    let j1 = sess.spawn("echo JOB1_MARKER_ABC123").expect("spawn j1");
    let j2 = sess.spawn("echo JOB2_MARKER_XYZ789").expect("spawn j2");
    let o1 = j1.wait_with_timeout(Duration::from_secs(5)).expect("wait j1");
    let o2 = j2.wait_with_timeout(Duration::from_secs(5)).expect("wait j2");
    assert!(o1.stdout.contains("JOB1_MARKER_ABC123"), "j1 output: {}", o1.stdout);
    assert!(o2.stdout.contains("JOB2_MARKER_XYZ789"), "j2 output: {}", o2.stdout);
    assert!(!o1.stdout.contains("JOB2_MARKER"), "crosstalk in j1");
    assert!(!o2.stdout.contains("JOB1_MARKER"), "crosstalk in j2");
}

#[test]
fn session_spawn_exec_mixed_inherits_state() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let mut sess = Session::open(&cfg).expect("Session::open");
    sess.exec("export MIX_TEST=one").expect("exec export");
    let j1 = sess.spawn("echo MIX=$MIX_TEST").expect("spawn");
    let o1 = j1.wait_with_timeout(Duration::from_secs(5)).expect("wait j1");
    assert!(o1.stdout.contains("MIX=one"));
    sess.exec("export MIX_TEST=two").expect("exec export2");
    let j2 = sess.spawn("echo MIX=$MIX_TEST").expect("spawn2");
    let o2 = j2.wait_with_timeout(Duration::from_secs(5)).expect("wait j2");
    assert!(o2.stdout.contains("MIX=two"));
}

#[test]
fn session_close_cleans_up() {
    if skip_if_no_vz() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let sess = Session::open(&cfg).expect("Session::open");
    sess.close().expect("close");
}
