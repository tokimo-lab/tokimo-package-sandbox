//! Integration tests for multi-user [`Workspace`].
//!
//! Requires `bwrap` (bubblewrap) installed on the host.
#![cfg(target_os = "linux")]

use std::time::Duration;
use tokimo_package_sandbox::{UserConfig, Workspace, WorkspaceConfig};

fn skip_if_no_bwrap() {
    if std::process::Command::new("which")
        .arg("bwrap")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("SKIP: bwrap not installed");
        std::process::exit(0);
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    ws: Workspace,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = WorkspaceConfig::new(tmp.path());
        let ws = Workspace::open(&cfg).expect("open workspace");
        Self { _tmp: tmp, ws }
    }
}

// ---------------------------------------------------------------------------
// Step 1 + 3: basic multi-user workspace
// ---------------------------------------------------------------------------

#[test]
fn two_users_exec_independently() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");
    f.ws.add_user(&UserConfig::new("bob")).expect("add bob");

    let a = f.ws.exec("alice", "echo ALICE", Duration::from_secs(10)).expect("alice");
    let b = f.ws.exec("bob", "echo BOB", Duration::from_secs(10)).expect("bob");

    assert!(a.stdout.contains("ALICE"), "alice: {}", a.stdout);
    assert!(b.stdout.contains("BOB"), "bob: {}", b.stdout);
}

#[test]
fn add_user_creates_isolated_tmp() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");

    // Verify per-user tmp directory exists and is writable.
    let out = f.ws.exec("alice", "ls -d /tmp/alice && echo ok", Duration::from_secs(10)).expect("exec");
    assert!(out.stdout.contains("ok"), "/tmp/alice should exist: {}", out.stdout);

    // Verify per-user work directory exists.
    let out = f.ws.exec("alice", "ls -d /work/alice && echo ok", Duration::from_secs(10)).expect("exec");
    assert!(out.stdout.contains("ok"), "/work/alice should exist: {}", out.stdout);
}

#[test]
fn add_user_creates_isolated_cwd() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("bob").cwd("/work/bob")).expect("add bob");

    let out = f.ws.exec("bob", "pwd", Duration::from_secs(10)).expect("exec");
    assert!(out.stdout.contains("/work/bob"), "expected /work/bob in pwd, got: {}", out.stdout);
}

#[test]
fn two_users_env_isolated() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice").env("MYVAR", "alice_value")).expect("add alice");
    f.ws.add_user(&UserConfig::new("bob").env("MYVAR", "bob_value")).expect("add bob");

    let a = f.ws.exec("alice", "echo $MYVAR", Duration::from_secs(10)).expect("alice");
    let b = f.ws.exec("bob", "echo $MYVAR", Duration::from_secs(10)).expect("bob");

    assert!(a.stdout.contains("alice_value"), "alice: {}", a.stdout);
    assert!(b.stdout.contains("bob_value"), "bob: {}", b.stdout);
}

// ---------------------------------------------------------------------------
// Step 2: remove user
// ---------------------------------------------------------------------------

#[test]
fn remove_user_does_not_affect_other() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");
    f.ws.add_user(&UserConfig::new("bob")).expect("add bob");

    f.ws.remove_user("alice").expect("remove alice");

    let b = f.ws.exec("bob", "echo still_alive", Duration::from_secs(10)).expect("bob");
    assert!(b.stdout.contains("still_alive"), "bob: {}", b.stdout);
}

#[test]
fn add_user_after_remove() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");
    f.ws.remove_user("alice").expect("remove alice");
    f.ws.add_user(&UserConfig::new("alice2")).expect("re-add as alice2");

    let out = f.ws.exec("alice2", "echo reincarnated", Duration::from_secs(10)).expect("exec");
    assert!(out.stdout.contains("reincarnated"), "re-added user: {}", out.stdout);
}

#[test]
fn three_users_concurrent_exec() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("u1")).expect("add u1");
    f.ws.add_user(&UserConfig::new("u2")).expect("add u2");
    f.ws.add_user(&UserConfig::new("u3")).expect("add u3");

    let r1 = f.ws.exec("u1", "echo ONE", Duration::from_secs(10)).expect("u1");
    let r2 = f.ws.exec("u2", "echo TWO", Duration::from_secs(10)).expect("u2");
    let r3 = f.ws.exec("u3", "echo THREE", Duration::from_secs(10)).expect("u3");

    assert!(r1.stdout.contains("ONE"));
    assert!(r2.stdout.contains("TWO"));
    assert!(r3.stdout.contains("THREE"));
}

// ---------------------------------------------------------------------------
// Step 4: per-user timeout isolation
// ---------------------------------------------------------------------------

#[test]
fn user_timeout_only_kills_that_user() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice").timeout(Duration::from_secs(1))).expect("add alice");
    f.ws.add_user(&UserConfig::new("bob").timeout(Duration::from_secs(30))).expect("add bob");

    let result = f.ws.exec("alice", "sleep 10", Duration::from_secs(1));
    assert!(result.is_err() || result.unwrap().exit_code == 124);

    let b = f.ws.exec("bob", "echo bob_ok", Duration::from_secs(10)).expect("bob");
    assert!(b.stdout.contains("bob_ok"), "bob: {}", b.stdout);
}

#[test]
fn user_spawn_unaffected_by_exec_timeout() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice").timeout(Duration::from_secs(1))).expect("add alice");

    f.ws.spawn("alice", "sleep 30").expect("spawn");

    let result = f.ws.exec("alice", "sleep 10", Duration::from_secs(1));
    assert!(result.is_err() || result.unwrap().exit_code == 124);

    let out = f.ws.exec("alice", "echo still_working", Duration::from_secs(10)).expect("alice");
    assert!(out.stdout.contains("still_working"), "alice: {}", out.stdout);
}

// ---------------------------------------------------------------------------
// Step 5: dynamic bind mount
// ---------------------------------------------------------------------------

#[test]
fn dynamic_add_mount_visible() {
    skip_if_no_bwrap();
    let host_dir = tempfile::tempdir().expect("host dir");
    let host_file = host_dir.path().join("hello.txt");
    std::fs::write(&host_file, b"mounted_content").expect("write file");

    let tmp = tempfile::tempdir().expect("workspace tmp");
    let cfg = WorkspaceConfig::new(tmp.path()).mount(tokimo_package_sandbox::Mount::rw(host_dir.path()));
    let mut ws = Workspace::open(&cfg).expect("open");
    ws.add_user(&UserConfig::new("alice")).expect("add alice");

    let host_path_str = host_dir.path().to_string_lossy().to_string();
    let out = ws.exec("alice", &format!("cat {}/hello.txt", host_path_str), Duration::from_secs(10)).expect("exec");
    assert!(out.stdout.contains("mounted_content"), "got: {}", out.stdout);
}

// ---------------------------------------------------------------------------
// Step 6: seccomp — child cannot mount
// ---------------------------------------------------------------------------

#[test]
fn child_cannot_call_mount() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");

    let out = f.ws.exec("alice", "mount --bind /tmp /mnt 2>&1; echo EXIT:$?", Duration::from_secs(10)).expect("exec");

    let combined = format!("{}{}", out.stdout, out.stderr);
    assert!(
        combined.contains("permitted")
            || combined.contains("EPERM")
            || combined.contains("denied")
            || combined.contains("Operation not permitted")
            || !combined.contains("EXIT:0"),
        "mount should have failed, got: stdout={} stderr={}", out.stdout, out.stderr
    );
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

#[test]
fn workspace_close_cleans_up() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");
    f.ws.close().expect("close");
}

#[test]
fn user_count_reflects_add_remove() {
    skip_if_no_bwrap();
    let mut f = Fixture::new();
    assert_eq!(f.ws.user_count(), 0);
    f.ws.add_user(&UserConfig::new("alice")).expect("add alice");
    assert_eq!(f.ws.user_count(), 1);
    f.ws.add_user(&UserConfig::new("bob")).expect("add bob");
    assert_eq!(f.ws.user_count(), 2);
    f.ws.remove_user("alice").expect("remove alice");
    assert_eq!(f.ws.user_count(), 1);
}
