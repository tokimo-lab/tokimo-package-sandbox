//! macOS VZ Workspace integration tests.
//!
//! Multi-user sandbox tests for the VZ backend. Requires kernel + initrd +
//! rootfs artifacts.

#![cfg(target_os = "macos")]

use std::time::Duration;

use tokimo_package_sandbox::{UserConfig, Workspace, WorkspaceConfig};

fn skip_if_no_vz() -> bool {
    let vmlinuz = std::env::var("TOKIMO_VZ_KERNEL").ok().or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.tokimo/kernel/vmlinuz"))
    });
    let Some(kernel) = vmlinuz else {
        eprintln!("SKIP: TOKIMO_VZ_KERNEL not set");
        return true;
    };
    if !std::path::Path::new(&kernel).exists() {
        eprintln!("SKIP: kernel not found at {kernel}");
        return true;
    }
    if !arcbox_vz::is_supported() {
        eprintln!("SKIP: Virtualization.framework not available");
        return true;
    }
    false
}

#[test]
fn two_users_exec_independently() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    ws.add_user(&UserConfig::new("alice")).expect("add alice");
    ws.add_user(&UserConfig::new("bob")).expect("add bob");

    ws.exec_default("alice", "export ALICE_ONLY=42").expect("exec alice");
    ws.exec_default("bob", "export BOB_ONLY=99").expect("exec bob");

    let a_out = ws
        .exec_default("alice", "echo A=$ALICE_ONLY B=$BOB_ONLY")
        .expect("exec alice check");
    let b_out = ws
        .exec_default("bob", "echo A=$ALICE_ONLY B=$BOB_ONLY")
        .expect("exec bob check");

    assert!(a_out.stdout.contains("A=42"), "alice should see A=42: {}", a_out.stdout);
    assert!(
        !a_out.stdout.contains("B=99"),
        "alice should not see B=99: {}",
        a_out.stdout
    );
    assert!(
        !b_out.stdout.contains("A=42"),
        "bob should not see A=42: {}",
        b_out.stdout
    );
    assert!(b_out.stdout.contains("B=99"), "bob should see B=99: {}", b_out.stdout);

    ws.close().expect("close");
}

#[test]
fn add_user_creates_isolated_tmp() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    ws.add_user(&UserConfig::new("alice")).expect("add alice");

    let out = ws.exec_default("alice", "echo $TMPDIR").expect("exec");
    assert!(
        out.stdout.contains("alice"),
        "TMPDIR should contain user id: {}",
        out.stdout
    );

    ws.close().expect("close");
}

#[test]
fn remove_user_does_not_affect_other() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    ws.add_user(&UserConfig::new("alice")).expect("add alice");
    ws.add_user(&UserConfig::new("bob")).expect("add bob");

    ws.remove_user("alice").expect("remove alice");

    // Bob should still work.
    let out = ws.exec_default("bob", "echo STILL_HERE").expect("exec bob");
    assert_eq!(out.stdout.trim(), "STILL_HERE");

    // Alice should be gone.
    let err = ws.exec_default("alice", "echo NOPE").unwrap_err();
    assert!(err.to_string().contains("not found"), "expected 'not found': {err}");

    ws.close().expect("close");
}

#[test]
fn add_user_after_remove() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    ws.add_user(&UserConfig::new("alice")).expect("add alice");
    ws.remove_user("alice").expect("remove alice");
    ws.add_user(&UserConfig::new("alice")).expect("re-add alice");

    let out = ws.exec_default("alice", "echo BACK").expect("exec");
    assert_eq!(out.stdout.trim(), "BACK");

    ws.close().expect("close");
}

#[test]
fn three_users_concurrent_exec() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    ws.add_user(&UserConfig::new("u1")).expect("add u1");
    ws.add_user(&UserConfig::new("u2")).expect("add u2");
    ws.add_user(&UserConfig::new("u3")).expect("add u3");

    for uid in &["u1", "u2", "u3"] {
        ws.exec_default(uid, &format!("export MYVAR={uid}_val"))
            .expect("exec export");
    }

    for uid in &["u1", "u2", "u3"] {
        let out = ws.exec_default(uid, "echo $MYVAR").expect("exec read");
        assert!(
            out.stdout.contains(&format!("{uid}_val")),
            "{} should see its own var: {}",
            uid,
            out.stdout
        );
    }

    ws.close().expect("close");
}

#[test]
fn user_count_reflects_add_remove() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    assert_eq!(ws.user_count(), 0);

    ws.add_user(&UserConfig::new("a")).expect("add a");
    assert_eq!(ws.user_count(), 1);

    ws.add_user(&UserConfig::new("b")).expect("add b");
    assert_eq!(ws.user_count(), 2);

    ws.remove_user("a").expect("remove a");
    assert_eq!(ws.user_count(), 1);

    ws.close().expect("close");
}

#[test]
fn workspace_close_cleans_up() {
    if skip_if_no_vz() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = WorkspaceConfig::new(tmp.path());
    let mut ws = Workspace::open(&cfg).expect("Workspace::open");
    ws.add_user(&UserConfig::new("alice")).expect("add alice");
    ws.close().expect("close");
}
