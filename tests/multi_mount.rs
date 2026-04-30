//! Windows-only integration tests covering the V2 wire protocol features:
//!
//! 1. Multiple Plan9 shares per session (one RW + one RO extra mount in
//!    addition to the workspace).
//! 2. Persistent rootfs VHDX: state under writable system paths survives
//!    a session close + reopen at the same target path.
//! 3. Persistent rootfs busy rejection: a second `Session::open` against
//!    the same persistent target while the first session is alive must
//!    fail with `Error::SessionAlreadyActive`.
//!
//! ```bash
//! cargo test --test multi_mount -- --test-threads=1
//! ```

#![cfg(target_os = "windows")]

mod common;

use std::fs;
use tokimo_package_sandbox::{Error, Mount, NetworkPolicy, SandboxConfig, Session};

macro_rules! require_session {
    () => {
        if common::skip_unless_platform_ready() || common::skip_unless_session_supported() {
            return;
        }
    };
}

#[test]
fn multi_share_rw_ro() {
    require_session!();

    let work = tempfile::tempdir().expect("work tempdir");
    let ro_src = tempfile::tempdir().expect("ro tempdir");
    let rw_src = tempfile::tempdir().expect("rw tempdir");

    fs::write(ro_src.path().join("readme.txt"), b"ro-share-marker").expect("seed ro");

    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .mount(Mount::ro(ro_src.path()).guest("/mnt/ro_share"))
        .mount(Mount::rw(rw_src.path()).guest("/mnt/rw_share"));

    let mut sess = Session::open(&cfg).expect("Session::open");

    let out = sess.exec("cat /mnt/ro_share/readme.txt").expect("read ro share");
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("ro-share-marker"), "ro contents: {}", out.stdout);

    let out = sess
        .exec("touch /mnt/ro_share/should_fail 2>&1; echo RC=$?")
        .expect("attempt rw to ro");
    assert!(
        out.stdout.contains("RC=") && !out.stdout.contains("RC=0"),
        "RO mount must reject writes, got: {}",
        out.stdout
    );

    let out = sess
        .exec("echo rw-marker > /mnt/rw_share/written.txt && echo OK")
        .expect("write rw share");
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("OK"), "rw write failed: {}", out.stdout);

    let host_written = rw_src.path().join("written.txt");
    let bytes = fs::read(&host_written).expect("host should see rw write");
    assert!(
        String::from_utf8_lossy(&bytes).contains("rw-marker"),
        "host file contents: {:?}",
        bytes
    );

    sess.close().expect("close");
}

#[test]
fn persistent_rootfs_survives_session() {
    require_session!();

    let work = tempfile::tempdir().expect("work");
    let store = tempfile::tempdir().expect("store");
    let target = store.path().join("persist.vhdx");

    {
        let cfg = SandboxConfig::new(work.path())
            .network(NetworkPolicy::Blocked)
            .persistent_rootfs(&target);
        let mut sess = Session::open(&cfg).expect("first open");
        let out = sess
            .exec("echo persist-marker > /var/tokimo_marker && sync")
            .expect("write marker");
        assert_eq!(out.exit_code, 0);
        sess.close().expect("close first session");
    }

    assert!(target.is_file(), "persistent vhdx should remain at {target:?}");

    {
        let cfg = SandboxConfig::new(work.path())
            .network(NetworkPolicy::Blocked)
            .persistent_rootfs(&target);
        let mut sess = Session::open(&cfg).expect("second open");
        let out = sess.exec("cat /var/tokimo_marker").expect("read marker");
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("persist-marker"),
            "marker not persisted, got: {}",
            out.stdout
        );
        sess.close().expect("close second session");
    }
}

#[test]
fn persistent_rootfs_busy_rejected() {
    require_session!();

    let work_a = tempfile::tempdir().expect("work A");
    let work_b = tempfile::tempdir().expect("work B");
    let store = tempfile::tempdir().expect("store");
    let target = store.path().join("busy.vhdx");

    let cfg_a = SandboxConfig::new(work_a.path())
        .network(NetworkPolicy::Blocked)
        .persistent_rootfs(&target);
    let mut sess_a = Session::open(&cfg_a).expect("open A");

    let cfg_b = SandboxConfig::new(work_b.path())
        .network(NetworkPolicy::Blocked)
        .persistent_rootfs(&target);
    let err = match Session::open(&cfg_b) {
        Ok(_) => panic!("second open must fail while A holds the lease"),
        Err(e) => e,
    };
    assert!(
        matches!(err, Error::SessionAlreadyActive),
        "expected SessionAlreadyActive, got: {err:?}"
    );

    let _ = sess_a.exec("echo still-alive").expect("A still works");
    sess_a.close().expect("close A");

    // After A closes, the lease should be released and a new session can
    // re-acquire the same persistent target.
    let cfg_c = SandboxConfig::new(work_b.path())
        .network(NetworkPolicy::Blocked)
        .persistent_rootfs(&target);
    let sess_c = Session::open(&cfg_c).expect("reopen after close");
    sess_c.close().expect("close C");
}
