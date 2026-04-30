//! macOS VZ multi-mount integration tests.
//!
//! Validates `cfg.extra_mounts` is honored on the macOS backend via
//! per-mount virtiofs devices + `Op::MountManifest`. RW propagation in both
//! directions and RO enforcement are checked.
//!
//! Skipped unless kernel/initrd/rootfs artifacts are present (same checks as
//! `vz_session.rs`).

#![cfg(target_os = "macos")]

mod common;

use std::fs;

use tokimo_package_sandbox::{Mount, NetworkPolicy, SandboxConfig, Session};

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
    if !arcbox_vz::is_supported() {
        eprintln!("SKIP: Virtualization.framework not available");
        return true;
    }
    false
}

fn setup_work_dir() -> tempfile::TempDir {
    let work = tempfile::tempdir().expect("work tempdir");
    common::clone_rootfs_to(work.path());
    work
}

#[test]
fn multi_mount_rw_and_ro_propagate() {
    if skip_if_no_vz() {
        return;
    }

    let work = setup_work_dir();

    // Two extra host directories: one RW, one RO.
    let rw_host = tempfile::tempdir().expect("rw host tempdir");
    let ro_host = tempfile::tempdir().expect("ro host tempdir");
    fs::write(rw_host.path().join("from_host.txt"), "hello-from-host-rw").expect("seed RW host file");
    fs::write(ro_host.path().join("readme.txt"), "ro-content").expect("seed RO host file");

    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .mount(Mount {
            host: rw_host.path().to_path_buf(),
            guest: Some("/mnt/rw".into()),
            read_only: false,
        })
        .mount(Mount {
            host: ro_host.path().to_path_buf(),
            guest: Some("/mnt/ro".into()),
            read_only: true,
        });

    let mut sess = Session::open(&cfg).expect("Session::open");

    // host -> guest read (RW share).
    let out = sess.exec("cat /mnt/rw/from_host.txt").expect("cat rw");
    assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    assert_eq!(out.stdout.trim(), "hello-from-host-rw");

    // host -> guest read (RO share).
    let out = sess.exec("cat /mnt/ro/readme.txt").expect("cat ro");
    assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    assert_eq!(out.stdout.trim(), "ro-content");

    // guest -> host write (RW share).
    let out = sess
        .exec("printf 'guest-wrote-this' > /mnt/rw/from_guest.txt")
        .expect("write rw");
    assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    let host_view = fs::read_to_string(rw_host.path().join("from_guest.txt")).expect("host should see guest write");
    assert_eq!(host_view, "guest-wrote-this");

    // guest -> RO share write must fail.
    let out = sess
        .exec("printf 'nope' > /mnt/ro/forbidden.txt 2>&1; echo rc=$?")
        .expect("write ro");
    assert_ne!(
        out.stdout.trim().lines().last().unwrap_or(""),
        "rc=0",
        "RO write unexpectedly succeeded; output: {}",
        out.stdout
    );
    assert!(
        !ro_host.path().join("forbidden.txt").exists(),
        "RO mount should not have leaked the write back to host"
    );
}
