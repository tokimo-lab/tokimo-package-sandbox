mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::{Mount, Sandbox};

const SLIDE_NAMES: &[&str] = &["slide-1.jpg", "slide-2.jpg", "slide-3.jpg"];

fn seed_slide_files(label: &str) -> std::path::PathBuf {
    let ws = workspace_dir(label);
    for name in SLIDE_NAMES {
        std::fs::write(ws.join(name), b"fake-jpeg").expect("write seed file");
    }
    ws
}

fn cleanup_slide_files(ws: &std::path::Path) {
    for name in SLIDE_NAMES {
        let _ = std::fs::remove_file(ws.join(name));
    }
}

fn run_sandbox_command(label: &str, command: &[u8], marker: &str) -> String {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, command).unwrap();
    let captured = drain_until(&rx, &shell, marker, Duration::from_secs(30));

    sb.stop_vm().ok();
    captured
}

fn assert_all_slide_names(captured: &str) {
    for name in SLIDE_NAMES {
        assert!(
            captured.contains(name),
            "expected {name} in output. captured: {captured:?}"
        );
    }
}

#[test]
fn fuse_host_file_visible_in_guest() {
    const FNAME: &str = "tokimo_sentinel.txt";
    const BODY: &str = "SENTINEL_FROM_HOST_5C9D";

    // We need to write the file on the host *before* configure picks up
    // the workspace path. config(label) creates a per-label tmp dir and
    // shares it as /work — write the sentinel into that exact dir.
    let label = "p9visible";
    let host_path = workspace_dir(label).join(FNAME);
    std::fs::write(&host_path, BODY).expect("write sentinel on host");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, format!("cat /work/{FNAME}\n").as_bytes())
        .unwrap();

    let captured = drain_until(&rx, &shell, BODY, Duration::from_secs(30));
    sb.stop_vm().ok();
    let _ = std::fs::remove_file(&host_path);

    assert!(
        captured.contains(BODY),
        "host sentinel not visible in guest. captured: {captured:?}"
    );
}

#[test]
fn fuse_dynamic_add_remove() {
    const FNAME: &str = "extra_sentinel.txt";
    const BODY: &str = "DYNAMIC_5E7C_HOST";

    let label = "p9dyn";
    let extra = workspace_dir(&format!("{label}-extra"));
    std::fs::write(extra.join(FNAME), BODY).expect("write sentinel");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // 1. Before add: /extra is empty / nonexistent.
    sb.write_stdin(&shell, b"ls /extra 2>&1 | head -1; echo PRE_DONE_1AB\n")
        .unwrap();
    let pre = drain_until(&rx, &shell, "PRE_DONE_1AB", Duration::from_secs(20));
    assert!(
        !pre.contains(BODY),
        "extra share already mounted before add. captured: {pre:?}"
    );

    // 2. Add share, then read sentinel from inside the guest.
    sb.add_mount(Mount {
        name: "extra".into(),
        host_path: extra.clone(),
        guest_path: "/extra".into(),
        read_only: false,
        create_host_dir: false,
    })
    .expect("add_mount");
    sb.write_stdin(&shell, format!("cat /extra/{FNAME}; echo POST_ADD_2CD\n").as_bytes())
        .unwrap();
    let post = drain_until(&rx, &shell, "POST_ADD_2CD", Duration::from_secs(30));
    assert!(
        post.contains(BODY),
        "after add, sentinel not visible. captured: {post:?}"
    );

    // 3. Remove share. After this, /extra may be empty or fail to read.
    sb.remove_mount("extra").expect("remove_mount");
    sb.write_stdin(
        &shell,
        format!("cat /extra/{FNAME} 2>&1; echo POST_REM_3EF\n").as_bytes(),
    )
    .unwrap();
    let removed = drain_until(&rx, &shell, "POST_REM_3EF", Duration::from_secs(20));
    assert!(
        !removed.contains(BODY),
        "after remove, sentinel still readable. captured: {removed:?}"
    );

    sb.stop_vm().ok();
}

/// Verify that glob expansion (`ls slide-*.jpg`) inside a FUSE-mounted
/// directory does not produce spurious I/O errors.  Regression test for
/// a FUSE readdir issue that returned `nodeid: 0` for all entries,
/// causing the Linux kernel to drop them from glob expansion.
#[test]
fn fuse_glob_no_io_error() {
    const MARKER: &str = "GLOB_DONE_A1B2";

    let label = "fuseglob";
    let ws = workspace_dir(label);

    // Seed files so the glob has something to match.
    for name in &["slide-01.jpg", "slide-02.jpg", "slide-03.jpg"] {
        std::fs::write(ws.join(name), b"fake-jpeg").expect("write seed file");
    }

    let captured = run_sandbox_command(label, b"ls /work/slide-*.jpg 2>&1; echo GLOB_DONE_A1B2\n", MARKER);

    for name in &["slide-01.jpg", "slide-02.jpg", "slide-03.jpg"] {
        let _ = std::fs::remove_file(ws.join(name));
    }

    assert!(
        !captured.contains("Input/output error"),
        "FUSE glob produced an I/O error. captured: {captured:?}"
    );
    assert!(
        captured.contains("slide-01.jpg"),
        "expected slide-01.jpg in ls output. captured: {captured:?}"
    );
}

#[test]
fn fuse_bash_echo_glob_expands() {
    const MARKER: &str = "BASH_ECHO_GLOB_DONE_C3D4";

    let label = "fusebashechoglob";
    let ws = seed_slide_files(label);
    let captured = run_sandbox_command(
        label,
        b"bash -c 'cd /work && echo slide-*.jpg'; echo BASH_ECHO_GLOB_DONE_C3D4\n",
        MARKER,
    );
    cleanup_slide_files(&ws);

    assert_all_slide_names(&captured);
    assert!(
        !captured.contains("slide-*.jpg"),
        "bash echoed the literal glob instead of expanding it. captured: {captured:?}"
    );
}

#[test]
fn fuse_bash_dash_c_ls_glob() {
    const MARKER: &str = "BASH_LS_GLOB_DONE_E5F6";

    let label = "fusebashlsglob";
    let ws = seed_slide_files(label);
    let captured = run_sandbox_command(
        label,
        b"bash -c 'ls /work/slide-*.jpg' 2>&1; echo BASH_LS_GLOB_DONE_E5F6\n",
        MARKER,
    );
    cleanup_slide_files(&ws);

    assert!(
        !captured.contains("Input/output error"),
        "bash ls glob produced an I/O error. captured: {captured:?}"
    );
    assert_all_slide_names(&captured);
}

#[test]
fn fuse_bash_glob_no_match() {
    const MARKER: &str = "BASH_GLOB_NO_MATCH_DONE_A7B8";

    let label = "fusebashglobnomatch";
    let captured = run_sandbox_command(
        label,
        b"bash -c 'ls /work/nonexistent-*.jpg' 2>&1 || true; echo BASH_GLOB_NO_MATCH_DONE_A7B8\n",
        MARKER,
    );

    assert!(
        captured.contains("No such file") || captured.contains("cannot access"),
        "expected ENOENT-ish ls error for unmatched glob literal. captured: {captured:?}"
    );
    assert!(
        !captured.contains("Input/output error"),
        "unmatched glob literal produced an I/O error. captured: {captured:?}"
    );
}
