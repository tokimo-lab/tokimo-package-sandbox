//! Verifies that *external* (host-side) mutations to a `LocalDirVfs`
//! mount become visible inside the guest within a short window, even
//! when the guest has already cached the entry/attrs.
//!
//! Today this fails: entry/attr TTL is 60s and nothing on the host
//! invalidates the kernel dentry cache when an outside process writes
//! to the backing directory. The intended fix is an inotify
//! (Linux) / FSEvents (macOS) / ReadDirectoryChangesW (Windows) watcher
//! that translates external mutations into `FUSE_NOTIFY_INVAL_ENTRY` /
//! `FUSE_NOTIFY_INVAL_INODE` frames.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::Sandbox;

/// Time the guest has to observe a host-side change before we declare
/// failure. Generous enough to cover FSEvents (~30-60ms) plus a few
/// FUSE round trips.
const VISIBILITY_WINDOW: Duration = Duration::from_secs(2);

/// Marker the guest echoes to signal the end of its read loop.
const DONE_MARKER: &str = "__TOKIMO_DONE_MARKER__";

/// External write to a pre-cached file becomes visible to the guest.
///
/// Sequence:
///  1. Host seeds `file.txt` with `OLD`.
///  2. Guest `cat`s it → kernel caches dentry + attrs + 3 bytes of page
///     cache.
///  3. Host (this test process) overwrites with `NEW_CONTENT_42`.
///  4. Guest `cat`s again *within* the TTL window.
///
/// Expected: second `cat` prints `NEW_CONTENT_42`.
/// Current (broken) behavior: prints `OLD`.
///
/// Marked `#[ignore]` until the host-side filesystem watcher lands.
/// Run explicitly with `cargo test -- --ignored
/// external_overwrite_visible_to_guest`.
#[test]
#[ignore = "fails until host-side inotify/FSEvents watcher pushes INVAL_INODE; see plan.md"]
fn external_overwrite_visible_to_guest() {
    let label = "extinval-overwrite";
    let ws = workspace_dir(label);
    let file_host = ws.join("file.txt");
    std::fs::write(&file_host, b"OLD").expect("seed file");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // 1. Prime the guest cache.
    sb.write_stdin(&shell, b"cat /tmp/tokimo-share/file.txt; echo ' PRIMED'\n")
        .unwrap();
    let primed = drain_until(&rx, &shell, "PRIMED", Duration::from_secs(10));
    assert!(
        primed.contains("OLD"),
        "guest did not see seeded content. captured: {primed:?}"
    );

    // 2. External (host-side) overwrite.
    std::fs::write(&file_host, b"NEW_CONTENT_42").expect("overwrite on host");

    // 3. Give the host watcher up to VISIBILITY_WINDOW to push an
    //    INVAL_INODE/INVAL_ENTRY. (`sleep` runs in the guest so we don't
    //    race the FUSE notify path with our own read.)
    sb.write_stdin(
        &shell,
        format!(
            "sleep {}; cat /tmp/tokimo-share/file.txt; echo ' {DONE_MARKER}'\n",
            VISIBILITY_WINDOW.as_secs_f32()
        )
        .as_bytes(),
    )
    .unwrap();
    let observed = drain_until(&rx, &shell, DONE_MARKER, Duration::from_secs(15));

    sb.stop_vm().ok();
    let _ = std::fs::remove_file(&file_host);

    assert!(
        observed.contains("NEW_CONTENT_42"),
        "external overwrite not visible inside TTL window. observed: {observed:?}"
    );
    assert!(
        !observed.contains("OLD"),
        "stale content still served. observed: {observed:?}"
    );
}

/// External `mkdir` becomes visible in `readdir` output.
#[test]
fn external_mkdir_visible_to_guest() {
    let label = "extinval-mkdir";
    let ws = workspace_dir(label);
    // Seed something so the directory itself exists and is cached.
    std::fs::write(ws.join("placeholder"), b"x").expect("seed placeholder");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // 1. Prime: list the directory.
    sb.write_stdin(&shell, b"ls /tmp/tokimo-share; echo ' PRIMED'\n")
        .unwrap();
    let _ = drain_until(&rx, &shell, "PRIMED", Duration::from_secs(10));

    // 2. Host creates a new entry.
    let new_dir = ws.join("freshly_minted_by_host");
    std::fs::create_dir(&new_dir).expect("mkdir on host");

    // 3. Guest lists again.
    sb.write_stdin(
        &shell,
        format!(
            "sleep {}; ls /tmp/tokimo-share; echo ' {DONE_MARKER}'\n",
            VISIBILITY_WINDOW.as_secs_f32()
        )
        .as_bytes(),
    )
    .unwrap();
    let observed = drain_until(&rx, &shell, DONE_MARKER, Duration::from_secs(15));

    sb.stop_vm().ok();
    let _ = std::fs::remove_dir(&new_dir);
    let _ = std::fs::remove_file(ws.join("placeholder"));

    assert!(
        observed.contains("freshly_minted_by_host"),
        "host-side mkdir not visible in guest readdir. observed: {observed:?}"
    );
}

/// External `unlink` propagates: a previously-cached entry becomes ENOENT.
#[test]
fn external_unlink_visible_to_guest() {
    let label = "extinval-unlink";
    let ws = workspace_dir(label);
    let victim = ws.join("victim.txt");
    std::fs::write(&victim, b"doomed").expect("seed victim");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Prime.
    sb.write_stdin(&shell, b"cat /tmp/tokimo-share/victim.txt; echo ' PRIMED'\n")
        .unwrap();
    let primed = drain_until(&rx, &shell, "PRIMED", Duration::from_secs(10));
    assert!(primed.contains("doomed"));

    // External unlink.
    std::fs::remove_file(&victim).expect("host unlink");

    // Guest probes existence. `stat` exits non-zero with ENOENT and
    // prints to stderr; we look for the literal "No such file" or the
    // GONE marker if the access path matters.
    sb.write_stdin(
        &shell,
        format!(
            "sleep {}; stat /tmp/tokimo-share/victim.txt 2>&1; echo ' {DONE_MARKER}'\n",
            VISIBILITY_WINDOW.as_secs_f32()
        )
        .as_bytes(),
    )
    .unwrap();
    let observed = drain_until(&rx, &shell, DONE_MARKER, Duration::from_secs(15));

    sb.stop_vm().ok();

    assert!(
        observed.contains("No such file") || observed.contains("cannot stat"),
        "external unlink not visible in guest. observed: {observed:?}"
    );
}
