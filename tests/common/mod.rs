//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{ConfigureParams, Event, JobId, Mount, NetworkPolicy, Sandbox};

/// Counter to make per-test session_id unique within a single test process.
pub static N: AtomicU32 = AtomicU32::new(0);

/// Process-wide queue of `vm_dir` paths to remove. Populated by
/// `config()`, drained by `config()` (at the start of the next test)
/// and by `SandboxGuard::drop()` (success path).
///
/// CI runs the integration suite with `--test-threads=1`, so tests are
/// strictly serial within a binary and cleaning previously-registered
/// dirs at the start of each test is safe. (A thread-local won't work
/// — libtest can dispatch each test on a fresh worker thread, so
/// cleanup state cannot survive panicking tests via thread-locals.)
static VM_DIRS_TO_CLEAN: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Per-process once-init that wipes any pre-existing `.vm/run-*`
/// directories left over by a previous test binary in the same suite
/// invocation. Cargo runs each `tests/*.rs` as a separate process, so
/// the global mutex above does not survive across binaries, and the
/// last test of the previous binary leaks its ~2 GB `vm_dir`.
static INITIAL_SWEEP: Once = Once::new();

fn drain_pending_vm_dirs() {
    let dirs: Vec<PathBuf> = std::mem::take(&mut VM_DIRS_TO_CLEAN.lock().unwrap());
    for dir in dirs {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn sweep_existing_run_dirs() {
    let Ok(entries) = std::fs::read_dir(".vm") else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("run-") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// RAII guard that calls `stop_vm()` on drop. Prevents VM leaks when a
/// test panics before reaching its explicit `stop_vm()` call.
///
/// On drop the guard also removes any `vm_dir` paths registered by
/// `config()` on this thread. Each per-test `vm_dir` is ~2 GB (full
/// rootfs copy), and CI runners have ~14 GB of free disk — without
/// cleanup the integration suite would exhaust disk after a handful of
/// tests. Cleanup is best-effort: errors are swallowed.
///
/// Usage: `let _guard = SandboxGuard(sb.clone());` after `start_vm()`.
/// The guard's `stop_vm()` is idempotent — calling it again in the test
/// body is harmless.
pub struct SandboxGuard(pub Sandbox);

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        self.0.stop_vm().ok();
        drain_pending_vm_dirs();
    }
}

pub fn workspace_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tokimo-test-{label}"));
    std::fs::create_dir_all(&dir).ok();
    // Make the host-side workspace world-writable. Tests run as
    // whichever user invokes `cargo test` (root in dev, uid 1001 on
    // GitHub runners), but the in-sandbox shell runs in a separate
    // user namespace where the host caller's uid may not be mapped.
    // With DefaultPermissions, the kernel uses the FUSE-reported mode
    // + owner to decide whether the in-sandbox shell can write. By
    // setting 0o777 here we sidestep all userns-mapping subtleties:
    // every test, on every host, can write to /tmp/tokimo-share
    // regardless of how bwrap chose to map uids.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777));
    }
    dir
}

pub fn config(label: &str) -> ConfigureParams {
    INITIAL_SWEEP.call_once(sweep_existing_run_dirs);
    drain_pending_vm_dirs();

    let base_rootfs = std::path::PathBuf::from(".vm/base");
    let base_rootfs = if base_rootfs.exists() {
        base_rootfs.canonicalize().expect("canonicalize .vm/base")
    } else {
        base_rootfs
    };

    let counter = N.load(Ordering::Relaxed);
    let vm_dir = std::path::PathBuf::from(format!(".vm/run-{label}-{counter}"));
    std::fs::create_dir_all(&vm_dir).expect("create vm_dir directory");
    let vm_dir = vm_dir.canonicalize().expect("canonicalize vm_dir directory");

    VM_DIRS_TO_CLEAN.lock().unwrap().push(vm_dir.clone());

    ConfigureParams {
        user_data_name: "test".into(),
        base_rootfs,
        vm_dir,
        memory_mb: 1024,
        cpu_count: 2,
        mounts: vec![Mount {
            name: "ws".into(),
            host_path: workspace_dir(label),
            guest_path: "/tmp/tokimo-share".into(),
            read_only: false,
            create_host_dir: false,
        }],
        network: NetworkPolicy::Blocked,
        session_id: format!("{}-{}-{}", std::process::id(), label, N.fetch_add(1, Ordering::Relaxed)),
        ..Default::default()
    }
}

/// Drain `rx` for stdout chunks belonging to `shell` until either `needle`
/// is seen or the timeout elapses. Returns the captured text either way.
pub fn drain_until(rx: &Receiver<Event>, shell: &JobId, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::<u8>::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            // Capture stderr in addition to stdout. The needle still has
            // to come over stdout (so assertions remain unambiguous), but
            // including stderr in the returned buffer means panicked-test
            // diagnostics actually show the bash error that aborted a
            // `set -e` script, instead of an opaque empty string.
            Ok(Event::Stdout { id, data }) | Ok(Event::Stderr { id, data }) if id == *shell => {
                buf.extend_from_slice(&data);
                if std::str::from_utf8(&buf).map(|s| s.contains(needle)).unwrap_or(false) {
                    break;
                }
            }
            Ok(Event::Exit { id, .. }) if id == *shell => break,
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

pub fn drain_until_for_id(rx: &Receiver<Event>, target: &JobId, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut buf = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Event::Stdout { id, data }) if &id == target => {
                buf.push_str(&String::from_utf8_lossy(&data));
                if buf.contains(needle) {
                    return buf;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    buf
}

/// Byte-exact drain. Collects raw stdout bytes for `target` until either
/// `needle` (as bytes) appears or the timeout elapses.
pub fn drain_bytes_until(rx: &Receiver<Event>, target: &JobId, needle: &[u8], timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Event::Stdout { id, data }) if &id == target => {
                buf.extend_from_slice(&data);
                if buf.windows(needle.len()).any(|w| w == needle) {
                    return buf;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    buf
}

pub fn link_count(rx: &Receiver<Event>, sb: &Sandbox, shell: &JobId) -> usize {
    sb.write_stdin(shell, b"awk 'NR>2 {print}' /proc/net/dev | wc -l; echo LC_DONE_X9F2\n")
        .unwrap();
    let captured = drain_until(rx, shell, "LC_DONE_X9F2", Duration::from_secs(20));
    captured
        .lines()
        .find_map(|l| l.trim().parse::<usize>().ok())
        .unwrap_or_else(|| panic!("no numeric link count line in: {captured:?}"))
}

/// Check whether the host has working IPv6 connectivity by attempting to
/// open a short-lived TCP connection to a known dual-stack endpoint.
pub fn host_has_ipv6() -> bool {
    use std::net::{SocketAddr, TcpStream};
    let addr: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}
