//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{ConfigureParams, Event, JobId, Mount, NetworkPolicy, Sandbox};

/// Counter to make per-test session_id unique within a single test process.
pub static N: AtomicU32 = AtomicU32::new(0);

/// RAII guard that calls `stop_vm()` on drop. Prevents VM leaks when a
/// test panics before reaching its explicit `stop_vm()` call.
///
/// Usage: `let _guard = SandboxGuard(sb.clone());` after `start_vm()`.
/// The guard's `stop_vm()` is idempotent — calling it again in the test
/// body is harmless.
pub struct SandboxGuard(pub Sandbox);

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        self.0.stop_vm().ok();
    }
}

pub fn workspace_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tokimo-test-{label}"));
    std::fs::create_dir_all(&dir).ok();
    dir
}

pub fn config(label: &str) -> ConfigureParams {
    ConfigureParams {
        user_data_name: "test".into(),
        base_rootfs: ".vm/base".into(),
        vm_dir: ".vm/run".into(),
        memory_mb: 1024,
        cpu_count: 2,
        mounts: vec![Mount {
            name: "ws".into(),
            host_path: workspace_dir(label),
            guest_path: "/work".into(),
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
            Ok(Event::Stdout { id, data }) if id == *shell => {
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
