//! Windows one-shot sandbox integration tests.
//!
//! These tests use `tokimo_package_sandbox::run()` which boots a Linux VM
//! via Hyper-V on each call. The `tokimo-sandbox-svc.exe` service must be
//! running (either installed or in `--console` mode).
//!
//! ```bash
//! # Start the service in console mode first:
//! cargo build --bin tokimo-sandbox-svc
//! .\target\debug\tokimo-sandbox-svc.exe --console &
//!
//! # Then run the tests:
//! cargo test --test windows_run
//!
//! # With verbose output:
//! cargo test --test windows_run -- --nocapture
//! ```

mod common;

use tokimo_package_sandbox::{NetworkPolicy, SandboxConfig};

/// Convenience: run a bash one-liner and return `ExecOutput`, or skip if
/// sandbox VM cannot boot (e.g. Hyper-V not available).
macro_rules! try_run {
    ($cfg:expr, $cmd:expr) => {{
        match tokimo_package_sandbox::run(&["bash", "-c", $cmd], $cfg) {
            Ok(r) => tokimo_package_sandbox::ExecOutput {
                stdout: r.stdout,
                stderr: r.stderr,
                exit_code: r.exit_code,
            },
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("0x8037011B") || msg.contains("0x8037") {
                    eprintln!("SKIP: Hyper-V not available");
                    return;
                }
                panic!("run failed: {e}");
            }
        }
    }};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn run_echo_hello() {
    if common::skip_unless_platform_ready() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let out = try_run!(&cfg, "echo hello");
    assert_eq!(out.stdout.trim(), "hello");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn run_stderr_capture() {
    if common::skip_unless_platform_ready() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let out = try_run!(&cfg, "echo to-stderr 1>&2");
    assert_eq!(out.stderr.trim(), "to-stderr");
    assert!(out.stdout.trim().is_empty());
}

#[test]
fn run_exit_code_nonzero() {
    if common::skip_unless_platform_ready() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let out = try_run!(&cfg, "exit 7");
    assert_eq!(out.exit_code, 7);
}

#[test]
fn run_large_output() {
    if common::skip_unless_platform_ready() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path()).network(NetworkPolicy::Blocked);
    let out = try_run!(&cfg, "seq 1 500");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 500);
    assert_eq!(lines[0].trim(), "1");
    assert_eq!(lines[499].trim(), "500");
}

#[test]
fn run_env_var_passed() {
    if common::skip_unless_platform_ready() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .env("MY_VAR", "hello123");
    let out = try_run!(&cfg, "echo $MY_VAR");
    assert_eq!(out.stdout.trim(), "hello123");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn run_stdin_piped() {
    if common::skip_unless_platform_ready() {
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .stdin_str("from-stdin");
    let out = try_run!(&cfg, "cat");
    assert_eq!(out.stdout.trim(), "from-stdin");
}
