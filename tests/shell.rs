mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

#[test]
fn shell_env_does_not_leak_init_control_vars() {
    // Regression test: init's private control env vars
    // (TOKIMO_SANDBOX_CONTROL_FD, TOKIMO_SANDBOX_BRINGUP_LO,
    // TOKIMO_SANDBOX_MOUNT_SYSFS, TOKIMO_SANDBOX_SECCOMP_B64, ...) must
    // never be visible inside the sandbox. They were previously snapshotted
    // verbatim by `snapshot_base_env` and inherited by every shell child.
    const END: &str = "END_ENV_LEAK_9C7B";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("envleak")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, b"env | grep -c '^TOKIMO_SANDBOX_' || true\n")
        .unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    // `grep -c` prints "0" when nothing matches. Anything else means leakage.
    let count_line = captured
        .lines()
        .rfind(|l| l.trim().chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("");
    assert_eq!(
        count_line.trim(),
        "0",
        "TOKIMO_SANDBOX_* env vars leaked into shell. captured: {captured:?}"
    );
}

#[test]
fn shell_stdout_echo() {
    const MARKER: &str = "TOKIMO_MARKER_8F2E";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("echo")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, format!("echo {MARKER}\n").as_bytes())
        .expect("write_stdin");

    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(
        captured.contains(MARKER),
        "marker never seen on stdout. captured: {captured:?}"
    );
}

#[test]
fn shell_runs_multiple_commands() {
    const END: &str = "END_MULTI_5A1F";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("multicmd")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, b"pwd\n").unwrap();
    sb.write_stdin(&shell, b"uname -s\n").unwrap();
    sb.write_stdin(&shell, b"id -u\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(captured.contains("Linux"), "missing uname output: {captured:?}");
    assert!(captured.contains(END), "missing terminator: {captured:?}");
}
