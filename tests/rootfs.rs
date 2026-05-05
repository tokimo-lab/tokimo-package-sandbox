mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

#[test]
fn rootfs_node_version() {
    const END: &str = "ROOTFS_NODE_END_3A1F";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("rootfs-node")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, b"node --version\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    let line = captured.lines().find(|l| l.trim_start().starts_with('v')).unwrap_or("");
    assert!(
        line.trim().starts_with("v24."),
        "expected Node 24.x from packaged rootfs, got: {captured:?}"
    );
}

#[test]
fn rootfs_python_version() {
    const END: &str = "ROOTFS_PY_END_5B2E";

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("rootfs-py")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, b"python3 --version\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(
        captured.contains("Python 3."),
        "expected Python 3.x from packaged rootfs, got: {captured:?}"
    );
}
