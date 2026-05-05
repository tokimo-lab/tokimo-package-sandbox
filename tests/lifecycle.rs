mod common;

use common::{SandboxGuard, config};
use tokimo_package_sandbox::Sandbox;

#[test]
fn lifecycle_start_and_stop() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("basic")).expect("configure");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell = sb.shell_id().expect("shell_id");
    assert!(!shell.as_str().is_empty(), "shell id must not be empty");
    assert!(sb.is_running().expect("is_running"));

    sb.stop_vm().expect("stop_vm");
}

#[test]
fn shell_id_before_start() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("nostart")).expect("configure");
    assert!(sb.shell_id().is_err(), "shell_id should fail before start_vm");
}

#[test]
fn shell_id_after_stop_is_error() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("after_stop")).expect("configure");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.shell_id().expect("shell_id during run");
    sb.stop_vm().expect("stop_vm");
    assert!(sb.shell_id().is_err(), "shell_id after stop must fail");
}
