mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

#[test]
fn shared_session_two_handles_see_same_shell() {
    let cfg = config("share_same");

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg.clone()).expect("configure 1");
    sb1.start_vm().expect("start_vm");
    let _guard1 = SandboxGuard(sb1.clone());
    let shell_a = sb1.shell_id().expect("shell_id 1");

    // Second connect with the same session_id MUST observe the running
    // VM and return the same boot-shell JobId.
    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg.clone()).expect("configure 2 idempotent");
    assert!(sb2.is_running().expect("is_running 2"));
    let shell_b = sb2.shell_id().expect("shell_id 2");
    assert_eq!(shell_a, shell_b, "same session_id must share the boot shell");

    // start_vm on the second handle must also be idempotent.
    sb2.start_vm().expect("start_vm 2 idempotent");
    let _guard2 = SandboxGuard(sb2.clone());

    sb1.stop_vm().expect("stop_vm");
    // After teardown, the second handle observes the VM as not running.
    assert!(!sb2.is_running().unwrap_or(true));
}

#[test]
fn shared_session_writes_visible_via_other_handle() {
    let cfg = config("share_io");

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg.clone()).expect("configure 1");
    let rx = sb1.subscribe().expect("subscribe");
    sb1.start_vm().expect("start_vm");
    let _guard1 = SandboxGuard(sb1.clone());
    let shell = sb1.shell_id().expect("shell_id");

    // Drive stdin from the *second* handle, observe events on the first.
    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg.clone()).expect("configure 2");

    const TOKEN: &str = "SHARED_OK_8E1A";
    sb2.write_stdin(&shell, format!("echo {TOKEN}\n").as_bytes())
        .expect("write_stdin via sb2");

    let captured = drain_until(&rx, &shell, TOKEN, Duration::from_secs(20));
    assert!(
        captured.contains(TOKEN),
        "stdout from shared session not seen, got: {captured:?}"
    );

    sb1.stop_vm().expect("stop_vm");
}

#[test]
fn stop_from_one_handle_tears_down_for_others() {
    let cfg = config("share_stop");

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg.clone()).expect("configure 1");
    sb1.start_vm().expect("start_vm");
    let _guard1 = SandboxGuard(sb1.clone());

    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg.clone()).expect("configure 2");
    assert!(sb2.is_running().expect("is_running 2"));

    // Stop from sb2.
    sb2.stop_vm().expect("stop_vm via sb2");

    // sb1's view is now also "not running".
    assert!(!sb1.is_running().unwrap_or(true), "stop must affect all handles");
    // shell_id on sb1 should now error (VmNotRunning).
    assert!(sb1.shell_id().is_err(), "shell_id after shared stop must error");
}

#[test]
fn empty_session_id_is_not_shared() {
    // Empty session_id → untracked, fresh backend per handle. Two
    // such handles must NOT share a VM.  Proof: writes are isolated
    // to each handle's event stream.
    let mut cfg_a = config("empty_a");
    cfg_a.session_id = String::new();
    let mut cfg_b = config("empty_b");
    cfg_b.session_id = String::new();

    let sb1 = Sandbox::connect().expect("connect 1");
    sb1.configure(cfg_a).expect("configure 1");
    let rx1 = sb1.subscribe().expect("subscribe 1");
    sb1.start_vm().expect("start_vm 1");
    let _guard1 = SandboxGuard(sb1.clone());
    let shell_1 = sb1.shell_id().expect("shell_id 1");

    let sb2 = Sandbox::connect().expect("connect 2");
    sb2.configure(cfg_b).expect("configure 2");
    let rx2 = sb2.subscribe().expect("subscribe 2");
    sb2.start_vm().expect("start_vm 2");
    let _guard2 = SandboxGuard(sb2.clone());
    let shell_2 = sb2.shell_id().expect("shell_id 2");

    const TOK1: &str = "EMPTY_ONE_DA32";
    const TOK2: &str = "EMPTY_TWO_DA32";
    sb1.write_stdin(&shell_1, format!("echo {TOK1}\n").as_bytes()).unwrap();
    sb2.write_stdin(&shell_2, format!("echo {TOK2}\n").as_bytes()).unwrap();

    let o1 = drain_until(&rx1, &shell_1, TOK1, Duration::from_secs(20));
    let o2 = drain_until(&rx2, &shell_2, TOK2, Duration::from_secs(20));
    assert!(o1.contains(TOK1) && !o1.contains(TOK2), "VM1 saw VM2 output");
    assert!(o2.contains(TOK2) && !o2.contains(TOK1), "VM2 saw VM1 output");

    sb1.stop_vm().ok();
    sb2.stop_vm().ok();
}
