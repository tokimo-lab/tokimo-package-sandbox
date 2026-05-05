mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

#[test]
fn multi_session_concurrent() {
    use std::thread;

    let h1 = thread::spawn(|| run_marker_session("session-A", "MARKER_A_4F2"));
    let h2 = thread::spawn(|| run_marker_session("session-B", "MARKER_B_8E1"));
    h1.join().expect("session-A panicked");
    h2.join().expect("session-B panicked");
}

fn run_marker_session(label: &str, marker: &str) {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, format!("echo {marker}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, marker, Duration::from_secs(45));
    sb.stop_vm().ok();

    assert!(
        captured.contains(marker),
        "[{label}] marker not seen. captured: {captured:?}"
    );
}

#[test]
fn distinct_session_ids_get_distinct_vms() {
    // Two configs with **different** session_ids → two separate VMs.
    // Proof: writes into VM A only show up on A's event stream; B's
    // stream sees only B's writes.  (JobId values are not a proxy
    // for distinctness — each VM numbers shells locally.)
    let cfg_a = config("distinct_a");
    let cfg_b = config("distinct_b");

    let sb_a = Sandbox::connect().expect("connect a");
    sb_a.configure(cfg_a).expect("configure a");
    let rx_a = sb_a.subscribe().expect("subscribe a");
    sb_a.start_vm().expect("start_vm a");
    let _guard_a = SandboxGuard(sb_a.clone());
    let shell_a = sb_a.shell_id().expect("shell_id a");

    let sb_b = Sandbox::connect().expect("connect b");
    sb_b.configure(cfg_b).expect("configure b");
    let rx_b = sb_b.subscribe().expect("subscribe b");
    sb_b.start_vm().expect("start_vm b");
    let _guard_b = SandboxGuard(sb_b.clone());
    let shell_b = sb_b.shell_id().expect("shell_id b");

    const TOK_A: &str = "DISTINCT_A_4F1C";
    const TOK_B: &str = "DISTINCT_B_4F1C";
    sb_a.write_stdin(&shell_a, format!("echo {TOK_A}\n").as_bytes())
        .expect("write a");
    sb_b.write_stdin(&shell_b, format!("echo {TOK_B}\n").as_bytes())
        .expect("write b");

    let out_a = drain_until(&rx_a, &shell_a, TOK_A, Duration::from_secs(20));
    let out_b = drain_until(&rx_b, &shell_b, TOK_B, Duration::from_secs(20));
    assert!(out_a.contains(TOK_A) && !out_a.contains(TOK_B), "A leaked B's output");
    assert!(out_b.contains(TOK_B) && !out_b.contains(TOK_A), "B leaked A's output");

    // Stopping A must not affect B.
    sb_a.stop_vm().expect("stop_vm a");
    assert!(
        sb_b.is_running().expect("is_running b after stop a"),
        "stopping VM A must not affect VM B"
    );
    sb_b.stop_vm().expect("stop_vm b");
}
