mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, drain_until_for_id};
use tokimo_package_sandbox::{Event, Sandbox, ShellOpts};

#[test]
fn multi_shell_isolated_streams() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("multi-shell")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell_a = sb.shell_id().expect("shell_id (boot shell = A)");
    let shell_b = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell B");
    assert_ne!(shell_a, shell_b, "spawn_shell must yield a fresh JobId");

    // Send distinct markers to each shell. Stdout streams MUST be tagged
    // with the right JobId — A's marker only on A's stream, B's only on B.
    sb.write_stdin(&shell_a, b"echo MARK_FROM_A_F00D\n").unwrap();
    sb.write_stdin(&shell_b, b"echo MARK_FROM_B_BEEF\n").unwrap();

    // Single drain loop — events for A and B arrive interleaved on one
    // channel. Bucket by JobId so neither marker gets discarded.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut from_a = String::new();
    let mut from_b = String::new();
    while std::time::Instant::now() < deadline {
        if from_a.contains("MARK_FROM_A_F00D") && from_b.contains("MARK_FROM_B_BEEF") {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Event::Stdout { id, data }) if id == shell_a => {
                from_a.push_str(&String::from_utf8_lossy(&data));
            }
            Ok(Event::Stdout { id, data }) if id == shell_b => {
                from_b.push_str(&String::from_utf8_lossy(&data));
            }
            _ => {}
        }
    }

    sb.close_shell(&shell_b).expect("close_shell B");
    sb.stop_vm().ok();

    assert!(
        from_a.contains("MARK_FROM_A_F00D"),
        "A stream missing A marker: {from_a:?}"
    );
    assert!(
        !from_a.contains("MARK_FROM_B_BEEF"),
        "A stream leaked B marker: {from_a:?}"
    );
    assert!(
        from_b.contains("MARK_FROM_B_BEEF"),
        "B stream missing B marker: {from_b:?}"
    );
    assert!(
        !from_b.contains("MARK_FROM_A_F00D"),
        "B stream leaked A marker: {from_b:?}"
    );
}

#[test]
fn multi_shell_independent_signals() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("multi-sig")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell_a = sb.shell_id().expect("shell_id");
    let shell_b = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell");

    // Park A in a long sleep; B will stay idle.
    sb.write_stdin(&shell_a, b"sleep 60\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));

    // SIGINT only A.
    sb.signal_shell(&shell_a, 2).expect("signal A");

    // Watch for A's exit but NOT B's.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut a_exited = false;
    let mut b_exited = false;
    while std::time::Instant::now() < deadline && !a_exited {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(500)) {
            #[allow(clippy::collapsible_match)]
            if let Event::Exit { id, signal, .. } = &ev {
                if id == &shell_a {
                    assert_eq!(*signal, Some(2), "A should die from SIGINT, got {signal:?}");
                    a_exited = true;
                } else if id == &shell_b {
                    b_exited = true;
                }
            }
        }
    }

    // Probe B is still alive by sending a marker and reading it back.
    sb.write_stdin(&shell_b, b"echo B_STILL_ALIVE_77\n").unwrap();
    let probe = drain_until_for_id(&rx, &shell_b, "B_STILL_ALIVE_77", Duration::from_secs(5));

    sb.close_shell(&shell_b).ok();
    sb.stop_vm().ok();

    assert!(a_exited, "A should have exited from SIGINT");
    assert!(!b_exited, "B should NOT have exited (signal was scoped to A)");
    assert!(
        probe.contains("B_STILL_ALIVE_77"),
        "B unresponsive after A's SIGINT: {probe:?}"
    );
}

#[test]
fn list_shells_tracks_lifecycle() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("list-shells")).expect("configure");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let boot = sb.shell_id().expect("shell_id");
    let initial = sb.list_shells().expect("list_shells (initial)");
    assert_eq!(initial.len(), 1, "expected only the boot shell, got {initial:?}");
    assert!(
        initial.contains(&boot),
        "boot shell missing from initial list: {initial:?}"
    );

    let extra1 = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell #1");
    let extra2 = sb.spawn_shell(ShellOpts::default()).expect("spawn_shell #2");

    let after_spawn = sb.list_shells().expect("list_shells (after spawn)");
    assert_eq!(after_spawn.len(), 3, "expected 3 shells, got {after_spawn:?}");
    for id in [&boot, &extra1, &extra2] {
        assert!(after_spawn.contains(id), "{id:?} missing from {after_spawn:?}");
    }

    sb.close_shell(&extra1).expect("close_shell #1");
    // close_shell removes the bookkeeping synchronously; list_shells must
    // reflect the change immediately, even if Event::Exit hasn't propagated.
    let after_close = sb.list_shells().expect("list_shells (after close)");
    assert_eq!(
        after_close.len(),
        2,
        "expected 2 shells after close, got {after_close:?}"
    );
    assert!(
        !after_close.contains(&extra1),
        "closed shell still listed: {after_close:?}"
    );
    assert!(after_close.contains(&boot), "boot shell vanished: {after_close:?}");
    assert!(after_close.contains(&extra2), "extra2 vanished: {after_close:?}");

    sb.close_shell(&extra2).ok();
    sb.stop_vm().ok();
}
