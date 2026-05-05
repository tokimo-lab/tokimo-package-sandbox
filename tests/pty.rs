mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_bytes_until, drain_until_for_id};
use tokimo_package_sandbox::{Sandbox, ShellOpts};

#[test]
fn pty_shell_reports_correct_size() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-size")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((40, 132)),
            ..Default::default()
        })
        .expect("spawn pty shell");
    sb.write_stdin(&shell, b"stty size\n").expect("write_stdin");

    let captured = drain_until_for_id(&rx, &shell, "40 132", Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(captured.contains("40 132"), "stty size missing '40 132': {captured:?}");
}

#[test]
fn pty_shell_resize_propagates() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-resize")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((24, 80)),
            ..Default::default()
        })
        .expect("spawn pty shell");
    sb.write_stdin(&shell, b"stty size\n").unwrap();
    let first = drain_until_for_id(&rx, &shell, "24 80", Duration::from_secs(15));
    assert!(first.contains("24 80"), "initial stty size missing '24 80': {first:?}");

    sb.resize_shell(&shell, 50, 120).expect("resize_shell");
    sb.write_stdin(&shell, b"stty size\n").unwrap();
    let second = drain_until_for_id(&rx, &shell, "50 120", Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(
        second.contains("50 120"),
        "post-resize stty size missing '50 120': {second:?}"
    );
}

#[test]
fn pty_shell_ctrl_c_does_not_kill_shell() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-ctrlc")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((24, 80)),
            ..Default::default()
        })
        .expect("spawn pty shell");

    // Park the shell in a long sleep, then deliver Ctrl-C as a slave-side
    // byte. In a PTY the line discipline turns this into SIGINT delivered
    // ONLY to the foreground process group (sleep), not the shell itself.
    sb.write_stdin(&shell, b"sleep 60\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    sb.write_stdin(&shell, b"\x03").unwrap();

    sb.write_stdin(&shell, b"echo ALIVE\n").unwrap();
    let captured = drain_until_for_id(&rx, &shell, "ALIVE", Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(
        captured.contains("ALIVE"),
        "shell unresponsive after Ctrl-C — slave-side ^C must NOT kill the shell. captured: {captured:?}"
    );
}

#[test]
fn pty_shell_color_escape_codes_pass_through() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("pty-color")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let shell = sb
        .spawn_shell(ShellOpts {
            pty: Some((24, 80)),
            ..Default::default()
        })
        .expect("spawn pty shell");
    sb.write_stdin(&shell, b"printf '\\e[31mRED\\e[0m\\n'\n").unwrap();

    let needle: &[u8] = b"\x1b[31mRED\x1b[0m";
    let captured = drain_bytes_until(&rx, &shell, needle, Duration::from_secs(15));
    sb.close_shell(&shell).ok();
    sb.stop_vm().ok();

    assert!(
        captured.windows(needle.len()).any(|w| w == needle),
        "color escape sequence missing — captured bytes: {:?}",
        String::from_utf8_lossy(&captured)
    );
}
