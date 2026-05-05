mod common;

use std::time::{Duration, Instant};

use common::{SandboxGuard, config};
use tokimo_package_sandbox::{Event, Sandbox};

// Note: the boot-time shell runs in pipe mode without a controlling TTY,
// so bash itself takes the default SIGINT disposition (terminate). This
// test therefore verifies the *wire path* — host → service → init →
// `killpg(SIGINT)` → kernel — by asserting an Exit event surfaces with
// `signal == Some(2)`. A higher-level "interrupt the foreground command
// without killing the shell" mode requires PTY-mode shells, which is
// tracked separately.

#[test]
fn signal_shell_delivers_sigint() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("sigint")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Park bash inside a long sleep so SIGINT has something to interrupt.
    sb.write_stdin(&shell, b"sleep 60\n").unwrap();
    std::thread::sleep(Duration::from_millis(750));

    sb.interrupt_shell(&shell).expect("interrupt_shell");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_exit = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Exit { id, exit_code, signal }) if id == shell => {
                got_exit = Some((exit_code, signal));
                break;
            }
            Ok(_) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    sb.stop_vm().ok();

    let (exit_code, signal) = got_exit.expect("shell never reported Exit after SIGINT");
    assert_eq!(
        signal,
        Some(2),
        "expected SIGINT (2). exit_code={exit_code} signal={signal:?}"
    );
}
