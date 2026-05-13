//! Cross-platform mode round-trip symmetry test: setting a mode in the
//! guest and reading it back via `stat -c %a` must yield the same value.
//! On Windows this exercises the NTFS `$LXMOD` EA path; on Linux/macOS
//! it exercises the FUSE setattr -> host chmod path.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

const MARKER: &str = "TOKIMO_MODESYM_DONE_4E8F";

#[test]
fn mode_round_trip_symmetry() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("fuse-mode-sym")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let file_modes = [
        ("0600", "600"),
        ("0644", "644"),
        ("0700", "700"),
        ("0755", "755"),
        ("4755", "4755"),
        ("2755", "2755"),
        ("1755", "1755"),
        ("0444", "444"),
    ];
    let dir_modes = [("0700", "700"), ("0755", "755")];

    let mut script = String::from("set -e\ncd /tmp/tokimo-share\n");
    for (chmod_arg, expected) in &file_modes {
        script.push_str(&format!(
            "rm -f file_{chmod_arg}\ntouch file_{chmod_arg}\nchmod {chmod_arg} file_{chmod_arg}\ngot=$(stat -c %a file_{chmod_arg})\ntest \"$got\" = \"{expected}\" || {{ echo \"BAD_{chmod_arg}=$got\"; exit 1; }}\n"
        ));
    }
    for (chmod_arg, expected) in &dir_modes {
        script.push_str(&format!(
            "rm -rf dir_{chmod_arg}\nmkdir dir_{chmod_arg}\nchmod {chmod_arg} dir_{chmod_arg}\ngot=$(stat -c %a dir_{chmod_arg})\ntest \"$got\" = \"{expected}\" || {{ echo \"BAD_DIR_{chmod_arg}=$got\"; exit 1; }}\n"
        ));
    }
    script.push_str("echo MODESYM_OK\n");
    script.push_str(&format!("echo {MARKER}\n"));

    sb.write_stdin(&shell, script.as_bytes()).unwrap();
    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(120));
    sb.stop_vm().ok();
    assert!(captured.contains("MODESYM_OK"), "captured = {captured}");
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}
