#![cfg(target_os = "windows")]
//! Windows-only integration tests for NTFS Extended Attribute backed unix mode.
//!
//! On Windows hosts the FUSE layer persists guest-visible unix mode bits in
//! an NTFS Extended Attribute (`$LXMOD`). These tests exercise:
//!   * Round-tripping arbitrary modes (including setuid/setgid/sticky).
//!   * Falling back to a synthesized default mode when the EA is absent
//!     (host-created files, or after `fsutil file removeEA`).

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::Sandbox;

const MARKER_RT: &str = "TOKIMO_WINMODE_RT_DONE_7B3C";
const MARKER_FB_CHMOD: &str = "TOKIMO_WINMODE_FB_CHMOD_A1B2";
const MARKER_FB: &str = "TOKIMO_WINMODE_FB_DONE_9D1E";

#[test]
fn windows_ea_round_trips() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("fuse-winmode-rt")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let script = r#"
set -e
cd /tmp/tokimo-share

# 1) New file default
rm -f foo.txt
touch foo.txt
got=$(stat -c %a foo.txt)
test "$got" = "644" || { echo "BAD_NEW_FILE=$got"; exit 1; }

# 2) New dir default
rm -rf d
mkdir d
got=$(stat -c %a d)
test "$got" = "755" || { echo "BAD_NEW_DIR=$got"; exit 1; }

# 3) chmod 0700
chmod 0700 foo.txt
got=$(stat -c %a foo.txt)
test "$got" = "700" || { echo "BAD_0700=$got"; exit 1; }

# 4) chmod 0444
chmod 0444 foo.txt
got=$(stat -c %a foo.txt)
test "$got" = "444" || { echo "BAD_0444=$got"; exit 1; }

# 5) chmod 0755 then 0644
chmod 0755 foo.txt
chmod 0644 foo.txt
got=$(stat -c %a foo.txt)
test "$got" = "644" || { echo "BAD_0644=$got"; exit 1; }

# 6) setuid
rm -f setuid.bin
touch setuid.bin
chmod 04755 setuid.bin
got=$(stat -c %a setuid.bin)
test "$got" = "4755" || { echo "BAD_SETUID=$got"; exit 1; }

# 7) setgid
rm -f setgid.bin
touch setgid.bin
chmod 02755 setgid.bin
got=$(stat -c %a setgid.bin)
test "$got" = "2755" || { echo "BAD_SETGID=$got"; exit 1; }

# 8) sticky
rm -f sticky
touch sticky
chmod 01755 sticky
got=$(stat -c %a sticky)
test "$got" = "1755" || { echo "BAD_STICKY=$got"; exit 1; }

# 9) g+w via symbolic chmod
rm -f group.txt
touch group.txt
chmod 0644 group.txt
chmod g+w group.txt
gmode=$(stat -c %a group.txt)
case "$gmode" in
    *[2367][0-7]) echo GROUP_WRITE_OK ;;
    *) echo "BAD_GROUP_WRITE=$gmode"; exit 1 ;;
esac

echo WINMODE_RT_OK
"#;
    let mut full = String::from("set -e\n");
    full.push_str(script);
    full.push_str(&format!("\necho {MARKER_RT}\n"));

    sb.write_stdin(&shell, full.as_bytes()).unwrap();
    let captured = drain_until(&rx, &shell, MARKER_RT, Duration::from_secs(120));
    sb.stop_vm().ok();
    assert!(captured.contains("WINMODE_RT_OK"), "captured = {captured}");
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}

#[test]
fn windows_ea_fallback_paths() {
    let label = "fuse-winmode-fb";
    let host_dir = workspace_dir(label);

    // Pre-create a file on the host (no $LXMOD EA) before the sandbox starts.
    let host_created = host_dir.join("host_created.txt");
    let _ = std::fs::remove_file(&host_created);
    std::fs::write(&host_created, b"data").expect("write host_created.txt");

    let ea_test_host = host_dir.join("ea_test.txt");
    let _ = std::fs::remove_file(&ea_test_host);

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Phase 1: verify host-created file falls back to 644, then create
    // ea_test.txt in guest, chmod 0700, and emit a sync marker so the
    // host can perform `fsutil removeEA` mid-test.
    let script1 = format!(
        r#"set -e
cd /tmp/tokimo-share
got=$(stat -c %a host_created.txt)
test "$got" = "644" || {{ echo "BAD_HOST_CREATED=$got"; exit 5; }}
echo HOST_CREATED_FALLBACK_OK
rm -f ea_test.txt
touch ea_test.txt
chmod 0700 ea_test.txt
got=$(stat -c %a ea_test.txt)
test "$got" = "700" || {{ echo "BAD_EA_CHMOD=$got"; exit 5; }}
echo {MARKER_FB_CHMOD}
"#
    );

    sb.write_stdin(&shell, script1.as_bytes()).unwrap();
    let phase1 = drain_until(&rx, &shell, MARKER_FB_CHMOD, Duration::from_secs(120));
    assert!(phase1.contains("HOST_CREATED_FALLBACK_OK"), "phase1 = {phase1}");
    assert!(!phase1.contains("BAD_"), "phase1 = {phase1}");

    // Allow EA write to flush, then attempt to strip $LXMOD via fsutil.
    std::thread::sleep(Duration::from_millis(500));
    let ea_path = ea_test_host.to_string_lossy().to_string();
    let fsutil_result = std::process::Command::new("fsutil")
        .args(["file", "removeEA", &ea_path, "$LXMOD"])
        .status();

    let fsutil_ok = matches!(fsutil_result, Ok(s) if s.success());
    if !fsutil_ok {
        eprintln!("FSUTIL_REMOVEA_SKIP: fsutil removeEA unavailable or failed: {fsutil_result:?}");
    }

    // Phase 2: either verify post-removal fallback, or skip that check.
    let script2 = if fsutil_ok {
        format!(
            r#"set -e
got2=$(stat -c %a /tmp/tokimo-share/ea_test.txt)
test "$got2" = "644" || {{ echo "BAD_EA_REMOVED=$got2"; exit 6; }}
echo EA_REMOVED_FALLBACK_OK
echo {MARKER_FB}
"#
        )
    } else {
        format!(
            r#"set -e
echo FSUTIL_REMOVEA_SKIP
echo {MARKER_FB}
"#
        )
    };

    sb.write_stdin(&shell, script2.as_bytes()).unwrap();
    let captured = drain_until(&rx, &shell, MARKER_FB, Duration::from_secs(120));
    sb.stop_vm().ok();

    if fsutil_ok {
        assert!(captured.contains("EA_REMOVED_FALLBACK_OK"), "captured = {captured}");
    } else {
        assert!(captured.contains("FSUTIL_REMOVEA_SKIP"), "captured = {captured}");
    }
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}
