//! Integration test for FUSE chmod: setattr must propagate mode bits
//! to the host file so the guest can execute scripts/binaries after
//! `chmod +x`.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

const MARKER: &str = "TOKIMO_CHMOD_DONE_5F2A";

#[test]
fn chmod_x_makes_script_executable() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("fuse-chmod")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let script = r#"
set -e
cd /tmp/tokimo-share
rm -f hello.sh
cat > hello.sh <<'EOF'
#!/bin/sh
echo HELLO_FROM_CHMOD
EOF
# Force a non-executable starting mode regardless of host default
# (Windows hosts synthesize 0o755 from NTFS attributes), then test
# that chmod +x in the guest actually makes the file executable.
chmod 0644 hello.sh
chmod +x hello.sh
mode=$(stat -c %a hello.sh)
# At minimum owner-exec bit must be set (mode contains 1/3/5/7 in owner column).
case "$mode" in
    1*|3*|5*|7*) ;;
    *) echo "BAD_MODE=$mode"; exit 3 ;;
esac
out=$(./hello.sh)
test "$out" = "HELLO_FROM_CHMOD" || { echo "BAD_OUT=$out"; exit 4; }
echo CHMOD_BASIC_OK
"#;
    let mut full = String::from("set -e\n");
    full.push_str(script);
    full.push_str(&format!("\necho {MARKER}\n"));

    sb.write_stdin(&shell, full.as_bytes()).unwrap();
    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(120));
    sb.stop_vm().ok();
    assert!(captured.contains("CHMOD_BASIC_OK"), "captured = {captured}");
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}
