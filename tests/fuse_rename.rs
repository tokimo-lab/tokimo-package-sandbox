//! Regression tests for the FUSE rename / negative-dentry-cache fix.
//!
//! Background: before the fix, the kernel's FUSE dcache could keep a
//! stale **negative** dentry for a path that was later created via
//! `rename(2)` from a sibling. The classic trigger sequence is what
//! `git_config_set` does:
//!
//!     stat("config")        // ENOENT — kernel caches negative dentry
//!     write("config.lock")
//!     rename("config.lock", "config")
//!     open("config")        // returns ENOENT until cache expires
//!
//! The bridge now sends `FUSE_NOTIFY_INVAL_ENTRY` for the destination
//! (and source) name on every successful rename, which forces the
//! kernel to re-look the path up.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

const MARKER: &str = "TOKIMO_RENAME_DONE_4F1A";

fn run(label: &str, script: &str) -> String {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let mut full = String::from("set -e\ncd /tmp/tokimo-share\n");
    full.push_str(script);
    full.push_str(&format!("\necho {MARKER}\n"));

    sb.write_stdin(&shell, full.as_bytes()).unwrap();
    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(30));
    sb.stop_vm().ok();
    captured
}

/// Reproduces the exact pattern that caused `git init` to corrupt
/// `.git/config`: a pre-rename stat that plants a negative dentry,
/// then `O_CREAT|O_EXCL` on a sibling, then `rename(sibling, target)`,
/// then `open(target)` — which used to return ENOENT.
///
/// We use Python because the test is about kernel-level dcache
/// behaviour and Python gives us deterministic, syscall-level control.
#[test]
fn rename_invalidates_negative_dentry() {
    let script = r#"
rm -rf neg && mkdir neg && cd neg
python3 - <<'PY'
import os, sys
PAYLOAD = b"[core]\n\trepositoryformatversion = 0\n"

# Step 1: stat the target so the kernel caches a NEGATIVE dentry.
try:
    os.stat("config")
    print("UNEXPECTED: pre-stat found config", file=sys.stderr)
    sys.exit(2)
except FileNotFoundError:
    pass

# Step 2: create + write a sibling.
fd = os.open("config.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
os.write(fd, PAYLOAD)
os.fsync(fd)
os.close(fd)

# Step 3: atomic rename onto the previously-negative target.
os.rename("config.lock", "config")

# Step 4: read it back. Without the fix this raises FileNotFoundError
# because the kernel still serves the stale negative dentry.
with open("config", "rb") as f:
    got = f.read()

if got != PAYLOAD:
    print(f"BAD_LEN={len(got)}", file=sys.stderr)
    sys.exit(3)

print("RENAME_READBACK_OK")
PY
"#;
    let captured = run("fuse-rename-neg", script);
    assert!(
        captured.contains("RENAME_READBACK_OK"),
        "rename did not invalidate negative dentry. captured: {captured}"
    );
}

/// `git init` invokes the bug path via `git_config_set`: it writes
/// `.git/config` in stages, each stage doing `O_CREAT|O_EXCL` on
/// `config.lock` and then `rename(config.lock, config)`. Before the fix
/// it would either fail outright with `fatal: bad config line 1` or
/// leave a truncated 36-byte config. Verify both: exit code is 0 and
/// the config has all expected keys.
#[test]
fn git_init_produces_valid_config() {
    let script = r#"
rm -rf gi && mkdir gi && cd gi
git init -q t
cd t
test -f .git/config
# Sanity: a healthy `git init` produces a config with at least
# repositoryformatversion + filemode + bare + logallrefupdates.
grep -q '^\[core\]' .git/config
grep -q 'repositoryformatversion' .git/config
grep -q 'filemode' .git/config
grep -q 'bare' .git/config
grep -q 'logallrefupdates' .git/config
echo GIT_INIT_OK
"#;
    let captured = run("fuse-rename-gitinit", script);
    assert!(
        captured.contains("GIT_INIT_OK"),
        "git init produced an unhealthy .git/config. captured: {captured}"
    );
}
