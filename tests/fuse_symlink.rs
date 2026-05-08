//! Integration tests for symlink / readlink across the FUSE bridge.
//!
//! Covers:
//!   * creating a symlink in the mount, then reading it via `readlink`
//!     and traversing it via `cat`;
//!   * dangling symlinks (target doesn't exist);
//!   * symlinks unpacked from a tarball (real-world payload);
//!   * `git clone` of a tiny repo that contains a symlink.
//!
//! All four scenarios were broken before symlink/readlink were wired
//! through the VFS protocol — `ln -s` returned ENOSYS, and even an
//! existing host-side symlink showed up as its target's type because
//! the backend used `metadata` (follow) instead of `symlink_metadata`.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

const MARKER: &str = "TOKIMO_SYMLINK_DONE_8E3C";

fn run(label: &str, script: &str) -> String {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let mut full = String::from("set -e\ncd /work\n");
    full.push_str(script);
    full.push_str(&format!("\necho {MARKER}\n"));

    sb.write_stdin(&shell, full.as_bytes()).unwrap();
    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(120));
    sb.stop_vm().ok();
    captured
}

/// `ln -s payload link`, then `readlink link` returns "payload",
/// `cat link` returns the payload's contents, and `stat -c %F link`
/// reports "symbolic link" (lstat semantics — the link is NOT
/// silently followed by getattr).
#[test]
fn symlink_create_readlink_traverse() {
    let script = r#"
rm -rf sym && mkdir sym && cd sym
echo hello-symlink > payload
ln -s payload link
got_target=$(readlink link)
test "$got_target" = "payload" || { echo "BAD_TARGET=$got_target"; exit 2; }
got_payload=$(cat link)
test "$got_payload" = "hello-symlink" || { echo "BAD_PAYLOAD=$got_payload"; exit 3; }
got_kind=$(stat -c %F link)
test "$got_kind" = "symbolic link" || { echo "BAD_KIND=$got_kind"; exit 4; }
echo SYMLINK_BASIC_OK
"#;
    let captured = run("fuse-symlink-basic", script);
    assert!(
        captured.contains("SYMLINK_BASIC_OK"),
        "symlink basic ops failed. captured: {captured}"
    );
}

/// Dangling symlinks: the link itself stats fine (lstat), the target
/// resolution returns ENOENT. POSIX explicitly allows this.
#[test]
fn symlink_dangling() {
    let script = r#"
rm -rf dangle && mkdir dangle && cd dangle
ln -s does-not-exist orphan
got_target=$(readlink orphan)
test "$got_target" = "does-not-exist" || { echo "BAD_TARGET=$got_target"; exit 2; }
got_kind=$(stat -c %F orphan)
test "$got_kind" = "symbolic link" || { echo "BAD_KIND=$got_kind"; exit 3; }
# Reading through the dangling link must fail with ENOENT.
if cat orphan 2>/dev/null; then
    echo BAD_TRAVERSAL_SUCCEEDED
    exit 4
fi
echo SYMLINK_DANGLING_OK
"#;
    let captured = run("fuse-symlink-dangle", script);
    assert!(
        captured.contains("SYMLINK_DANGLING_OK"),
        "dangling symlink behaviour wrong. captured: {captured}"
    );
}

/// Tarballs frequently contain symlinks (e.g. shared-library SONAMEs).
/// `tar -x` calls `symlinkat(2)` directly, so this exercises the
/// kernel → FUSE_SYMLINK → backend path with the same syscall path
/// that real-world software uses.
#[test]
fn symlink_via_tar_extract() {
    let script = r#"
rm -rf tarsym && mkdir tarsym && cd tarsym
mkdir src
echo content > src/real
ln -s real src/link
tar -cf bundle.tar src
mkdir out
tar -xf bundle.tar -C out
got_target=$(readlink out/src/link)
test "$got_target" = "real" || { echo "BAD_TARGET=$got_target"; exit 2; }
got_payload=$(cat out/src/link)
test "$got_payload" = "content" || { echo "BAD_PAYLOAD=$got_payload"; exit 3; }
echo SYMLINK_TAR_OK
"#;
    let captured = run("fuse-symlink-tar", script);
    assert!(
        captured.contains("SYMLINK_TAR_OK"),
        "tar-extracted symlink wrong. captured: {captured}"
    );
}

/// `git clone` writes its own symlinks (e.g. branch refs use
/// `core.symlinks=true` checkouts) and reads them back during checkout
/// post-processing. This is the closest in-tree proxy for the user's
/// original failing command (`git clone …`) and validates the full
/// FUSE rename + symlink stack working together.
///
/// We use a local source repo (no network) containing a single symlink
/// in the working tree, then clone it into the FUSE mount.
#[test]
fn git_clone_with_symlink() {
    let script = r#"
rm -rf clonesrc clonedst && mkdir clonesrc
cd clonesrc
git init -q
git config user.email t@e.x
git config user.name T
echo target-content > real
ln -s real link
git add real link
git commit -q -m init
cd /work
git clone -q clonesrc clonedst
test -L clonedst/link || { echo NOT_A_SYMLINK; exit 2; }
got_target=$(readlink clonedst/link)
test "$got_target" = "real" || { echo "BAD_TARGET=$got_target"; exit 3; }
got_payload=$(cat clonedst/link)
test "$got_payload" = "target-content" || { echo "BAD_PAYLOAD=$got_payload"; exit 4; }
echo GIT_CLONE_SYMLINK_OK
"#;
    let captured = run("fuse-symlink-git-clone", script);
    assert!(
        captured.contains("GIT_CLONE_SYMLINK_OK"),
        "git clone with symlink failed. captured: {captured}"
    );
}
