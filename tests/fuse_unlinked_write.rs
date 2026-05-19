//! Reproduces the FUSE host bug surfaced by apt's GPG verification path:
//! POSIX requires `write(fd, ...)` to succeed after the underlying file
//! has been unlinked (the fd holds an inode reference until close).
//! Our FUSE LocalDirVfs mount returns EIO instead.
//!
//! Run with: cargo test --test fuse_unlinked_write -- --nocapture

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

#[test]
fn write_after_unlink_through_fuse_mount() {
    let cfg = config("fuse-unlink");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Probe: open + unlink + write through the FUSE LocalDirVfs mount.
    // Mirrors what apt's GetTempFile / mkstemp+unlink does internally.
    sb.write_stdin(
        &shell,
        b"set +e\n\
          cd /tmp/tokimo-share\n\
          python3 - <<'PY' 2>&1\n\
import os, tempfile\n\
fd, p = tempfile.mkstemp(prefix='probe.', dir='/tmp/tokimo-share')\n\
print('opened', p)\n\
os.unlink(p)\n\
print('unlinked')\n\
n = os.write(fd, b'hello world' * 100)\n\
print('wrote', n)\n\
os.close(fd)\n\
print('closed-ok')\n\
PY\n\
          echo END_TAG\n",
    )
    .unwrap();
    let out = drain_until(&rx, &shell, "END_TAG", Duration::from_secs(60));
    eprintln!("=== output ===\n{out}\n=== end ===");

    sb.stop_vm().ok();

    assert!(
        out.contains("wrote 1100") && out.contains("closed-ok"),
        "expected POSIX-compliant write-after-unlink to succeed, got:\n{out}"
    );
}
