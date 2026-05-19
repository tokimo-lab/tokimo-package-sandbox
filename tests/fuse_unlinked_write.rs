//! Reproduces the FUSE host bug surfaced by apt's GPG verification path:
//! POSIX requires `write(fd, ...)` to succeed after the underlying file
//! has been unlinked (the fd holds an inode reference until close).
//! Our FUSE LocalDirVfs mount returns EIO instead.
//!
//! Run with: cargo test --test fuse_unlinked_write -- --nocapture

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{SandboxGuard, drain_until};
use tokimo_package_sandbox::{ConfigureParams, Mount, NetworkPolicy, Sandbox};

#[test]
fn write_after_unlink_through_fuse_mount() {
    let cwd = std::env::current_dir().unwrap();
    let repo_root = cwd
        .ancestors()
        .find(|p| p.join(".data").is_dir())
        .expect("walk up to .data/")
        .to_path_buf();

    let base = repo_root.join(".data/vm/base");
    let vm = repo_root.join(".data/vm/data");
    assert!(base.join("rootfs").is_dir(), "base rootfs missing");

    let host_share = PathBuf::from(format!("/tmp/tokimo-fuse-unlink-{}", std::process::id()));
    std::fs::create_dir_all(&host_share).ok();

    let cfg = ConfigureParams {
        user_data_name: "fuse-unlink-repro".into(),
        base_rootfs: base,
        vm_dir: vm,
        memory_mb: 1024,
        cpu_count: 2,
        mounts: vec![Mount {
            name: "ws".into(),
            host_path: host_share.clone(),
            guest_path: "/mnt/ws".into(),
            read_only: false,
            create_host_dir: true,
        }],
        network: NetworkPolicy::Blocked,
        session_id: format!("fuse-unlink-{}", std::process::id()),
        ..Default::default()
    };

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
          echo --- mount ---\n\
          df -T /mnt/ws\n\
          echo --- python open+unlink+write ---\n\
          python3 -c \"\n\
import os, tempfile\n\
fd, p = tempfile.mkstemp(prefix='probe.', dir='/mnt/ws')\n\
print('opened', p)\n\
os.unlink(p)\n\
print('unlinked')\n\
n = os.write(fd, b'hello world' * 100)\n\
print('wrote', n)\n\
os.close(fd)\n\
print('closed-ok')\n\
\" 2>&1\n\
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
