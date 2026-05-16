//! End-to-end tests for the two FUSE/sandbox features added together:
//!
//!   1. `mknod(2)` over FUSE — required for `bind(2)` of an AF_UNIX
//!      socket whose path resides on a tokimo FUSE share (e.g. anything
//!      under `/tmp/tokimo-share`). Without the FUSE `mknod()` callback
//!      the kernel returns `ENOSYS` and the bind fails.
//!
//!   2. `/dev/shm` tmpfs — POSIX shared memory (`shm_open(3)`,
//!      multiprocessing, etc.) needs `/dev/shm` to be a real tmpfs.
//!
//! Both checks run inside a real bwrap-backed sandbox so they exercise
//! the full host VFS → FuseHost → kernel FUSE → guest path.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

fn run(label: &str, script: &str, marker: &str) -> String {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, script.as_bytes()).unwrap();
    let out = drain_until(&rx, &shell, marker, Duration::from_secs(45));
    sb.stop_vm().ok();
    out
}

/// `bind(AF_UNIX, "/tmp/tokimo-share/foo.sock")` used to fail with
/// `ENOSYS` because the FUSE bridge had no `mknod()` callback. After
/// wiring `VfsMknod` end-to-end, the bind must succeed and a subsequent
/// `stat` must report the path as a socket (`S_ISSOCK`).
#[test]
fn fuse_af_unix_bind_works_on_share() {
    const MARKER: &str = "MKNOD_TEST_DONE_8F2A";

    // Use python3 (always present in the rootfs) — busybox `nc -U` isn't
    // reliable across distros and we don't need a client, just a bind.
    let script = format!(
        r#"python3 - <<'PY' 2>&1
import os, socket, stat, sys
path = "/tmp/tokimo-share/test.sock"
try: os.unlink(path)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(1)
st = os.stat(path)
print("bind_ok", stat.S_ISSOCK(st.st_mode))
s.close()
os.unlink(path)
PY
echo {MARKER}
"#
    );

    let out = run("fusemknod", &script, MARKER);

    assert!(
        out.contains("bind_ok True"),
        "AF_UNIX bind over FUSE failed (mknod broken?). captured: {out:?}"
    );
    assert!(
        !out.contains("ENOSYS") && !out.contains("Function not implemented"),
        "got ENOSYS from bind. captured: {out:?}"
    );
}

/// AF_UNIX sockets must round-trip end-to-end: a server binds on the
/// FUSE share, a client connects, message is delivered. This exercises
/// FUSE_LOOKUP returning `NodeKind::Socket` so the kernel doesn't return
/// `ENOTSOCK` on `connect(2)`.
#[test]
fn fuse_af_unix_connect_roundtrip() {
    const MARKER: &str = "UNIX_RT_DONE_C7E1";

    let script = format!(
        r#"python3 - <<'PY' 2>&1
import os, socket, threading
path = "/tmp/tokimo-share/rt.sock"
try: os.unlink(path)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path); srv.listen(1)
def serve():
    c, _ = srv.accept()
    c.sendall(b"HELLO_FROM_SERVER")
    c.close()
t = threading.Thread(target=serve); t.start()
cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
cli.connect(path)
data = cli.recv(64)
print("roundtrip", data.decode())
cli.close(); t.join(); srv.close()
os.unlink(path)
PY
echo {MARKER}
"#
    );

    let out = run("fusertconnect", &script, MARKER);
    assert!(
        out.contains("roundtrip HELLO_FROM_SERVER"),
        "AF_UNIX roundtrip failed. captured: {out:?}"
    );
}

/// `/dev/shm` must be a writable tmpfs in the sandbox so POSIX shared
/// memory and `multiprocessing.shared_memory` work.
#[test]
fn dev_shm_is_writable_tmpfs() {
    const MARKER: &str = "SHM_DONE_4DEB";

    // 1) /dev/shm exists and is a tmpfs.
    // 2) Files written there are readable back.
    let script = format!(
        "stat -f -c %T /dev/shm 2>&1; \
         echo HELLO > /dev/shm/probe && cat /dev/shm/probe && rm /dev/shm/probe; \
         echo {MARKER}\n"
    );

    let out = run("devshm", &script, MARKER);
    assert!(
        out.contains("tmpfs"),
        "/dev/shm is not tmpfs. captured: {out:?}"
    );
    assert!(
        out.contains("HELLO"),
        "/dev/shm not writable. captured: {out:?}"
    );
}
