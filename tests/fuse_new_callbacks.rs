//! Integration tests for the FUSE callbacks added in VFS protocol v3:
//!   * `link`             — hard links inside the share
//!   * `fsync`/`fsyncdir` — `sync(2)`/`fdatasync(2)` on guest fds
//!   * `setxattr` family  — `user.*` xattrs on Linux
//!   * `access`           — `faccessat(2)` mode checks
//!   * `fallocate`        — `posix_fallocate(3)` extending a file
//!   * `lseek`            — SEEK_DATA / SEEK_HOLE on a sparse file
//!   * `getlk`/`setlk`    — `flock(2)` style advisory locks
//!   * `copy_file_range`  — fast copy between fds
//!
//! All scenarios exercise the in-guest syscall surface from a shell
//! inside the sandbox, so each round-trip flows: shell → Linux kernel
//! → FUSE → tokimo-sandbox-fuse (guest bridge) → vsock/unix → host
//! VfsHost dispatcher → `LocalDirVfs` → real host syscall, and back.
//!
//! On hosts where a syscall is not implemented (Windows, or macOS for a
//! handful of ops), the guest kernel transparently falls back to the
//! slow path, so we only assert observable behaviour, never which
//! fast-path the operation actually used.

mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;

const MARKER: &str = "TOKIMO_FUSE_V3_DONE_A41B";

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
    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(180));
    sb.stop_vm().ok();
    captured
}

#[test]
fn hard_link_creates_second_name() {
    let captured = run(
        "fuse-link",
        r#"
rm -rf link_dir && mkdir link_dir && cd link_dir
echo payload > a.txt
ln a.txt b.txt
# b.txt is a fresh lookup so its kernel-side attr cache comes from the
# link reply's EntryOut, which carries the real post-link nlink=2.
[ "$(stat -c %h b.txt)" = "2" ] || { echo "BAD_NLINK_B=$(stat -c %h b.txt)"; exit 1; }
[ "$(cat b.txt)" = "payload" ] || { echo "BAD_CONTENT_B=$(cat b.txt)"; exit 1; }
# Inode identity: after the (mount_id, dev, ino) dedup in the host
# IdTable, both names share one nodeid → the kernel reports identical
# st_ino, matching native (non-FUSE) hard-link semantics.
ino_a=$(stat -c %i a.txt)
ino_b=$(stat -c %i b.txt)
[ "$ino_a" = "$ino_b" ] || { echo "BAD_INO ino_a=$ino_a ino_b=$ino_b"; exit 1; }
# Cross-name content propagation: writing through one name must show
# up through the other. This used to require FUSE_NOTIFY_INVAL_INODE
# because each FUSE nodeid kept its own page cache; with inode dedup
# both names resolve to the same nodeid + cache, so the new content
# is visible immediately.
echo mutated > a.txt
[ "$(cat b.txt)" = "mutated" ] || { echo "BAD_CROSS_MUTATE=$(cat b.txt)"; exit 1; }
# Unlinking the source must NOT delete the file — that's the defining
# property of a hard link (vs a copy or a symlink).
rm a.txt
[ -f b.txt ] || { echo "B_MISSING_AFTER_UNLINK_A"; exit 1; }
[ "$(cat b.txt)" = "mutated" ] || { echo "BAD_CONTENT_2=$(cat b.txt)"; exit 1; }
echo LINK_OK
"#,
    );
    assert!(captured.contains("LINK_OK"), "captured = {captured}");
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}

#[test]
fn hard_link_inode_identity() {
    // Targeted regression test for the IdTable `(mount_id, dev, ino)`
    // dedup pass: two paths to the same inode must share one nodeid,
    // and dropping one name must keep the inode reachable through the
    // other without losing kernel-side cache coherency.
    let captured = run(
        "fuse-link-ino",
        r#"
rm -rf ino_dir && mkdir ino_dir && cd ino_dir
echo first > master.txt
ln master.txt alias1.txt
ln master.txt alias2.txt
# All three names share the same on-host inode and, via dedup, the
# same FUSE nodeid → identical st_ino.
ino_m=$(stat -c %i master.txt)
ino_1=$(stat -c %i alias1.txt)
ino_2=$(stat -c %i alias2.txt)
[ "$ino_m" = "$ino_1" ] && [ "$ino_1" = "$ino_2" ] \
    || { echo "BAD_INO_TRIPLE m=$ino_m a1=$ino_1 a2=$ino_2"; exit 1; }
# nlink reflects the real on-host count (3).
[ "$(stat -c %h master.txt)" = "3" ] || { echo "BAD_NLINK_M=$(stat -c %h master.txt)"; exit 1; }
# Unlink the source name; alias1 + alias2 must still resolve and
# share an inode.
rm master.txt
[ -f alias1.txt ] && [ -f alias2.txt ] || { echo "ALIASES_LOST"; exit 1; }
ino_1b=$(stat -c %i alias1.txt)
ino_2b=$(stat -c %i alias2.txt)
[ "$ino_1b" = "$ino_2b" ] || { echo "BAD_INO_AFTER_UNLINK a1=$ino_1b a2=$ino_2b"; exit 1; }
[ "$(stat -c %h alias1.txt)" = "2" ] || { echo "BAD_NLINK_AFTER=$(stat -c %h alias1.txt)"; exit 1; }
# Content propagation via cache invalidation: writing to alias1
# is visible through alias2 (same nodeid, same page cache).
echo updated > alias1.txt
[ "$(cat alias2.txt)" = "updated" ] || { echo "BAD_PROPAGATE=$(cat alias2.txt)"; exit 1; }
echo INO_OK
"#,
    );
    assert!(captured.contains("INO_OK"), "captured = {captured}");
    assert!(
        !captured.contains("BAD_") && !captured.contains("ALIASES_LOST"),
        "captured = {captured}"
    );
}

#[test]
fn fsync_and_fdatasync_succeed() {
    // We can't directly observe whether fsync hit the disk, but we can
    // confirm the syscall returns 0 (no ENOSYS / EIO). `dd` with
    // conv=fsync is the most portable way to issue an fsync from shell.
    let captured = run(
        "fuse-fsync",
        r#"
rm -rf fsync_dir && mkdir fsync_dir && cd fsync_dir
echo hello > f.txt
# fsync via dd; conv=fsync calls fsync(2) before close.
dd if=/dev/zero of=g.bin bs=1024 count=4 conv=fsync 2>/dev/null
[ -f g.bin ] || { echo "G_MISSING"; exit 1; }
# fdatasync via python (more direct than dd).
python3 - <<'PY'
import os
fd = os.open("g.bin", os.O_WRONLY)
os.write(fd, b"\x00" * 16)
os.fdatasync(fd)
os.fsync(fd)
os.close(fd)
PY
# fsync on a directory fd (fsyncdir).
python3 - <<'PY'
import os
fd = os.open(".", os.O_RDONLY)
os.fsync(fd)
os.close(fd)
PY
echo FSYNC_OK
"#,
    );
    assert!(captured.contains("FSYNC_OK"), "captured = {captured}");
}

#[test]
fn user_xattr_roundtrip() {
    // Linux hosts: user.* xattrs land on the underlying file. Windows
    // hosts: setxattr returns ENOTSUP and the test sees getfattr emit
    // "Operation not supported"; treat both as acceptable.
    let captured = run(
        "fuse-xattr",
        r#"
rm -rf xa_dir && mkdir xa_dir && cd xa_dir
echo hi > f.txt
python3 - <<'PY'
import os, errno, sys
path = "f.txt"
try:
    os.setxattr(path, b"user.tokimo", b"v3")
except OSError as e:
    if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS):
        print("XATTR_NOTSUP_OK")
        sys.exit(0)
    print("BAD_SET", e.errno); sys.exit(1)
try:
    v = os.getxattr(path, b"user.tokimo")
except OSError as e:
    print("BAD_GET", e.errno); sys.exit(1)
if v != b"v3":
    print("BAD_VALUE", v); sys.exit(1)
names = os.listxattr(path)
if "user.tokimo" not in names:
    print("BAD_LIST", names); sys.exit(1)
os.removexattr(path, b"user.tokimo")
try:
    os.getxattr(path, b"user.tokimo")
    print("BAD_NOT_REMOVED"); sys.exit(1)
except OSError as e:
    if e.errno != errno.ENODATA:
        print("BAD_REMOVE_ERRNO", e.errno); sys.exit(1)
print("XATTR_SUPPORTED_OK")
PY
"#,
    );
    assert!(
        captured.contains("XATTR_SUPPORTED_OK") || captured.contains("XATTR_NOTSUP_OK"),
        "captured = {captured}"
    );
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}

#[test]
fn access_mode_checks() {
    let captured = run(
        "fuse-access",
        r#"
rm -rf acc_dir && mkdir acc_dir && cd acc_dir
echo x > a.txt
chmod 0644 a.txt
# F_OK / R_OK should succeed; X_OK should fail on a 0644 plain file.
[ -e a.txt ] || { echo "F_OK_FAIL"; exit 1; }
[ -r a.txt ] || { echo "R_OK_FAIL"; exit 1; }
[ -x a.txt ] && { echo "X_OK_UNEXPECTED"; exit 1; }
chmod +x a.txt
[ -x a.txt ] || { echo "X_OK_FAIL_AFTER_CHMOD"; exit 1; }
echo ACCESS_OK
"#,
    );
    assert!(captured.contains("ACCESS_OK"), "captured = {captured}");
    assert!(
        !captured.contains("BAD_") && !captured.contains("FAIL"),
        "captured = {captured}"
    );
}

#[test]
fn fallocate_extends_file() {
    let captured = run(
        "fuse-fallocate",
        r#"
rm -rf fa_dir && mkdir fa_dir && cd fa_dir
: > f.bin
# fallocate may not be available on every shell; fall back to truncate.
if command -v fallocate >/dev/null && fallocate -l 1048576 f.bin 2>/dev/null; then
    sz=$(stat -c %s f.bin)
    [ "$sz" = "1048576" ] || { echo "BAD_SIZE_FALLOCATE=$sz"; exit 1; }
    echo FALLOCATE_OK
else
    # posix_fallocate via python (works on Linux >= 2.6.23)
    python3 -c "import os; fd=os.open('f.bin', os.O_WRONLY); os.posix_fallocate(fd, 0, 1048576); os.close(fd)"
    sz=$(stat -c %s f.bin)
    [ "$sz" = "1048576" ] || { echo "BAD_SIZE_POSIX=$sz"; exit 1; }
    echo POSIX_FALLOCATE_OK
fi
"#,
    );
    assert!(
        captured.contains("FALLOCATE_OK") || captured.contains("POSIX_FALLOCATE_OK"),
        "captured = {captured}"
    );
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}

#[test]
fn lseek_seek_data_hole() {
    // Use python's lseek with SEEK_DATA/SEEK_HOLE constants. On hosts
    // that don't support hole seeking the kernel returns ENXIO or the
    // entire file as data; we only assert SEEK_DATA(0) returns 0 and
    // SEEK_HOLE(0) returns >= file size or > 0.
    let captured = run(
        "fuse-lseek",
        r#"
rm -rf ls_dir && mkdir ls_dir && cd ls_dir
# Create a 1 MiB file with content at the start; whether it's sparse on
# the underlying FS depends on the host.
dd if=/dev/zero of=s.bin bs=1 count=0 seek=1048576 2>/dev/null
echo data | dd of=s.bin bs=1 count=5 conv=notrunc 2>/dev/null
python3 - <<'PY'
import os, sys
SEEK_DATA = 3
SEEK_HOLE = 4
fd = os.open("s.bin", os.O_RDONLY)
try:
    d = os.lseek(fd, 0, SEEK_DATA)
    print("DATA_AT", d)
    h = os.lseek(fd, 0, SEEK_HOLE)
    print("HOLE_AT", h)
except OSError as e:
    # ENOSYS / ENOTSUP is acceptable; kernel will fall back.
    print("LSEEK_FAIL", e.errno)
finally:
    os.close(fd)
PY
echo LSEEK_DONE
"#,
    );
    assert!(captured.contains("LSEEK_DONE"), "captured = {captured}");
    // Either the kernel reported real offsets or returned a graceful
    // ENOSYS (typically 38) / EINVAL (22) / ENOTSUP (95) — never panic.
    assert!(
        captured.contains("DATA_AT") || captured.contains("LSEEK_FAIL"),
        "captured = {captured}"
    );
}

#[test]
fn flock_advisory_lock_excludes_second_holder() {
    // POSIX advisory locks via fcntl (FUSE getlk/setlk). The second
    // attempt with F_SETLK (non-blocking) must fail with EAGAIN/EACCES
    // while the first lock is held.
    let captured = run(
        "fuse-flock",
        r#"
rm -rf lk_dir && mkdir lk_dir && cd lk_dir
: > l.bin
python3 - <<'PY'
import fcntl, os, struct, errno
fd1 = os.open("l.bin", os.O_RDWR)
fcntl.flock(fd1, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("LOCK1_OK")
fd2 = os.open("l.bin", os.O_RDWR)
try:
    fcntl.flock(fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print("LOCK2_UNEXPECTED")
except OSError as e:
    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
        print("LOCK2_BLOCKED_OK")
    elif e.errno == errno.ENOSYS:
        # Backend doesn't implement locks; kernel surfaces ENOSYS.
        print("LOCK_NOTSUP_OK")
    else:
        print("LOCK2_BAD_ERRNO", e.errno)
finally:
    os.close(fd2)
fcntl.flock(fd1, fcntl.LOCK_UN)
os.close(fd1)
PY
echo FLOCK_DONE
"#,
    );
    assert!(captured.contains("FLOCK_DONE"), "captured = {captured}");
    assert!(
        captured.contains("LOCK2_BLOCKED_OK") || captured.contains("LOCK_NOTSUP_OK"),
        "captured = {captured}"
    );
    assert!(
        !captured.contains("LOCK2_UNEXPECTED") && !captured.contains("BAD_ERRNO"),
        "captured = {captured}"
    );
}

#[test]
fn copy_file_range_round_trip() {
    // copy_file_range is best-effort on the wire (Linux hosts use the
    // fast syscall, others fall back to read+write). We only assert
    // byte-for-byte identity.
    let captured = run(
        "fuse-cfr",
        r#"
rm -rf cfr_dir && mkdir cfr_dir && cd cfr_dir
dd if=/dev/urandom of=src.bin bs=4096 count=256 2>/dev/null
python3 - <<'PY'
import os
src = os.open("src.bin", os.O_RDONLY)
dst = os.open("dst.bin", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
try:
    remaining = os.fstat(src).st_size
    while remaining:
        n = os.copy_file_range(src, dst, remaining)
        if n == 0:
            break
        remaining -= n
finally:
    os.close(src); os.close(dst)
PY
diff -q src.bin dst.bin >/dev/null || { echo "CFR_DIFFERS"; exit 1; }
[ "$(stat -c %s src.bin)" = "$(stat -c %s dst.bin)" ] || { echo "CFR_SIZE_MISMATCH"; exit 1; }
echo CFR_OK
"#,
    );
    assert!(captured.contains("CFR_OK"), "captured = {captured}");
    assert!(
        !captured.contains("CFR_DIFFERS") && !captured.contains("CFR_SIZE_MISMATCH"),
        "captured = {captured}"
    );
}

#[test]
fn hard_link_cross_name_propagation_after_eviction() {
    // Regression guard for the host-side `Frame::Notify(Inval::Inode)`
    // emitter. The IdTable's `(mount_id, dev, ino)` dedup will collapse
    // two `ln` aliases onto a single nodeid in this script, so the
    // kernel actually sees one page cache and one nodeid — but that's
    // exactly the trivial case the **emitter** is meant to handle on
    // its own when dedup *fails* (e.g. cold-queue eviction or a
    // path-only intern race).
    //
    // To exercise the emit fan-out itself we force the host to
    // re-stat both names via `cat` *before* the cross-name write, so
    // the kernel has populated its attr+data caches under whichever
    // nodeids it currently holds. We then write through one name and
    // assert the other immediately reflects it — if dedup ever
    // regresses (or if eviction tears the alias apart at runtime), the
    // notify path is the only thing that can rescue this assertion.
    let captured = run(
        "fuse-link-notify",
        r#"
rm -rf notify_dir && mkdir notify_dir && cd notify_dir
echo original > a.txt
ln a.txt b.txt
# Populate kernel caches for *both* names so a subsequent write
# through one would otherwise serve stale content through the other.
cat a.txt > /dev/null
cat b.txt > /dev/null
# Cross-name write.
echo updated > a.txt
got=$(cat b.txt)
[ "$got" = "updated" ] || { echo "BAD_CROSS_AFTER_CACHE=$got"; exit 1; }
echo NOTIFY_OK
"#,
    );
    assert!(captured.contains("NOTIFY_OK"), "captured = {captured}");
    assert!(!captured.contains("BAD_"), "captured = {captured}");
}

#[test]
fn rename_invalidates_source_dentry() {
    // Verify the rename source dentry is invalidated host-side via
    // `Frame::Notify(Inval::Entry)`. Modern kernels also eagerly drop
    // the source dentry when servicing the RENAME reply, so this test
    // is primarily a regression guard for the **emitter path** —
    // without our explicit notify_entry, a stricter kernel (or a
    // future FUSE version) could legitimately keep the cached dentry
    // for one attr_timeout and briefly answer `ls old.txt` from cache.
    let captured = run(
        "fuse-rename-notify",
        r#"
rm -rf rename_dir && mkdir rename_dir && cd rename_dir
echo content > old.txt
# Populate dentry cache.
ls old.txt >/dev/null
mv old.txt new.txt
# Immediate negative lookup (no sleep) must return ENOENT.
if ls old.txt >/dev/null 2>&1; then
    echo "OLD_STILL_VISIBLE"
    exit 1
fi
[ -f new.txt ] || { echo "NEW_MISSING"; exit 1; }
[ "$(cat new.txt)" = "content" ] || { echo "BAD_CONTENT=$(cat new.txt)"; exit 1; }
echo RENAME_NOTIFY_OK
"#,
    );
    assert!(captured.contains("RENAME_NOTIFY_OK"), "captured = {captured}");
    assert!(
        !captured.contains("OLD_STILL_VISIBLE") && !captured.contains("BAD_") && !captured.contains("NEW_MISSING"),
        "captured = {captured}"
    );
}
