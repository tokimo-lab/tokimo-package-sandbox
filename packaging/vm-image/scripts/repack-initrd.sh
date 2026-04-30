#!/usr/bin/env bash
# Repack initrd.img: take the existing busybox + new init + new vsock9p
# and produce a fresh gzipped cpio ready to feed into HCS.
#
# Usage (inside WSL):
#   bash scripts/repack-initrd.sh
#
# Output (paths assume a local dev checkout at /mnt/f/tokimo-package-sandbox):
#   /mnt/f/tokimo-package-sandbox/initrd-new.img
#   /mnt/f/tokimo-package-sandbox/packaging/vm-image/tokimo-os-amd64/initrd.img  (overwritten)
set -euo pipefail

ROOTFS_PROJ=/mnt/f/tokimo-package-sandbox/packaging/vm-image
PREP="$ROOTFS_PROJ/initrd-prep"
FINAL="$ROOTFS_PROJ/tokimo-os-amd64/initrd.img"
OUT=/tmp/tokimo-initrd.img
GENKERN="${GENKERN:-/tmp/tokimo-genkern}"

echo "==> compiling vsock9p"
mkdir -p "$PREP/bin"
gcc -static -O2 -o "$PREP/bin/vsock9p" "$ROOTFS_PROJ/vsock9p.c"

echo "==> ensuring busybox is present"
if [ ! -x "$PREP/bin/busybox" ]; then
    cp "$ROOTFS_PROJ/tokimo-os-amd64/busybox" "$PREP/bin/busybox"
    chmod +x "$PREP/bin/busybox"
fi

# Make the standard busybox applet symlinks if not already.
cd "$PREP/bin"
for applet in sh mount umount cat echo poweroff sync chroot mkdir ls base64 cp ln rm sleep insmod; do
    if [ ! -e "$applet" ]; then
        ln -sf busybox "$applet"
    fi
done
cd - >/dev/null

# /sbin -> ../bin alias for poweroff & friends
mkdir -p "$PREP/sbin"
for a in poweroff reboot init; do
    ln -sf ../bin/busybox "$PREP/sbin/$a" 2>/dev/null || true
done

echo "==> installing init script"
cp "$ROOTFS_PROJ/init.sh" "$PREP/init"
chmod +x "$PREP/init"

# Bundle the static-musl tokimo-sandbox-init binary so init.sh can exec
# into it for session mode. Built via: cross build --target
# x86_64-unknown-linux-musl --bin tokimo-sandbox-init --release  (run on
# the Windows host).
SANDBOX_INIT_BIN="${SANDBOX_INIT_BIN:-/mnt/f/tokimo-package-sandbox/target/x86_64-unknown-linux-musl/release/tokimo-sandbox-init}"
if [ -x "$SANDBOX_INIT_BIN" ]; then
    cp "$SANDBOX_INIT_BIN" "$PREP/bin/tokimo-sandbox-init"
    chmod +x "$PREP/bin/tokimo-sandbox-init"
    echo "==>   bundled tokimo-sandbox-init ($(stat -c%s "$PREP/bin/tokimo-sandbox-init") bytes)"
else
    echo "==>   WARNING: $SANDBOX_INIT_BIN missing — session mode will be unavailable"
fi

# Copy kernel modules (decompress .ko.xz so busybox insmod can load them).
echo "==> copying kernel modules from $GENKERN/modules"
rm -rf "$PREP/modules"
mkdir -p "$PREP/modules"
if [ -d "$GENKERN/modules" ]; then
    for f in "$GENKERN"/modules/*.ko*; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        case "$base" in
            *.ko.xz)
                out="$PREP/modules/${base%.xz}"
                xz -d -c "$f" > "$out"
                ;;
            *.ko)
                cp "$f" "$PREP/modules/$base"
                ;;
        esac
    done
    echo "==>   $(ls "$PREP/modules" | wc -l) modules installed"
else
    echo "==>   WARNING: $GENKERN/modules missing — initrd will boot without modules"
fi

# Ensure required dirs exist.
for d in proc sys dev mnt mnt/work newroot tmp run; do
    mkdir -p "$PREP/$d"
done

echo "==> creating cpio.gz"
cd "$PREP"
# Reproducible-ish: sorted name list; preserve perms.
find . -mindepth 1 \( -path './initrd*' -prune -o -print \) | LC_ALL=C sort \
    | cpio -o -H newc --quiet --reproducible \
    | gzip -9 -n > "$OUT"
cd - >/dev/null

echo "==> done: $OUT ($(stat -c%s "$OUT") bytes)"
echo "==> copying to $FINAL"
cp "$OUT" "$FINAL"
ls -la "$FINAL"
