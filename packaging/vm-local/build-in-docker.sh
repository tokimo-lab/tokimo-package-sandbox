#!/usr/bin/env bash
# Build minimal Tokimo VM artifacts (vmlinuz + initrd.img + rootfs.vhdx)
# entirely inside a debian:13 container. No external rootfs needed.
#
# Run via: scripts/build-vm-local.ps1 (Windows orchestrator).
#
# Inputs:
#   /vm-base/init.sh            (from packaging/vm-base/, mounted read-only)
#   /vm-base/vsock9p.c          (from packaging/vm-base/, mounted read-only)
#   /work/tokimo-sandbox-init   (musl static, prebuilt, in packaging/vm-local/)
#
# Outputs (placed in /out):
#   /out/vmlinuz
#   /out/initrd.img
#   /out/rootfs.vhdx

set -euo pipefail

WORK=/work
OUT=/out
mkdir -p "$OUT"

BUSYBOX_APPLETS="sh mount umount cat echo poweroff sync chroot mkdir ls base64 insmod cp chmod"

echo "==> [1/6] apt install build deps"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    ca-certificates \
    linux-image-amd64 kmod \
    busybox-static \
    bash coreutils util-linux \
    gcc libc6-dev \
    e2fsprogs qemu-utils \
    xz-utils cpio gzip \
    >/dev/null

echo "==> [2/6] compile vsock9p"
gcc -static -O2 -o /tmp/vsock9p /vm-base/vsock9p.c
ls -lh /tmp/vsock9p

echo "==> [3/6] extract kernel"
KERNEL_PATH=$(ls /boot/vmlinuz-* | head -1)
cp "$KERNEL_PATH" "$OUT/vmlinuz"
ls -lh "$OUT/vmlinuz"

echo "==> [4/6] build initrd"
INITRD=/tmp/initrd
rm -rf "$INITRD"
mkdir -p "$INITRD"/{bin,sbin,proc,sys,dev,mnt/work,tmp,modules,newroot}

cp /bin/busybox "$INITRD/bin/busybox"
chmod +x "$INITRD/bin/busybox"
for a in $BUSYBOX_APPLETS; do
    ln -sf busybox "$INITRD/bin/$a"
done
ln -sf /bin/busybox "$INITRD/sbin/poweroff"
ln -sf /bin/busybox "$INITRD/sbin/init"

cp /vm-base/init.sh "$INITRD/init"
chmod +x "$INITRD/init"

cp /tmp/vsock9p "$INITRD/bin/vsock9p"
chmod +x "$INITRD/bin/vsock9p"

cp "$WORK/tokimo-sandbox-init" "$INITRD/bin/tokimo-sandbox-init"
chmod +x "$INITRD/bin/tokimo-sandbox-init"

KVER=$(ls /lib/modules | head -1)
# Copy each named module + all its transitive dependencies. We use modinfo
# to walk deps. Modules are placed flat under /modules/ so init.sh insmod
# can find them by basename.
KMOD_LIST="hv_vmbus hv_utils vsock hv_sock scsi_common scsi_mod hv_storvsc sd_mod netfs 9pnet 9pnet_fd 9p crc16 crc32c_generic libcrc32c jbd2 mbcache ext4"

resolve_deps() {
    local mod="$1"
    local seen="$2"
    case " $seen " in *" $mod "*) echo "$seen"; return 0;; esac
    seen="$seen $mod"
    local depline
    depline=$(modinfo -F depends -k "$KVER" "$mod" 2>/dev/null || true)
    if [ -n "$depline" ]; then
        local IFS=','
        for d in $depline; do
            [ -z "$d" ] && continue
            seen=$(resolve_deps "$d" "$seen")
        done
    fi
    echo "$seen"
}

ALL_MODS=""
for m in $KMOD_LIST; do
    ALL_MODS=$(resolve_deps "$m" "$ALL_MODS")
done

for m in $ALL_MODS; do
    fname=$(modinfo -F filename -k "$KVER" "$m" 2>/dev/null || true)
    [ -z "$fname" ] && continue
    [ ! -f "$fname" ] && continue
    base=$(basename "$fname")
    case "$base" in
        *.ko.xz) xz -d -c "$fname" > "$INITRD/modules/${base%.xz}" ;;
        *.ko)    cp "$fname" "$INITRD/modules/$base" ;;
    esac
done
echo "    modules: $(ls "$INITRD/modules" | wc -l) files"
ls "$INITRD/modules" | sort

( cd "$INITRD" && find . | cpio -o -H newc 2>/dev/null ) | gzip -9 > "$OUT/initrd.img"
ls -lh "$OUT/initrd.img"

echo "==> [5/6] build minimal rootfs"
ROOTFS=/tmp/rootfs
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,sbin,etc,lib,lib64,usr,proc,sys,dev,run,tmp,home/tokimo,root,mnt/work,var}

# Use rsync-style copy of just what we need from the builder filesystem:
# bash, busybox, coreutils, util-linux + their lib deps. We copy whole /usr,
# /bin, /sbin, /lib, /lib64, /etc and then prune.
cp -a /bin/. "$ROOTFS/bin/"
cp -a /sbin/. "$ROOTFS/sbin/"
cp -a /lib/. "$ROOTFS/lib/"
[ -d /lib64 ] && cp -a /lib64/. "$ROOTFS/lib64/" || true
cp -a /usr "$ROOTFS/" || true
cp -a /etc "$ROOTFS/" || true
mkdir -p "$ROOTFS/var/log" "$ROOTFS/var/tmp"

# Aggressive slim-down.
rm -rf \
    "$ROOTFS"/usr/include \
    "$ROOTFS"/usr/share/man \
    "$ROOTFS"/usr/share/doc \
    "$ROOTFS"/usr/share/locale \
    "$ROOTFS"/usr/share/info \
    "$ROOTFS"/usr/share/lintian \
    "$ROOTFS"/usr/share/common-licenses \
    "$ROOTFS"/usr/share/gcc* \
    "$ROOTFS"/usr/share/perl* \
    "$ROOTFS"/usr/share/icons \
    "$ROOTFS"/usr/share/pixmaps \
    "$ROOTFS"/usr/share/applications \
    "$ROOTFS"/usr/share/menu \
    "$ROOTFS"/usr/share/keyrings \
    "$ROOTFS"/usr/share/cmake \
    "$ROOTFS"/usr/share/zsh \
    "$ROOTFS"/usr/share/fish \
    "$ROOTFS"/usr/share/python-wheels \
    "$ROOTFS"/var/cache/apt \
    "$ROOTFS"/var/lib/apt/lists \
    "$ROOTFS"/var/log/* \
    "$ROOTFS"/usr/lib/gcc \
    "$ROOTFS"/usr/lib/systemd \
    "$ROOTFS"/usr/lib/init \
    "$ROOTFS"/usr/lib/lsb \
    "$ROOTFS"/usr/lib/valgrind \
    "$ROOTFS"/usr/lib/mime \
    "$ROOTFS"/usr/lib/x86_64-linux-gnu/libreoffice* \
    "$ROOTFS"/usr/lib/x86_64-linux-gnu/perl* \
    "$ROOTFS"/usr/lib/perl* \
    "$ROOTFS"/etc/perl \
    "$ROOTFS"/etc/systemd \
    "$ROOTFS"/etc/init.d \
    "$ROOTFS"/etc/cron* \
    "$ROOTFS"/etc/logrotate.d \
    "$ROOTFS"/etc/pam.d \
    "$ROOTFS"/etc/pam.conf \
    "$ROOTFS"/etc/security \
    "$ROOTFS"/usr/share/pam* \
    2>/dev/null || true

# Drop kernel modules from rootfs (initrd carries the ones we need).
rm -rf "$ROOTFS"/lib/modules 2>/dev/null || true
rm -rf "$ROOTFS"/usr/lib/modules 2>/dev/null || true

# Remove gcc / cpp / static libs (only used at build time inside rootfs).
rm -rf "$ROOTFS"/usr/bin/gcc* "$ROOTFS"/usr/bin/cpp* "$ROOTFS"/usr/bin/c++* \
       "$ROOTFS"/usr/lib/gcc-cross "$ROOTFS"/usr/libexec/gcc* 2>/dev/null || true

# Keep terminfo only for xterm (bash readline).
find "$ROOTFS/usr/share/terminfo" -type f ! -path '*/xterm*' -delete 2>/dev/null || true
find "$ROOTFS/usr/share/terminfo" -type d -empty -delete 2>/dev/null || true

# Keep zoneinfo minimal.
find "$ROOTFS/usr/share/zoneinfo" -type f ! -name 'UTC' ! -name 'PRC' \
    ! -path '*/Asia/Shanghai' -delete 2>/dev/null || true
find "$ROOTFS/usr/share/zoneinfo" -type d -empty -delete 2>/dev/null || true

# Set up /etc/passwd, /etc/group with tokimo user.
cat > "$ROOTFS/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/bash
tokimo:x:1000:1000:tokimo:/home/tokimo:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF
cat > "$ROOTFS/etc/group" << 'EOF'
root:x:0:
tokimo:x:1000:
nogroup:x:65534:
EOF
echo 'TokimoOS' > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/os-release" << 'EOF'
PRETTY_NAME="TokimoOS minimal 1.0"
NAME="TokimoOS"
ID=tokimoos
ID_LIKE=debian
VERSION_ID="1.0"
EOF

# Make sure /home/tokimo exists with reasonable defaults.
mkdir -p "$ROOTFS/home/tokimo"
cat > "$ROOTFS/home/tokimo/.bashrc" << 'EOF'
export HOME=/home/tokimo
export USER=tokimo
export PATH=/usr/local/bin:/usr/bin:/bin
EOF
chown -R 1000:1000 "$ROOTFS/home/tokimo"

# Add busybox applets to rootfs as fallback symlinks.
cp /bin/busybox "$ROOTFS/bin/busybox" 2>/dev/null || true
for a in $BUSYBOX_APPLETS; do
    [ -e "$ROOTFS/bin/$a" ] || ln -sf busybox "$ROOTFS/bin/$a"
done

du -sh "$ROOTFS"

echo "==> [6/6] mkfs.ext4 + qemu-img convert → vhdx"
ROOTFS_SIZE_M=$(du -sm "$ROOTFS" | cut -f1)
IMG_SIZE_M=$((ROOTFS_SIZE_M + 256))
echo "    rootfs ${ROOTFS_SIZE_M}M, image ${IMG_SIZE_M}M"

qemu-img create -f raw /tmp/rootfs.img ${IMG_SIZE_M}M >/dev/null
mkfs.ext4 -F -L tokimo-rootfs -d "$ROOTFS" /tmp/rootfs.img >/dev/null

qemu-img convert -f raw -O vhdx -o subformat=dynamic /tmp/rootfs.img "$OUT/rootfs.vhdx"
ls -lh "$OUT/rootfs.vhdx"

echo ""
echo "==> Done. Outputs:"
ls -lh "$OUT"
