#!/usr/bin/env bash
# Build Tokimo VM artifacts (vmlinuz + initrd.img + rootfs) entirely inside
# a debian:13 container. Mirrors the CI pipeline (packaging/vm-base/build.sh)
# but runs as a single-pass script inside one container.
#
# Run via: scripts/build-vm-local.ps1 (Windows) or scripts/build-vm-local.sh (macOS).
#
# Usage: build-in-docker.sh [--arch amd64|arm64] [--format vhdx|dir]
#   --arch     Target architecture (default: amd64)
#   --format   Rootfs output format: vhdx (Windows) or dir (macOS, default: vhdx)
#
# Inputs:
#   /vm-base/init.sh              (from packaging/vm-base/, mounted read-only)
#   /vm-base/vsock9p.c            (from packaging/vm-base/, mounted read-only)
#   /work/tokimo-sandbox-init     (musl static, prebuilt)
#   /work/tokimo-tun-pump         (musl static, prebuilt)
#   /work/tokimo-sandbox-fuse     (musl static, prebuilt)
#
# Outputs (placed in /out):
#   /out/vmlinuz
#   /out/initrd.img
#   /out/rootfs.vhdx  (format=vhdx)
#   /out/rootfs/       (format=dir)

set -euo pipefail

ARCH="amd64"
FORMAT="vhdx"
while [ $# -gt 0 ]; do
    case "$1" in
        --arch)   ARCH="$2";   shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        *) echo "build-in-docker: unknown arg: $1" >&2; exit 1 ;;
    esac
done

case "$ARCH" in
    amd64) KERNEL_PKG="linux-image-amd64"; DEB_MULTIARCH="x86_64-linux-gnu" ;;
    arm64) KERNEL_PKG="linux-image-arm64";  DEB_MULTIARCH="aarch64-linux-gnu" ;;
    *) echo "build-in-docker: unsupported arch $ARCH" >&2; exit 1 ;;
esac

WORK=/work
OUT=/out
mkdir -p "$OUT"

BUSYBOX_APPLETS="sh mount umount cat echo poweroff sync chroot mkdir ls base64 insmod cp chmod udhcpc ip"

# ---------------------------------------------------------------------------
# [1/5] Install packages (mirrors CI: kernel + busybox + runtimes)
# ---------------------------------------------------------------------------
echo "==> [1/5] install packages (arch=$ARCH, format=$FORMAT)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl >/dev/null
apt-get update -qq

# Core packages — same as CI but without the heavyweight office/media tools.
apt-get install -y --no-install-recommends \
    gnupg vim nano less procps \
    wget git jq unzip zip bzip2 xz-utils zstd \
    iputils-ping rsync dnsutils \
    python3 python3-pip python3-venv \
    bash-completion \
    busybox-static \
    gcc libc6-dev \
    kmod \
    "$KERNEL_PKG" \
    >/dev/null

# Node.js 24 (same as CI)
curl -fsSL https://deb.nodesource.com/setup_24.x | bash - >/dev/null 2>&1
apt-get install -y --no-install-recommends nodejs >/dev/null

# tokimo user (same as CI)
groupadd -g 1000 tokimo 2>/dev/null || true
useradd -m -u 1000 -g 1000 -s /bin/bash -d /home/tokimo tokimo 2>/dev/null || true

# pip packages (same as CI)
mkdir -p /home/tokimo/python_packages
pip3 install --break-system-packages --target=/home/tokimo/python_packages \
    requests ipython rich \
    pypdf pdfplumber reportlab pdf2image \
    pandas openpyxl Pillow >/dev/null 2>&1

ln -sf ../../bin/python3 /usr/local/bin/python

# Environment setup (same as CI)
cat > /etc/profile.d/tokimo_env.sh << 'ENVEOF'
export HOME=/home/tokimo
export USER=tokimo
export LOGNAME=tokimo
export PATH=/home/tokimo/bin:/usr/local/bin:/usr/bin:/bin
export PYTHONPATH=/home/tokimo/python_packages${PYTHONPATH:+:$PYTHONPATH}
export PIP_TARGET=/home/tokimo/python_packages
export PYTHONPYCACHEPREFIX="/tmp/.pycache-${UID}"
ENVEOF
chmod +x /etc/profile.d/tokimo_env.sh

cat > /etc/bash.bashrc << 'BASHRCEOF'
for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done
unset f
[ -f ~/.bashrc ] && . ~/.bashrc
BASHRCEOF

cat > /home/tokimo/.bashrc << 'DOTBASHRC'
export HISTSIZE=10000
export HISTFILESIZE=20000
PS1='[\[\033[35;1m\]\u\[\033[0m\]@\[\033[31;1m\]TokimoOS\[\033[0m\]:\[\033[32;1m\]$PWD\[\033[0m\]]\$ '
alias ls='ls --color=auto'
alias ll='ls -lah --color=auto'
DOTBASHRC

cat > /home/tokimo/.bash_profile << 'DOTPROFILE'
[ -f ~/.bashrc ] && . ~/.bashrc
DOTPROFILE

echo 'TokimoOS' > /etc/hostname
cat > /etc/os-release << 'OSEOF'
PRETTY_NAME="TokimoOS 1.0"
NAME="TokimoOS"
ID=tokimoos
ID_LIKE=debian
VERSION_ID="1.0"
OSEOF

chown -R tokimo:tokimo /home/tokimo

echo "--- verification ---"
node --version
python3 --version

# ---------------------------------------------------------------------------
# [2/5] extract kernel
# ---------------------------------------------------------------------------
echo "==> [2/5] extract kernel"
KERNEL_PATH=$(ls /boot/vmlinuz-* | head -1)
cp "$KERNEL_PATH" "$OUT/vmlinuz"
ls -lh "$OUT/vmlinuz"

# ---------------------------------------------------------------------------
# [3/5] build initrd
# ---------------------------------------------------------------------------
echo "==> [3/5] build initrd"
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

for bin in tokimo-sandbox-init tokimo-tun-pump tokimo-sandbox-fuse; do
    cp "$WORK/$bin" "$INITRD/bin/$bin"
    chmod +x "$INITRD/bin/$bin"
done

KVER=$(ls /lib/modules | head -1)
KMOD_LIST="hv_vmbus hv_utils vsock hv_sock scsi_common scsi_mod hv_storvsc sd_mod netfs crc16 crc32c_generic libcrc32c jbd2 mbcache ext4 hv_netvsc failover net_failover tun"
if [ "$ARCH" = "arm64" ]; then
    KMOD_LIST="$KMOD_LIST vmw_vsock_virtio_transport virtio_net"
fi
KMOD_LIST="$KMOD_LIST sunrpc auth_rpcgss lockd grace nfs_acl nfs nfsv3"

resolve_deps() {
    local mod="$1" seen="$2"
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

( cd "$INITRD" && find . | cpio -o -H newc 2>/dev/null ) | gzip -9 > "$OUT/initrd.img"
ls -lh "$OUT/initrd.img"

# ---------------------------------------------------------------------------
# [4/5] Slim down the container filesystem (mirrors CI)
# ---------------------------------------------------------------------------
echo "==> [4/5] slim down rootfs"

# Remove build-only / dev packages
rm -rf /usr/include
rm -rf /usr/share/man /usr/share/doc /usr/share/locale /usr/share/info
rm -rf /usr/share/lintian /usr/share/common-licenses
rm -rf /usr/share/gcc* /usr/share/perl*
rm -rf /usr/share/icons /usr/share/pixmaps /usr/share/applications /usr/share/menu
rm -rf /usr/share/keyrings /usr/share/cmake /usr/share/zsh /usr/share/fish
rm -rf /usr/share/python-wheels
rm -rf /usr/share/vim/vim*/doc /usr/share/vim/vim*/tutor
rm -rf /usr/lib/systemd /usr/lib/init /etc/systemd /etc/init.d
rm -rf /var/lib/systemd /usr/lib/tmpfiles.d /usr/lib/sysctl.d
rm -rf /usr/lib/udev /etc/udev 2>/dev/null || true
rm -rf /usr/share/polkit-1
rm -rf /usr/share/gdb /usr/share/gitweb /usr/share/tabset
rm -rf /etc/pam.d /etc/pam.conf /etc/security /usr/share/pam*
rm -rf /var/lib/pam
rm -rf /etc/cron* /etc/logrotate.d /etc/logcheck
rm -rf /usr/lib/lsb /usr/lib/valgrind /usr/lib/mime

# Remove gcc (build-time only)
rm -rf /usr/bin/gcc* /usr/bin/cpp* /usr/bin/c++* \
       /usr/lib/gcc-cross /usr/libexec/gcc* 2>/dev/null || true

# Keep terminfo only for xterm
find /usr/share/terminfo -type f ! -path '*/xterm*' -delete 2>/dev/null || true
find /usr/share/terminfo -type d -empty -delete 2>/dev/null || true

# Keep zoneinfo minimal
find /usr/share/zoneinfo -type f \
    ! -path '*/Asia/*' ! -name 'UTC' ! -name 'PRC' ! -name 'posixrules' \
    -delete 2>/dev/null || true
find /usr/share/zoneinfo -type d -empty -delete 2>/dev/null || true

# Remove kernel modules from rootfs (initrd carries them)
find /lib/modules -name '*.ko*' -delete 2>/dev/null || true
rm -rf /lib/modules/*/kernel 2>/dev/null || true

# Clean caches
apt-get clean 2>/dev/null || true
rm -rf /var/lib/apt/lists/* /var/cache/apt /var/log/apt /var/log/*.log
rm -rf /root/.npm /root/.cache /home/tokimo/.cache
find / -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find / -name '*.pyc' -delete 2>/dev/null || true

du -sh /

# ---------------------------------------------------------------------------
# [5/5] Export rootfs
# ---------------------------------------------------------------------------
# Stage the rootfs by copying real directories only (skip /proc, /sys, /dev, /tmp
# which are virtual mounts inside the container).
ROOTFS=/tmp/rootfs-stage
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"
for d in bin sbin etc lib lib64 usr home root mnt opt run srv var; do
    [ -d "/$d" ] && cp -a "/$d" "$ROOTFS/" 2>/dev/null || true
done
mkdir -p "$ROOTFS"/{proc,sys,dev,mnt/work,tmp}

# Pre-compile Python stdlib .pyc (mirrors CI)
PYLIB=$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null) \
    && python3 -m compileall -q -j 0 "$PYLIB" 2>/dev/null || true

ROOTFS_SIZE_M=$(du -sm "$ROOTFS" | cut -f1)

if [ "$FORMAT" = "vhdx" ]; then
    echo "==> [5/5] mkfs.ext4 + qemu-img convert -> vhdx (rootfs ~${ROOTFS_SIZE_M}M)"
    IMG_SIZE_M=$((ROOTFS_SIZE_M + 256))
    qemu-img create -f raw /tmp/rootfs.img "${IMG_SIZE_M}M" >/dev/null
    mkfs.ext4 -F -L tokimo-rootfs -d "$ROOTFS" /tmp/rootfs.img >/dev/null
    qemu-img convert -f raw -O vhdx -o subformat=dynamic /tmp/rootfs.img "$OUT/rootfs.vhdx"
    ls -lh "$OUT/rootfs.vhdx"
else
    echo "==> [5/5] copy rootfs directory (rootfs ~${ROOTFS_SIZE_M}M)"
    cp -a "$ROOTFS" "$OUT/rootfs"
    ls -lh "$OUT/rootfs"
fi

echo ""
echo "==> Done. Outputs:"
ls -lh "$OUT"
