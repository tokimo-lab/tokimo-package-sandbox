#!/usr/bin/env bash
# Phase 2: Build minimal rootfs.vhdx for Windows Hyper-V sandbox
#
# Run inside WSL Ubuntu 22.04:
#   bash scripts/wsl/02-build-rootfs.sh
#
# Output:
#   /tmp/tokimo-build/out/rootfs.vhdx       — ext4 VHDX, ~150 MB dynamic
#   /tmp/tokimo-build/out/vmlinuz           — copied from Claude bundle
#   /tmp/tokimo-build/out/initrd            — copied from Claude bundle
#
# The script only needs sudo for ONE thing: installing build deps via apt
# (qemu-utils, e2fsprogs, musl-tools, rust musl target). The actual
# rootfs/vhdx building uses `mkfs.ext4 -d` so no mount/loop required.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KERNEL_VERSION="6.8.0-106-generic"
UBUNTU_RELEASE="jammy"   # 22.04
UBUNTU_BASE_URL="https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.5-base-amd64.tar.gz"
MODULES_DEB_URLS=(
    # linux-modules-${KERNEL_VERSION} — has 9p, vsock, hv_sock
    "http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.8/linux-modules-${KERNEL_VERSION}_6.8.0-106.106~22.04.1_amd64.deb"
    # linux-modules-extra has additional drivers (kept just in case)
    "http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.8/linux-modules-extra-${KERNEL_VERSION}_6.8.0-106.106~22.04.1_amd64.deb"
)

CLAUDE_BUNDLE="/mnt/c/Users/William/AppData/Local/Claude-3p/vm_bundles/claudevm.bundle"
WORK="/tmp/tokimo-build"
SANDBOX_REPO="/mnt/f/tokimo-package-sandbox"
OUT="$WORK/out"

mkdir -p "$WORK" "$OUT" "$WORK/dl" "$WORK/rootfs" "$WORK/modules-extract"

# ---------------------------------------------------------------------------
# Step 0: ensure deps
# ---------------------------------------------------------------------------
echo "===== 0. Checking build deps ====="
need_pkgs=()
for cmd in qemu-img mke2fs musl-gcc curl rustup; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        case "$cmd" in
            qemu-img)   need_pkgs+=("qemu-utils") ;;
            mke2fs)     need_pkgs+=("e2fsprogs") ;;
            musl-gcc)   need_pkgs+=("musl-tools") ;;
            curl)       need_pkgs+=("curl") ;;
            rustup)     need_pkgs+=("__rustup__") ;;
        esac
    fi
done

if [ ${#need_pkgs[@]} -gt 0 ]; then
    apt_pkgs=()
    needs_rustup=0
    for p in "${need_pkgs[@]}"; do
        if [ "$p" = "__rustup__" ]; then needs_rustup=1; else apt_pkgs+=("$p"); fi
    done
    if [ ${#apt_pkgs[@]} -gt 0 ]; then
        echo "Installing: ${apt_pkgs[*]} (will sudo)"
        sudo apt-get update -q
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${apt_pkgs[@]}"
    fi
    if [ "$needs_rustup" = 1 ]; then
        echo "Installing rustup (no sudo)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
        # shellcheck source=/dev/null
        . "$HOME/.cargo/env"
    fi
fi

# Need rust musl target.
if command -v rustup >/dev/null 2>&1; then
    # shellcheck source=/dev/null
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Step 1: Download Ubuntu base + kernel modules
# ---------------------------------------------------------------------------
echo "===== 1. Downloading artifacts ====="

UBUNTU_BASE_TAR="$WORK/dl/ubuntu-base.tar.gz"
if [ ! -f "$UBUNTU_BASE_TAR" ]; then
    echo "Downloading Ubuntu base..."
    curl -fL --retry 3 -o "$UBUNTU_BASE_TAR" "$UBUNTU_BASE_URL"
fi
ls -la "$UBUNTU_BASE_TAR"

for url in "${MODULES_DEB_URLS[@]}"; do
    fn="$WORK/dl/$(basename "$url")"
    if [ ! -f "$fn" ]; then
        echo "Downloading $(basename "$url")..."
        curl -fL --retry 3 -o "$fn" "$url" || {
            echo "FAILED to download $url"
            echo "If the version is wrong, check http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.8/"
            exit 1
        }
    fi
    ls -la "$fn"
done

# ---------------------------------------------------------------------------
# Step 2: Compile tokimo-sandbox-init (musl static)
# ---------------------------------------------------------------------------
echo "===== 2. Cross-compiling tokimo-sandbox-init (musl) ====="
cd "$SANDBOX_REPO"
# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

# musl linker config
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc

cargo build --release --target x86_64-unknown-linux-musl --bin tokimo-sandbox-init 2>&1 | tail -20

INIT_BIN="$SANDBOX_REPO/target/x86_64-unknown-linux-musl/release/tokimo-sandbox-init"
[ -x "$INIT_BIN" ] || { echo "ERROR: $INIT_BIN missing"; exit 1; }
file "$INIT_BIN"
ls -la "$INIT_BIN"

# ---------------------------------------------------------------------------
# Step 3: Assemble rootfs
# ---------------------------------------------------------------------------
echo "===== 3. Assembling rootfs ====="
ROOTFS="$WORK/rootfs"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"

cd "$ROOTFS"
echo "Extracting Ubuntu base..."
tar --extract --gzip --file="$UBUNTU_BASE_TAR" --numeric-owner

echo "Extracting kernel modules .deb (to temp staging to preserve usrmerge symlinks)..."
MOD_STAGE="$WORK/modules-extract"
rm -rf "$MOD_STAGE"
mkdir -p "$MOD_STAGE"
for f in "$WORK"/dl/linux-modules-*.deb; do
    echo "  $(basename "$f")"
    dpkg-deb -x "$f" "$MOD_STAGE"
done
# .deb contains /lib/modules/... which would clobber the /lib -> usr/lib
# symlink if extracted directly. Move modules into /usr/lib/modules/ and
# preserve usrmerge.
if [ -d "$MOD_STAGE/lib/modules" ]; then
    mkdir -p "$ROOTFS/usr/lib/modules"
    cp -a "$MOD_STAGE/lib/modules/." "$ROOTFS/usr/lib/modules/"
fi
if [ -d "$MOD_STAGE/lib/firmware" ]; then
    mkdir -p "$ROOTFS/usr/lib/firmware"
    cp -a "$MOD_STAGE/lib/firmware/." "$ROOTFS/usr/lib/firmware/"
fi
# Anything else from the deb (rare) — copy preserving structure but
# do not allow it to replace /lib symlink.
for d in "$MOD_STAGE"/usr/*; do
    [ -e "$d" ] || continue
    name="$(basename "$d")"
    cp -a "$d/." "$ROOTFS/usr/$name/" 2>/dev/null || cp -a "$d" "$ROOTFS/usr/" || true
done

# Belt-and-braces: ensure /lib is still a symlink to usr/lib.
if [ -d "$ROOTFS/lib" ] && [ ! -L "$ROOTFS/lib" ]; then
    # Migrate any stragglers and re-create the symlink.
    mkdir -p "$ROOTFS/usr/lib"
    cp -a "$ROOTFS/lib/." "$ROOTFS/usr/lib/" || true
    rm -rf "$ROOTFS/lib"
    ln -s usr/lib "$ROOTFS/lib"
fi

# Verify modules we care about exist.
echo ""
echo "--- Module check ---"
for m in 9pnet 9pnet_fd 9p hv_sock vsock vsock_loopback hv_vmbus hv_storvsc; do
    found=$(find "$ROOTFS/lib/modules/$KERNEL_VERSION" -name "${m}.ko*" 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo "  OK $m: $found"
    else
        echo "  MISSING $m"
    fi
done

# Install our agent.
mkdir -p "$ROOTFS/usr/local/bin"
cp "$INIT_BIN" "$ROOTFS/usr/local/bin/tokimo-sandbox-init"
chmod +x "$ROOTFS/usr/local/bin/tokimo-sandbox-init"

# Write the /sbin/init shim — replaces upstart/systemd entirely.
# This becomes PID 1 inside the VM after switch_root from initrd.
cat > "$ROOTFS/sbin/init" <<'SBIN_INIT'
#!/bin/sh
# tokimo-sandbox PID 1: minimal boot, mount workspace, exec agent.
#
# At this point we are PID 1 in the rootfs (post switch_root from initrd).
# The initrd already mounted /proc /sys /dev as part of standard initramfs.

exec </dev/console >/dev/console 2>&1

echo "[tokimo-init] PID 1 starting on $(uname -r)"

# Make sure /proc /sys /dev are present (idempotent).
[ -d /proc/1 ] || mount -t proc  proc  /proc  || true
[ -d /sys/kernel ] || mount -t sysfs sysfs /sys || true
[ -e /dev/console ] || mount -t devtmpfs devtmpfs /dev || true
mkdir -p /dev/pts /dev/shm /run /tmp /mnt/work
mount -t devpts devpts /dev/pts -o noexec,nosuid,gid=5,mode=0620 || true
mount -t tmpfs  tmpfs  /run  -o mode=0755,nosuid,nodev || true
mount -t tmpfs  tmpfs  /tmp  -o mode=1777,nosuid,nodev || true

echo "[tokimo-init] loading kernel modules via finit_module (no modprobe)"
KMOD_DIR="/lib/modules/$(uname -r)/kernel"
# Order matters: hv_vmbus first, then hv_sock (depends on vmbus), then
# AF_VSOCK transport modules, then 9p over fd.
/usr/local/bin/tokimo-sandbox-init --load-modules \
    "$KMOD_DIR/drivers/hv/hv_vmbus.ko" \
    "$KMOD_DIR/drivers/hv/hv_utils.ko" \
    "$KMOD_DIR/net/vmw_vsock/vsock.ko" \
    "$KMOD_DIR/net/vmw_vsock/hv_sock.ko" \
    "$KMOD_DIR/net/9p/9pnet.ko" \
    "$KMOD_DIR/net/9p/9pnet_fd.ko" \
    "$KMOD_DIR/fs/9p/9p.ko" \
    || echo "[tokimo-init] WARN: some modules failed to load"

# Parse cmdline for our params.
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")
WORK_PORT=""
INIT_PORT=50003
for arg in $CMDLINE; do
    case "$arg" in
        tokimo.work_port=*) WORK_PORT="${arg#tokimo.work_port=}" ;;
        tokimo.init_port=*) INIT_PORT="${arg#tokimo.init_port=}" ;;
    esac
done

# Mount workspace via 9p-over-vsock (Hyper-V Plan9).
# Hyper-V exposes the 9p server on host vsock CID=2. We connect via
# AF_VSOCK and pass the fd to 9pnet via trans=fd,rfdno=N,wfdno=N.
if [ -n "$WORK_PORT" ]; then
    echo "[tokimo-init] mounting workspace via vsock port $WORK_PORT"
    if [ -x /usr/local/bin/vsock9p ]; then
        /usr/local/bin/vsock9p /mnt/work "$WORK_PORT" work || \
            echo "[tokimo-init] WARN: vsock9p failed for port $WORK_PORT"
    else
        # Fallback: use a simple python helper if available, else give up.
        echo "[tokimo-init] WARN: /usr/local/bin/vsock9p missing"
    fi
else
    echo "[tokimo-init] no tokimo.work_port — workspace not mounted"
fi

# Hand off to the Rust agent.
export TOKIMO_SANDBOX_VSOCK_PORT="$INIT_PORT"
export TOKIMO_SANDBOX_PRE_CHROOTED=1
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "[tokimo-init] exec agent (vsock port=$INIT_PORT)"
exec /usr/local/bin/tokimo-sandbox-init

# If agent returns, halt the VM.
echo "[tokimo-init] agent exited; halting"
exec /sbin/poweroff -f 2>/dev/null || /bin/sh
SBIN_INIT
chmod +x "$ROOTFS/sbin/init"

# Compile vsock9p (small C helper) if source is available.
VSOCK9P_SRC="/mnt/f/tokimo-package-rootfs/vsock9p.c"
if [ -f "$VSOCK9P_SRC" ]; then
    echo "Compiling vsock9p..."
    musl-gcc -static -O2 -o "$ROOTFS/usr/local/bin/vsock9p" "$VSOCK9P_SRC" || \
        gcc -static -O2 -o "$ROOTFS/usr/local/bin/vsock9p" "$VSOCK9P_SRC"
    chmod +x "$ROOTFS/usr/local/bin/vsock9p"
else
    echo "WARN: $VSOCK9P_SRC not found; will mount 9p only via plain mount(8) if possible"
fi

# Strip down: remove docs, locales, apt cache to shrink image.
echo "Slimming rootfs..."
rm -rf "$ROOTFS/usr/share/doc" "$ROOTFS/usr/share/man" "$ROOTFS/usr/share/locale" \
       "$ROOTFS/var/cache/apt" "$ROOTFS/var/lib/apt/lists" \
       "$ROOTFS/usr/share/info" "$ROOTFS/usr/share/lintian" 2>/dev/null || true

# Drop Mellanox / unrelated heavy modules to keep size down (we only need
# Hyper-V + 9p + vsock).
echo "Pruning unneeded kernel modules..."
MODDIR="$ROOTFS/lib/modules/$KERNEL_VERSION/kernel"
if [ -d "$MODDIR" ]; then
    # Keep only what we need.
    KEEP_PATHS="
        drivers/hv
        drivers/scsi/hv_storvsc.ko
        drivers/scsi/scsi_transport_fc.ko
        drivers/scsi/scsi_common.ko
        drivers/net/hyperv
        net/9p
        fs/9p
        fs/netfs
        net/vmw_vsock
    "
    # Two-pass: collect everything, blacklist the heavy stuff
    find "$MODDIR" -type d \( \
        -path "*/drivers/gpu*" -o \
        -path "*/drivers/infiniband*" -o \
        -path "*/drivers/net/ethernet*" -o \
        -path "*/drivers/net/wireless*" -o \
        -path "*/drivers/usb*" -o \
        -path "*/drivers/media*" -o \
        -path "*/drivers/staging*" -o \
        -path "*/drivers/iio*" -o \
        -path "*/sound*" -o \
        -path "*/drivers/crypto*" -o \
        -path "*/fs/btrfs*" -o \
        -path "*/fs/xfs*" -o \
        -path "*/fs/ocfs2*" -o \
        -path "*/fs/ceph*" -o \
        -path "*/fs/nfs*" -o \
        -path "*/fs/cifs*" -o \
        -path "*/fs/gfs2*" \
        \) -exec rm -rf {} + 2>/dev/null || true
    # Rebuild modules.dep so modprobe still works.
    depmod --basedir "$ROOTFS" "$KERNEL_VERSION" || true
fi

# ---------------------------------------------------------------------------
# Step 4: Build ext4 image (no mount/loop required)
# ---------------------------------------------------------------------------
echo ""
echo "===== 4. Building ext4 image ====="
SIZE_MB=400
RAW_IMG="$WORK/rootfs.img"
rm -f "$RAW_IMG"
truncate -s "${SIZE_MB}M" "$RAW_IMG"

# mkfs.ext4 -d populates from a directory at format time — no mount needed.
# -E options speed up creation; -L sets label; -F bypasses block-device check.
mke2fs -t ext4 -L tokimo-root -F \
    -E lazy_itable_init=0,lazy_journal_init=0 \
    -d "$ROOTFS" \
    "$RAW_IMG"

ls -la "$RAW_IMG"

# ---------------------------------------------------------------------------
# Step 5: Convert to VHDX
# ---------------------------------------------------------------------------
echo ""
echo "===== 5. Converting to VHDX ====="
qemu-img convert -O vhdx -o subformat=dynamic "$RAW_IMG" "$OUT/rootfs.vhdx"
qemu-img info "$OUT/rootfs.vhdx"
ls -la "$OUT/rootfs.vhdx"

# ---------------------------------------------------------------------------
# Step 6: Stage kernel + initrd
# ---------------------------------------------------------------------------
echo ""
echo "===== 6. Staging kernel + initrd ====="
cp -f "$CLAUDE_BUNDLE/vmlinuz" "$OUT/vmlinuz"
cp -f "$CLAUDE_BUNDLE/initrd"  "$OUT/initrd"
ls -la "$OUT/"

echo ""
echo "===== DONE ====="
echo "Artifacts ready at $OUT/"
echo ""
echo "Next: run scripts/install-artifacts.ps1 (PowerShell) to copy them into"
echo "%USERPROFILE%\\.tokimo\\ for use by tokimo-sandbox-svc."
