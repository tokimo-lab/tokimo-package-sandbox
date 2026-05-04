#!/usr/bin/env bash
# Download VM artifacts (kernel + initrd + rootfs/) from
# tokimo-package-sandbox GitHub releases (tag prefix vm-v*) into <repo>/vm/.
#
# Usage:
#   scripts/linux/fetch-vm.sh                 # latest vm-v* release, host arch
#   scripts/linux/fetch-vm.sh -t vm-v1.9.0    # specific tag
#   scripts/linux/fetch-vm.sh -a arm64        # arm64
#   scripts/linux/fetch-vm.sh -f              # force re-download
#
# Layout produced:
#   vm/vmlinuz        — Linux kernel
#   vm/initrd.img     — initramfs (busybox + tokimo-sandbox-init/fuse/tun-pump)
#   vm/rootfs/        — extracted Debian rootfs directory
#
# Dependencies: curl, jq, tar, zstd.

set -euo pipefail

REPO="tokimo-lab/tokimo-package-sandbox"
TAG="latest"
ARCH=""
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--tag)   TAG="$2"; shift 2 ;;
        -a|--arch)  ARCH="$2"; shift 2 ;;
        -f|--force) FORCE=1; shift ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64)         ARCH="x86_64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *) echo "unsupported host arch: $(uname -m)" >&2; exit 2 ;;
    esac
fi
case "$ARCH" in
    amd64|x86_64) ARCH_NAME="x86_64" ;;
    arm64|aarch64) ARCH_NAME="arm64" ;;
    *) echo "unsupported -a/--arch: $ARCH" >&2; exit 2 ;;
esac

for cmd in curl jq tar zstd; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 2
    fi
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VM_DIR="$REPO_ROOT/vm"
WORK="$(mktemp -d -p "$REPO_ROOT" .fetch-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

KERNEL_ASSET="tokimo-linux-kernel-${ARCH_NAME}.tar.zst"
ROOTFS_ASSET="tokimo-linux-rootfs-${ARCH_NAME}.tar.zst"

if [[ "$TAG" == "latest" ]]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$TAG"
fi

mkdir -p "$VM_DIR"

if [[ $FORCE -eq 0 \
      && -f "$VM_DIR/vmlinuz" \
      && -f "$VM_DIR/initrd.img" \
      && -d "$VM_DIR/rootfs" ]]; then
    echo "vm/ already populated. Use -f/--force to re-download." >&2
    ls -lh "$VM_DIR"
    exit 0
fi

dl() {
    echo "==> $1"
    curl -fL --retry 3 -o "$2" "$1"
}

# 1) kernel + initrd
dl "$BASE/$KERNEL_ASSET" "$WORK/$KERNEL_ASSET"
zstd -d -f "$WORK/$KERNEL_ASSET" -o "$WORK/kernel.tar"
tar -xf "$WORK/kernel.tar" -C "$VM_DIR" vmlinuz initrd.img

# 2) rootfs
dl "$BASE/$ROOTFS_ASSET" "$WORK/$ROOTFS_ASSET"
zstd -d -f "$WORK/$ROOTFS_ASSET" -o "$WORK/rootfs.tar"

rm -rf "$VM_DIR/rootfs"
mkdir -p "$VM_DIR/rootfs"
# rootfs tar uses absolute device files (etc/ already preserves perms);
# extract as the current user — the sandbox doesn't care about ownership
# at runtime since bwrap binds it read-only.
tar -xpf "$WORK/rootfs.tar" -C "$VM_DIR/rootfs"

echo
echo "Done. vm/ contents:"
ls -lh "$VM_DIR"
