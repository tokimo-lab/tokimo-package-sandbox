#!/usr/bin/env bash
# Download VM artifacts (kernel + initrd + rootfs/) from
# tokimo-package-sandbox GitHub releases into <repo>/.vm/base/.
#
# Kernel and rootfs are published under independent tag namespaces:
#   vm-kernel-*  → vmlinuz + initrd.img (tokimo guest bins baked in)
#   vm-rootfs-*  → rootfs tarball (Debian, no tokimo bins)
#
# Usage:
#   scripts/linux/fetch-vm.sh                              # latest of each
#   scripts/linux/fetch-vm.sh -k vm-kernel-1.0.0          # pin kernel tag
#   scripts/linux/fetch-vm.sh -r vm-rootfs-1.0.0          # pin rootfs tag
#   scripts/linux/fetch-vm.sh -a arm64                    # arm64
#   scripts/linux/fetch-vm.sh -f                          # force re-download
#
# Layout produced:
#   .vm/base/vmlinuz        — Linux kernel (mac/win backends)
#   .vm/base/initrd.img     — initramfs (busybox + tokimo-sandbox-init/fuse/tun-pump)
#   .vm/base/rootfs/        — extracted Debian rootfs directory (no tokimo bins)
#
# For the ch backend, additionally run scripts/linux/fetch-ch-deps.sh to
# populate bin/cloud-hypervisor/ and bin/virtiofsd/ (ch reuses the same
# vmlinuz this script fetches — no separate kernel artifact).
#
# Dependencies: curl, jq, tar, zstd.

set -euo pipefail

REPO="tokimo-lab/tokimo-package-sandbox"
KERNEL_TAG="latest"
ROOTFS_TAG="latest"
ARCH=""
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--kernel-tag) KERNEL_TAG="$2"; shift 2 ;;
        -r|--rootfs-tag) ROOTFS_TAG="$2"; shift 2 ;;
        -a|--arch)       ARCH="$2"; shift 2 ;;
        -f|--force)      FORCE=1; shift ;;
        -h|--help)
            sed -n '2,21p' "$0" | sed 's/^# \?//'
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
VM_DIR="$REPO_ROOT/.vm/base"
WORK="$(mktemp -d -p "$REPO_ROOT" .fetch-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

KERNEL_ASSET="tokimo-linux-kernel-${ARCH_NAME}.tar.zst"
ROOTFS_ASSET="tokimo-linux-rootfs-${ARCH_NAME}.tar.zst"

resolve_base() {
    local tag="$1" prefix="$2"
    if [[ "$tag" == "latest" ]]; then
        local hit
        hit=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" \
              | jq -r --arg p "$prefix" '[.[] | select(.tag_name | startswith($p))][0].tag_name')
        if [[ -z "$hit" || "$hit" == "null" ]]; then
            echo "no release found for tag prefix $prefix*" >&2; exit 1
        fi
        echo "https://github.com/$REPO/releases/download/$hit"
    else
        echo "https://github.com/$REPO/releases/download/$tag"
    fi
}

KERNEL_BASE=$(resolve_base "$KERNEL_TAG" "vm-kernel-")
ROOTFS_BASE=$(resolve_base "$ROOTFS_TAG" "vm-rootfs-")

mkdir -p "$VM_DIR"

if [[ $FORCE -eq 0 \
      && -f "$VM_DIR/vmlinuz" \
      && -f "$VM_DIR/initrd.img" \
      && -d "$VM_DIR/rootfs" ]]; then
    echo ".vm/base already populated. Use -f/--force to re-download." >&2
    ls -lh "$VM_DIR"
    exit 0
fi

dl() {
    echo "==> $1"
    curl -fL --retry 3 -o "$2" "$1"
}

# 1) kernel + initrd
dl "$KERNEL_BASE/$KERNEL_ASSET" "$WORK/$KERNEL_ASSET"
zstd -d -f "$WORK/$KERNEL_ASSET" -o "$WORK/kernel.tar"
tar -xf "$WORK/kernel.tar" -C "$VM_DIR"

# 2) rootfs
dl "$ROOTFS_BASE/$ROOTFS_ASSET" "$WORK/$ROOTFS_ASSET"
zstd -d -f "$WORK/$ROOTFS_ASSET" -o "$WORK/rootfs.tar"

if [[ -e "$VM_DIR/rootfs" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
        rm -rf "$VM_DIR/rootfs"
    elif ! rm -rf "$VM_DIR/rootfs" 2>/dev/null; then
        # Previous extraction may have created root-owned files.
        sudo rm -rf "$VM_DIR/rootfs"
    fi
fi
mkdir -p "$VM_DIR/rootfs"
# rootfs.tar carries numeric uid/gid (notably tokimo=1000 / root=0).
# Preserving them matters because:
#   - the rootfs ships /etc/passwd with `tokimo:x:1000:1000:…`; if the
#     extraction renumbers files to the host user's uid (e.g. 1001) then
#     the tokimo account owns nothing in /home/tokimo, sudo's group
#     membership lookups break, and macOS/Windows VM modes (which boot
#     this rootfs as a real Linux root) end up with mismatched owners.
#   - `tar -xpf` as a non-root user silently *drops* ownership and writes
#     everything as the invoking uid, which is exactly the regression
#     we're guarding against here.
# So extract as root with --numeric-owner. Fall back to sudo if available.
if [[ "$(id -u)" -eq 0 ]]; then
    tar --numeric-owner -xpf "$WORK/rootfs.tar" -C "$VM_DIR/rootfs"
elif command -v sudo >/dev/null 2>&1; then
    echo "==> extracting rootfs as root (preserves uid=1000 for tokimo); sudo may prompt"
    sudo tar --numeric-owner -xpf "$WORK/rootfs.tar" -C "$VM_DIR/rootfs"
    # Make the tree at least readable to the invoking user so subsequent
    # tooling (e.g. `cargo test`, fetch-vm.sh -f) can rm -rf it without
    # another sudo prompt.
    sudo chmod -R u+rwX,go+rX "$VM_DIR/rootfs" || true
else
    echo "ERROR: extracting rootfs requires root to preserve uid=1000 ownership," >&2
    echo "       and 'sudo' was not found. Re-run as root or install sudo." >&2
    exit 1
fi

echo
echo "Done. .vm/base contents:"
ls -lh "$VM_DIR"

